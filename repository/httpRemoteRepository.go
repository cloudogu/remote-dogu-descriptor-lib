package repository

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudogu/ces-commons-lib/dogu"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	neturl "net/url"

	"github.com/cloudogu/cesapp-lib/core"
	"github.com/cloudogu/cesapp-lib/remote"
	"github.com/cloudogu/cesapp-lib/util"
	"github.com/eapache/go-resiliency/retrier"
	"github.com/pkg/errors"
)

// common errors
var errUnauthorized = errors.New("401 unauthorized, please login to proceed")
var errForbidden = errors.New("403 forbidden, not enough privileges")
var errNotFound = errors.New("404 not found")
var defaultBackoff = retrier.ConstantBackoff(1, 100*time.Millisecond)

// httpRemote is able to handle request to a remote registry.
type httpRemote struct {
	endpoint            string
	endpointCacheDir    string
	credentials         *core.Credentials
	retrier             *retrier.Retrier
	client              *http.Client
	urlSchema           remote.URLSchema
	useCache            bool
	remoteConfiguration *core.Remote
}

func newHTTPRemote(remoteConfig *core.Remote, credentials *core.Credentials) (*httpRemote, error) {
	backoff, err := core.GetBackoff(remoteConfig.RetryPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to create httpRemote: %w", err)
	}
	if len(backoff) < 1 {
		backoff = defaultBackoff
	}
	netRetrier := retrier.New(
		backoff,
		retrier.BlacklistClassifier{errUnauthorized, errForbidden},
	)

	checkSum := fmt.Sprintf("%x", sha256.Sum256([]byte(remoteConfig.CacheDir)))

	client, err := CreateHTTPClient(remoteConfig)
	if err != nil {
		return nil, err
	}

	urlSchema := remote.NewURLSchemaByName(remoteConfig.URLSchema, remoteConfig.Endpoint)

	return &httpRemote{
		endpoint:            remoteConfig.Endpoint,
		endpointCacheDir:    filepath.Join(remoteConfig.CacheDir, checkSum),
		credentials:         credentials,
		retrier:             netRetrier,
		client:              client,
		urlSchema:           urlSchema,
		useCache:            true,
		remoteConfiguration: remoteConfig,
	}, nil
}

// CreateHTTPClient creates a httpClient for the given remote settings.
func CreateHTTPClient(config *core.Remote) (*http.Client, error) {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	transport, err := createProxyHTTPTransport(config)
	if err != nil {
		return nil, err
	}
	httpClient.Transport = transport

	return httpClient, nil
}

func createProxyHTTPTransport(config *core.Remote) (*http.Transport, error) {
	transport := &http.Transport{}

	if config.ProxySettings.Enabled {
		proxyURLString := config.ProxySettings.CreateURL()
		core.GetLogger().Infof("configure http client to use proxy %s", proxyURLString)

		proxyURL, err := neturl.Parse(proxyURLString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy url %s: %w", proxyURLString, err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		appendProxyAuthorizationIfRequired(transport, &config.ProxySettings)
	}

	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: config.Insecure,
	}

	return transport, nil
}

func appendProxyAuthorizationIfRequired(transport *http.Transport, proxySettings *core.ProxySettings) {
	if proxySettings.Username != "" {
		authorization := proxySettings.Username + ":" + proxySettings.Password
		basicAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(authorization))
		if transport.ProxyConnectHeader == nil {
			transport.ProxyConnectHeader = make(map[string][]string)
		}

		transport.ProxyConnectHeader.Add("Proxy-Authorization", basicAuthorization)
	}
}

// GetLatest returns the detail about the latest dogu from the remote server by name.
func (r *httpRemote) GetLatest(_ context.Context, name dogu.QualifiedName) (*core.Dogu, error) {
	err := name.Validate()
	if err != nil {
		return nil, fmt.Errorf("qualified dogu name is not valid (name: %s): %w", name.String(), err)
	}
	requestUrl := r.urlSchema.Get(name.String())
	cacheDirectory := filepath.Join(r.endpointCacheDir, string(name.SimpleName))
	return r.receiveDoguFromRemoteOrCache(requestUrl, cacheDirectory)
}

// Get returns a version specific detail about the dogu.
func (r *httpRemote) Get(_ context.Context, doguVersion dogu.QualifiedVersion) (*core.Dogu, error) {
	err := doguVersion.Name.Validate()
	if err != nil {
		return nil, fmt.Errorf("qualified dogu name is not valid (name: %s): %w", doguVersion.Name.String(), err)
	}
	requestUrl := r.urlSchema.GetVersion(doguVersion.Name.String(), doguVersion.Version.Raw)
	cacheDirectory := filepath.Join(r.endpointCacheDir, string(doguVersion.Name.SimpleName), doguVersion.Version.Raw)
	return r.receiveDoguFromRemoteOrCache(requestUrl, cacheDirectory)
}

func (r *httpRemote) receiveDoguFromRemoteOrCache(requestUrl string, cacheDirectory string) (*core.Dogu, error) {
	var remoteDogu *core.Dogu
	err := r.retrier.Run(func() error {
		if r.remoteConfiguration.AnonymousAccess {
			return r.requestWithoutCredentialsFirst(requestUrl, &remoteDogu)
		}
		return r.request(requestUrl, &remoteDogu, true)
	})

	if errors.Is(err, errNotFound) {
		return nil, dogu.ErrDescriptorNotFound
	}

	err = r.handleCachingIfNecessary(&remoteDogu, err, cacheDirectory, "content.json")
	if err != nil {
		return nil, err
	}

	return remoteDogu, nil
}

// handleCachingIfNecessary handles the caching if useCache is true. This means, it ...
// - reads from cache if requestError is not nil
// - updates the cache content if the request was successful
// If useCache is false, the requestError is returned.
func (r *httpRemote) handleCachingIfNecessary(cachingType interface{}, requestError error, dirname string, filename string) error {
	if r.useCache {
		if requestError != nil {
			core.GetLogger().Errorf("failed to read from remote registry: %s", requestError)
			core.GetLogger().Info("reading from cache")
			err := r.readCacheWithFilename(cachingType, dirname, filename)
			if err != nil {
				return errors.Wrap(err, "failed to read from remote registry and cache")
			}
		} else {
			err := r.writeCacheWithFilename(cachingType, dirname, filename)
			if err != nil {
				return errors.Wrap(err, "failed to write to cache")
			}
		}
	} else {
		if requestError != nil {
			return errors.Wrap(requestError, "failed to read from remote registry")
		}
	}
	return nil
}

func (r *httpRemote) writeCacheWithFilename(responseType interface{}, cacheDirectory string, filename string) error {
	// cache
	core.GetLogger().Debug("storing result from ", r.endpoint, " into cacheDir ", cacheDirectory)
	err := os.MkdirAll(cacheDirectory, os.ModePerm)

	if nil != err {
		return errors.Wrap(err, "failed to create cache directory "+cacheDirectory)
	}

	cacheFile := filepath.Join(cacheDirectory, filename)

	if isDoguResponseType(responseType) {
		//nolint:forcetypeassert
		err = core.WriteDoguToFile(cacheFile, *responseType.(**core.Dogu))
	} else if isDoguSliceResponseType(responseType) {
		//nolint:forcetypeassert
		err = core.WriteDogusToFile(cacheFile, *responseType.(*[]*core.Dogu))
	} else {
		err = util.WriteJSONFile(responseType, cacheFile)
	}

	if nil != err {
		removeErr := os.Remove(cacheFile)
		if removeErr != nil {
			core.GetLogger().Warningf("failed to remove cache file %s", cacheFile)
		}
		return errors.Wrapf(err, "failed to write cache %s", cacheFile)
	}

	return nil
}

func (r *httpRemote) readCacheWithFilename(responseType interface{}, cacheDirectory string, filename string) error {
	cacheFile := filepath.Join(cacheDirectory, filename)

	if isDoguResponseType(responseType) {
		doguFromFile, _, err := core.ReadDoguFromFile(cacheFile)
		if err != nil {
			return errors.Wrapf(err, "failed to read cache %s", cacheFile)
		}
		//nolint:forcetypeassert
		*responseType.(**core.Dogu) = doguFromFile
	} else if isDoguSliceResponseType(responseType) {
		dogus, _, err := core.ReadDogusFromFile(cacheFile)
		if err != nil {
			return errors.Wrapf(err, "failed to read cache %s", cacheFile)
		}
		//nolint:forcetypeassert
		*responseType.(*[]*core.Dogu) = dogus
	} else {
		err := util.ReadJSONFile(responseType, cacheFile)
		if err != nil {
			return errors.Wrapf(err, "failed to read cache %s", cacheFile)
		}
	}

	return nil
}

func (r *httpRemote) requestWithoutCredentialsFirst(requestURL string, responseType interface{}) error {
	core.GetLogger().Debug("Access \"" + requestURL + "\" anonymous...")
	err := r.request(requestURL, responseType, false)
	if err != nil {
		core.GetLogger().Debug("Anonymous access to \"" + requestURL + "\" failed. Using credentials...")
		err = r.request(requestURL, responseType, true)
		if err != nil {
			core.GetLogger().Debug("Access to \"" + requestURL + "\" with credentials failed...")
		} else {
			core.GetLogger().Debug("Access to \"" + requestURL + "\" with credentials was successfull...")
		}
	}
	return err
}

func (r *httpRemote) request(requestURL string, responseType interface{}, useCredentials bool) error {
	core.GetLogger().Debugf("fetch json from remote %s", requestURL)

	request, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return errors.Wrap(err, "failed to prepare request")
	}

	if useCredentials && r.credentials != nil {
		request.SetBasicAuth(r.credentials.Username, r.credentials.Password)
	}

	resp, err := r.client.Do(request)
	if err != nil {
		return errors.Wrap(err, "failed to request remote registry")
	}

	err = checkStatusCode(resp)
	if err != nil {
		return err
	}

	defer util.CloseButLogError(resp.Body, "requesting json from remove")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read response body")
	}

	if isDoguResponseType(responseType) {
		doguFromString, version, err := core.ReadDoguFromString(string(body))
		if err != nil {
			return errors.Wrap(err, "failed to parse json of response")
		}

		if version == core.DoguApiV1 {
			core.GetLogger().Warningf("Read dogu %s in v1 format from registry.", doguFromString.Name)
		}
		//nolint:forcetypeassert
		*responseType.(**core.Dogu) = doguFromString
	} else if isDoguSliceResponseType(responseType) {
		dogus, version, err := core.ReadDogusFromString(string(body))
		if err != nil {
			return errors.Wrap(err, "failed to parse json of response")
		}
		if version == core.DoguApiV1 {
			core.GetLogger().Warning("Read dogus in v1 format from registry.")
		}
		//nolint:forcetypeassert
		*responseType.(*[]*core.Dogu) = dogus
	} else {
		err = json.Unmarshal(body, responseType)
		if err != nil {
			return errors.Wrap(err, "failed to parse json of response")
		}
	}

	return nil
}

func checkStatusCode(response *http.Response) error {
	sc := response.StatusCode
	switch sc {
	case http.StatusUnauthorized:
		return errUnauthorized
	case http.StatusForbidden:
		return errForbidden
	case http.StatusNotFound:
		return errNotFound
	default:
		if sc >= 300 {
			furtherExplanation := extractRemoteBody(response.Body, sc)

			return errors.Errorf("remote registry returns invalid status: %s: %s", response.Status, furtherExplanation)
		}

		return nil
	}
}

func extractRemoteBody(responseBodyReader io.ReadCloser, statusCode int) string {
	buf := new(strings.Builder)
	_, err := io.Copy(buf, responseBodyReader)
	if err != nil {
		core.GetLogger().Errorf("error while copying response body: %s", err.Error())
		return "error"
	}

	responseBody := []byte(buf.String())

	body := &remoteResponseBody{statusCode: statusCode}
	jsonErr := json.Unmarshal(responseBody, body)
	if jsonErr != nil {
		core.GetLogger().Errorf("error while parsing response body: %s", jsonErr.Error())
		return "error"
	}

	return body.String()
}

func isDoguResponseType(responseType interface{}) bool {
	_, ok := responseType.(**core.Dogu)
	return ok
}

func isDoguSliceResponseType(responseType interface{}) bool {
	_, ok := responseType.(*[]*core.Dogu)
	return ok
}

type remoteResponseBody struct {
	statusCode int
	Status     string `json:"status"`
	Error      string `json:"error"`
}

func (rb *remoteResponseBody) String() string {
	errorField := rb.Error
	statusField := rb.Status
	if rb.Status == "" {
		statusField = fmt.Sprintf("%d", rb.statusCode)
	}

	if rb.Error == "" {
		errorField = "(no error)"
	}
	return fmt.Sprintf("%s: %s", statusField, errorField)
}
