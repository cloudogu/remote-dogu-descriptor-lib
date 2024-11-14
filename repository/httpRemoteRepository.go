package repository

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudogu/ces-commons-lib/dogu"
	commonerrors "github.com/cloudogu/ces-commons-lib/errors"
	"github.com/pkg/errors"
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
	"github.com/cloudogu/retry-lib/retry"
)

var maxTries = 20

// httpRemote is able to handle request to a remote registry.
type httpRemote struct {
	endpoint            string
	endpointCacheDir    string
	credentials         *core.Credentials
	client              *http.Client
	urlSchema           remote.URLSchema
	useCache            bool
	remoteConfiguration *core.Remote
}

func newHTTPRemote(remoteConfig *core.Remote, credentials *core.Credentials) (*httpRemote, error) {
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
	cacheDirectory := filepath.Join(r.endpointCacheDir, name.String())
	return r.receiveDoguFromRemoteOrCache(requestUrl, cacheDirectory)
}

// Get returns a version specific detail about the dogu.
func (r *httpRemote) Get(_ context.Context, doguVersion dogu.QualifiedVersion) (*core.Dogu, error) {
	err := doguVersion.Name.Validate()
	if err != nil {
		return nil, fmt.Errorf("qualified dogu name is not valid (name: %s): %w", doguVersion.Name.String(), err)
	}
	requestUrl := r.urlSchema.GetVersion(doguVersion.Name.String(), doguVersion.Version.Raw)
	cacheDirectory := filepath.Join(r.endpointCacheDir, doguVersion.Name.String(), doguVersion.Version.Raw)
	return r.receiveDoguFromRemoteOrCache(requestUrl, cacheDirectory)
}

func (r *httpRemote) receiveDoguFromRemoteOrCache(requestUrl string, dirname string) (*core.Dogu, error) {
	var remoteDogu, err = r.readCachedDogu(dirname)
	if err != nil {
		err = retry.OnError(maxTries, isRetryError, func() error {
			remoteDogu, err = r.request(requestUrl, true)
			return err
		})

		if err != nil {
			return nil, err
		}

		err = r.writeDoguToCache(remoteDogu, dirname)
		if err != nil {
			return &core.Dogu{}, fmt.Errorf("failed to write dogu to cache: %w", err)
		}
	}

	return remoteDogu, nil
}

func (r *httpRemote) readCachedDogu(dirname string) (*core.Dogu, error) {
	if r.useCache {
		cacheFile := filepath.Join(dirname, "content.json")
		doguFromFile, _, err := core.ReadDoguFromFile(cacheFile)
		if err != nil {
			return nil, commonerrors.NewGenericError(fmt.Errorf("failed to read from cache %s: %w", cacheFile, err))
		}
		if doguFromFile == nil {
			return nil, commonerrors.NewNotFoundError(fmt.Errorf("dogu descriptor not found"))
		}
		return doguFromFile, nil
	}
	return nil, commonerrors.NewGenericError(fmt.Errorf("useCache is not activated"))
}

func (r *httpRemote) writeDoguToCache(doguToWrite *core.Dogu, dirname string) error {
	err := os.MkdirAll(dirname, os.ModePerm)
	if nil != err {
		return fmt.Errorf("failed to create cache directory %s: %w", dirname, err)
	}

	cacheFile := filepath.Join(dirname, "content.json")
	err = core.WriteDoguToFile(cacheFile, doguToWrite)

	if nil != err {
		removeErr := os.Remove(cacheFile)
		if removeErr != nil {
			core.GetLogger().Warningf("failed to remove cache file %s", cacheFile)
		}
		return fmt.Errorf("failed to write cache %s: %w", cacheFile, err)
	}

	return nil
}

func (r *httpRemote) request(requestURL string, useCredentials bool) (*core.Dogu, error) {
	core.GetLogger().Debugf("fetch json from remote %s", requestURL)

	request, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, commonerrors.NewGenericError(fmt.Errorf("failed to prepare request: %w", err))
	}

	if useCredentials && r.credentials != nil {
		request.SetBasicAuth(r.credentials.Username, r.credentials.Password)
	}

	resp, err := r.client.Do(request)
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)
	if err != nil {
		return nil, commonerrors.NewGenericError(fmt.Errorf("failed to request remote registry: %w", err))
	}

	err = checkStatusCode(resp)
	if err != nil {
		return nil, err
	}

	defer util.CloseButLogError(resp.Body, "requesting json from remove")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, commonerrors.NewGenericError(fmt.Errorf("failed to read response body: %w", err))
	}

	doguFromString, version, err := core.ReadDoguFromString(string(body))
	if err != nil {
		return nil, commonerrors.NewGenericError(fmt.Errorf("failed to parse json of request: %w", err))
	}

	if version == core.DoguApiV1 {
		core.GetLogger().Warningf("Read dogu %s in v1 format from registry.", doguFromString.Name)
	}
	//nolint:forcetypeassert
	return doguFromString, nil
}

func checkStatusCode(response *http.Response) error {
	sc := response.StatusCode
	switch sc {
	case http.StatusUnauthorized:
		return commonerrors.NewUnauthorizedError(errors.New("401 unauthorized, please login to proceed"))
	case http.StatusForbidden:
		return commonerrors.NewForbiddenError(errors.New("403 forbidden, not enough privileges"))
	case http.StatusNotFound:
		return commonerrors.NewNotFoundError(errors.New("404 not found"))
	case http.StatusInternalServerError:
		return commonerrors.NewConnectionError(errors.New("500 internal server error"))
	default:
		if sc >= 300 {
			furtherExplanation := extractRemoteBody(response.Body, sc)

			return fmt.Errorf("remote registry returns invalid status: %s: %s", response.Status, furtherExplanation)
		}

		return nil
	}
}

func extractRemoteBody(responseBodyReader io.ReadCloser, statusCode int) string {
	buf := new(strings.Builder)
	_, err := io.Copy(buf, responseBodyReader)
	if err != nil {
		return fmt.Sprintf("error while copying response body: %s", err.Error())
	}

	responseBody := []byte(buf.String())

	body := &remoteResponseBody{statusCode: statusCode}
	jsonErr := json.Unmarshal(responseBody, body)
	if jsonErr != nil {
		return fmt.Sprintf("error while parsing response body: %s", jsonErr.Error())
	}

	return body.String()
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

func isRetryError(err error) bool {
	return commonerrors.IsUnauthorizedError(err) || commonerrors.IsForbiddenError(err) || commonerrors.IsConnectionError(err)
}
