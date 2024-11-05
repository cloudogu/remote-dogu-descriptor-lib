package repository

import (
	"context"
	"github.com/cloudogu/ces-commons-lib/dogu"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/cloudogu/cesapp-lib/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func clearCache() {
	_ = os.RemoveAll("/tmp/ces/cache/remote_test")
}

func TestAnonymousOnAnonymousServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			data, _ := core.WriteDoguToString(&core.Dogu{Name: "Test", Version: "3.0"})
			w.Write([]byte(data))
			w.WriteHeader(200)
		}
	}))
	defer ts.Close()
	testRemote := createRemoteWithConfiguration(t, ts, &core.Remote{
		AnonymousAccess: true,
	})
	version, err := core.ParseVersion("3.0")
	require.NoError(t, err)

	qDoguVersion := dogu.QualifiedDoguVersion{
		Name:    dogu.QualifiedDoguName{SimpleName: "Test"},
		Version: version,
	}

	dogu, err := testRemote.Get(context.TODO(), qDoguVersion)
	assert.NotNil(t, dogu)
	assert.Nil(t, err)
}

func TestGet(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasSuffix(r.URL.Path, "/Test"))

		data, err := core.WriteDoguToString(&core.Dogu{Name: "Test", Version: "3.0"})
		assert.Nil(t, err)
		w.Write([]byte(data))
		w.WriteHeader(200)
	}))
	defer ts.Close()

	testRemote := createRemote(t, ts)

	dogu, err := testRemote.GetLatest(context.TODO(), dogu.QualifiedDoguName{SimpleName: "Test"})

	assert.Nil(t, err)
	assert.NotNil(t, dogu)

	assert.Equal(t, "Test", dogu.Name)
	assert.Equal(t, "3.0", dogu.Version)

	clearCache()
}

func TestGetWithRetry(t *testing.T) {
	counter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if counter > 0 {
			data, err := core.WriteDoguToString(&core.Dogu{Name: "official/Hansolo", Version: "3.0"})
			assert.Nil(t, err)
			w.Write([]byte(data))
			w.WriteHeader(200)
		} else {
			counter++
			w.WriteHeader(500)
		}
	}))
	defer ts.Close()

	testRemote := createRemote(t, ts)
	dogu, err := testRemote.GetLatest(context.TODO(), dogu.QualifiedDoguName{SimpleName: "Hansolo", Namespace: "official"})
	assert.Nil(t, err)
	assert.NotNil(t, dogu)

	assert.Equal(t, "official/Hansolo", dogu.Name)
	assert.Equal(t, "3.0", dogu.Version)

	assert.Equal(t, 1, counter)

	clearCache()
}

func TestGetVersion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasSuffix(r.URL.Path, "/Test/3.0"))

		data, err := core.WriteDoguToString(&core.Dogu{Name: "Test", Version: "3.0"})
		assert.Nil(t, err)
		w.Write([]byte(data))
		w.WriteHeader(200)
	}))
	defer ts.Close()

	testRemote := createRemote(t, ts)

	version, err := core.ParseVersion("3.0")
	require.NoError(t, err)

	qDoguVersion := dogu.QualifiedDoguVersion{
		Name:    dogu.QualifiedDoguName{SimpleName: "Test"},
		Version: version,
	}

	dogu, err := testRemote.Get(context.TODO(), qDoguVersion)

	assert.Nil(t, err)
	assert.NotNil(t, dogu)

	assert.Equal(t, "Test", dogu.Name)
	assert.Equal(t, "3.0", dogu.Version)

	clearCache()
}

func TestIsDoingAnonymousAccessOnceWithRetry(t *testing.T) {
	var accessCounter = 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessCounter++
		if (accessCounter % 2) != 0 {
			//First access and third access will be here (because we do one retry)
			assert.Empty(t, r.Header.Get("Authorization"))
		} else {
			assert.NotEmpty(t, r.Header.Get("Authorization"))
		}
	}))
	defer ts.Close()

	testRemote := createRemoteWithConfiguration(t, ts, &core.Remote{
		AnonymousAccess: true,
	})

	version, err := core.ParseVersion("3.0")
	require.NoError(t, err)

	qDoguVersion := dogu.QualifiedDoguVersion{
		Name:    dogu.QualifiedDoguName{SimpleName: "Test"},
		Version: version,
	}

	_, _ = testRemote.Get(context.TODO(), qDoguVersion)
	assert.Equal(t, 4, accessCounter)

	// Try again with anonymous docker access also activated. Should not affect the result
	testRemote = createRemoteWithConfiguration(t, ts, &core.Remote{
		AnonymousAccess: true,
	})
	_, _ = testRemote.Get(context.TODO(), qDoguVersion)
	assert.Equal(t, 8, accessCounter)
}

func TestIsDoingNoAnynymousAcces(t *testing.T) {
	var accessCounter = 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		accessCounter++
	}))
	defer ts.Close()

	version, err := core.ParseVersion("3.0")
	require.NoError(t, err)

	qDoguVersion := dogu.QualifiedDoguVersion{
		Name:    dogu.QualifiedDoguName{SimpleName: "Test"},
		Version: version,
	}

	testRemote := createRemoteWithConfiguration(t, ts, &core.Remote{})
	_, _ = testRemote.Get(context.TODO(), qDoguVersion)
	assert.Equal(t, 2, accessCounter)

	// Try again with anonymous docker access also activated. Should not affect the result
	testRemote = createRemoteWithConfiguration(t, ts, &core.Remote{})
	_, _ = testRemote.Get(context.TODO(), qDoguVersion)
	assert.Equal(t, 4, accessCounter)
}

func TestGetDoNotRetryWithFailedAuthentication(t *testing.T) {
	counter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if counter == 0 {
			w.WriteHeader(401)
		} else {
			w.WriteHeader(403)
		}
		counter++
	}))
	defer ts.Close()

	version, err := core.ParseVersion("3.0")
	require.NoError(t, err)

	qDoguVersion := dogu.QualifiedDoguVersion{
		Name:    dogu.QualifiedDoguName{SimpleName: "Test"},
		Version: version,
	}

	testRemote := createRemote(t, ts)
	_, err = testRemote.Get(context.TODO(), qDoguVersion)
	assert.NotNil(t, err)
	assert.Equal(t, 1, counter)

	_, err = testRemote.Get(context.TODO(), qDoguVersion)
	assert.NotNil(t, err)
	assert.Equal(t, 2, counter)

	clearCache()
}

func TestGetCached(t *testing.T) {
	expectedDogu := core.Dogu{Name: "a", Version: "1.0"}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		data, err := core.WriteDoguToString(&expectedDogu)
		assert.Nil(t, err)
		w.Write([]byte(data))
		w.WriteHeader(200)
	}))

	testRemote := createRemote(t, ts)

	doguResult, err := testRemote.GetLatest(context.TODO(), dogu.QualifiedDoguName{SimpleName: "a"})
	assert.Nil(t, err)
	assert.NotNil(t, doguResult)
	assert.Equal(t, expectedDogu, *doguResult)

	ts.Close()

	doguResult, err = testRemote.GetLatest(context.TODO(), dogu.QualifiedDoguName{SimpleName: "a"})
	assert.Nil(t, err)
	assert.NotNil(t, doguResult)
	assert.Equal(t, expectedDogu, *doguResult)

	clearCache()
}

func createRemote(t *testing.T, ts *httptest.Server) *httpRemote {
	return createRemoteWithURLScheme(t, ts, "")
}

func createRemoteWithConfiguration(t *testing.T, ts *httptest.Server, remoteConf *core.Remote) *httpRemote {
	t.Helper()
	remoteConf.Endpoint = ts.URL
	rem, err := newHTTPRemote(
		remoteConf,
		&core.Credentials{
			Username: "trillian",
			Password: "secret",
		},
	)
	assert.Nil(t, err)
	assert.NotNil(t, rem)
	return rem
}

func createRemoteWithURLScheme(t *testing.T, ts *httptest.Server, urlScheme string) *httpRemote {
	testRemote, err := newHTTPRemote(
		&core.Remote{
			Endpoint:  ts.URL,
			CacheDir:  "/tmp/ces/cache/remote_test",
			URLSchema: urlScheme,
		},
		&core.Credentials{
			Username: "trillian",
			Password: "secret",
		},
	)

	assert.Nil(t, err)
	assert.NotNil(t, testRemote)

	return testRemote
}