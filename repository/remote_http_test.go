package repository

import (
	"fmt"
	commonerrors "github.com/cloudogu/ces-commons-lib/errors"
	"github.com/cloudogu/cesapp-lib/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

func Test_newHTTPRemote(t *testing.T) {
	t.Run("Should return new httpRemote", func(t *testing.T) {
		config := &core.Remote{}
		creds := &core.Credentials{}

		_, err := newHTTPRemote(config, creds)

		require.NoError(t, err)
	})
}

func Test_checkStatusCode(t *testing.T) {
	t.Run("should return nil for HTTP 200", func(t *testing.T) {
		mockResp := &http.Response{}
		mockResp.Status = "200 OK"
		mockResp.StatusCode = http.StatusOK
		mockResp.Body = ioutil.NopCloser(strings.NewReader(`{"status": "is well"}`))

		// when
		err := checkStatusCode(mockResp)

		// then
		require.NoError(t, err)
	})

	t.Run("should return error for HTTP statuses >= 300", func(t *testing.T) {
		mockResp := &http.Response{}
		mockResp.Status = "300 Whoopsie!"
		mockResp.StatusCode = 300
		mockResp.Body = ioutil.NopCloser(strings.NewReader(`{"status": "I, uh, well... phew!"}`))

		// when
		err := checkStatusCode(mockResp)

		// then
		require.Error(t, err)
		assert.Equal(t, err.Error(), "remote registry returns invalid status: 300 Whoopsie!: I, uh, well... phew!: (no error)")
	})

	t.Run("should return error for HTTP 400", func(t *testing.T) {
		const errorBody = "Do not use v1 endpoint for v2 dogu creation. Use v2 endpoint instead."

		mockResp := &http.Response{}
		mockResp.Status = http.StatusText(http.StatusBadRequest)
		mockResp.StatusCode = http.StatusBadRequest
		mockResp.Body = ioutil.NopCloser(strings.NewReader(fmt.Sprintf(`{"error": "%s"}`, errorBody)))

		// when
		err := checkStatusCode(mockResp)

		// then
		require.Error(t, err)
		assert.Equal(t, err.Error(), "remote registry returns invalid status: Bad Request: 400: Do not use v1 endpoint for v2 dogu creation. Use v2 endpoint instead.")
	})

	t.Run("should return custom error for HTTP 401", func(t *testing.T) {
		mockResp := &http.Response{}
		mockResp.Status = http.StatusText(http.StatusUnauthorized)
		mockResp.StatusCode = http.StatusUnauthorized
		mockResp.Body = ioutil.NopCloser(strings.NewReader(`{"status": "unauthorized"}`))

		// when
		err := checkStatusCode(mockResp)

		// then
		require.Error(t, err)
		assert.True(t, commonerrors.IsUnauthorizedError(err))
	})

	t.Run("should return custom error for HTTP 403", func(t *testing.T) {
		mockResp := &http.Response{}
		mockResp.Status = http.StatusText(http.StatusForbidden)
		mockResp.StatusCode = http.StatusForbidden
		mockResp.Body = ioutil.NopCloser(strings.NewReader(`{"status": "forbidden"}`))

		// when
		err := checkStatusCode(mockResp)

		// then
		require.Error(t, err)
		assert.True(t, commonerrors.IsForbiddenError(err))
	})

	t.Run("should return custom error for HTTP 404", func(t *testing.T) {
		mockResp := &http.Response{}
		mockResp.Status = http.StatusText(http.StatusNotFound)
		mockResp.StatusCode = http.StatusNotFound
		mockResp.Body = ioutil.NopCloser(strings.NewReader(`{"status": "forbidden"}`))

		// when
		err := checkStatusCode(mockResp)

		// then
		require.Error(t, err)
		assert.True(t, commonerrors.IsNotFoundError(err))
	})
}

func Test_extractRemoteErrorBody(t *testing.T) {
	t.Run("should return error body", func(t *testing.T) {
		responseBody := ioutil.NopCloser(strings.NewReader(`{"error": "the error text"}`))
		// when
		actual := extractRemoteBody(responseBody, 400)

		// then
		assert.Equal(t, "400: the error text", actual)
	})

	t.Run("should include generic error for truncated json", func(t *testing.T) {
		responseBody := ioutil.NopCloser(strings.NewReader(`{"error": "the erro...`))
		// when
		actual := extractRemoteBody(responseBody, 400)

		// then
		assert.Contains(t, "error while parsing response body: unexpected end of JSON input", actual)
	})
}

func Test_remoteResponseBody_String(t *testing.T) {
	type fields struct {
		statusCode int
		Status     string
		Error      string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"return mixed string", fields{Status: "aaa", Error: "bbb"}, "aaa: bbb"},
		{"return only status", fields{Status: "aaa", Error: ""}, "aaa: (no error)"},
		{"return only error", fields{statusCode: 123, Error: "bbb"}, "123: bbb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responseBody := &remoteResponseBody{
				statusCode: tt.fields.statusCode,
				Status:     tt.fields.Status,
				Error:      tt.fields.Error,
			}
			if got := responseBody.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}
