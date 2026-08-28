// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeInternalClient is a test double for InternalClient that captures log messages.
type fakeInternalClient struct {
	mu       sync.Mutex
	debug    bool
	messages []string
}

func (f *fakeInternalClient) LogLevelIsSetTo(level string) bool {
	return level == "debug" && f.debug
}

func (f *fakeInternalClient) Log(_ context.Context, _ string, msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages = append(f.messages, msg)
}

func (f *fakeInternalClient) joined() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.messages, "\n")
}

func TestRedactSensitiveHeaders_ReplacesValuesOfNamedHeaders(t *testing.T) {
	dump := []byte("POST /v1/foo HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Authorization: super-secret-api-key\r\n" +
		"X-Xdr-Auth-Id: 42\r\n" +
		"X-Xdr-Nonce: deadbeef\r\n" +
		"X-Xdr-Timestamp: 1700000000000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"name":"value"}`)

	got := string(redactSensitiveHeaders(dump, sensitiveRequestHeaders))

	// Authorization and key ID are secrets — must be redacted.
	assert.Contains(t, got, "Authorization: "+redactedValue)
	assert.Contains(t, got, "X-Xdr-Auth-Id: "+redactedValue)
	assert.NotContains(t, got, "super-secret-api-key")

	// Nonce and timestamp are not secrets — must pass through unchanged.
	assert.Contains(t, got, "X-Xdr-Nonce: deadbeef")
	assert.Contains(t, got, "X-Xdr-Timestamp: 1700000000000")

	// Non-sensitive headers and body must be untouched.
	assert.Contains(t, got, "POST /v1/foo HTTP/1.1")
	assert.Contains(t, got, "Host: api.example.com")
	assert.Contains(t, got, "Content-Type: application/json")
	assert.Contains(t, got, `{"name":"value"}`)
}

func TestRedactSensitiveHeaders_DoesNotMatchInsideBody(t *testing.T) {
	dump := []byte("POST /v1/foo HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"Authorization":"this-is-data-not-a-header"}`)

	got := string(redactSensitiveHeaders(dump, sensitiveRequestHeaders))

	assert.Contains(t, got, `"Authorization":"this-is-data-not-a-header"`)
	assert.NotContains(t, got, redactedValue)
}

func TestRedactSensitiveHeaders_HandlesCaseInsensitiveHeaderNames(t *testing.T) {
	dump := []byte("GET /foo HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"authorization: secret\r\n" +
		"x-xdr-auth-id: 1\r\n" +
		"\r\n")

	got := string(redactSensitiveHeaders(dump, sensitiveRequestHeaders))

	assert.NotContains(t, got, "secret")
	assert.Contains(t, got, "authorization: "+redactedValue)
	assert.Contains(t, got, "x-xdr-auth-id: "+redactedValue)
}

func TestRedactSensitiveHeaders_NoHeaderTerminatorReturnsInputUnchanged(t *testing.T) {
	dump := []byte("not a real http dump")
	got := redactSensitiveHeaders(dump, sensitiveRequestHeaders)
	assert.Equal(t, dump, got)
}

func TestRedactSensitiveHeaders_EmptyHeaderSection(t *testing.T) {
	dump := []byte("GET / HTTP/1.1\r\n\r\n")
	got := redactSensitiveHeaders(dump, sensitiveRequestHeaders)
	assert.Equal(t, dump, got)
}

func TestRedactSensitiveHeaders_PreservesByteIdentityForNonSensitiveDump(t *testing.T) {
	dump := []byte("GET / HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Accept: */*\r\n" +
		"\r\n")
	got := redactSensitiveHeaders(dump, sensitiveRequestHeaders)
	assert.Equal(t, string(dump), string(got))
}

// TestTransport_RoundTrip_PostBodyReachesServerIntact is a regression test for
// body corruption: req.Clone shares the body reader, so dumping the clone drains
// req.Body before the real RoundTrip runs. Dumping req directly avoids this.
func TestTransport_RoundTrip_PostBodyReachesServerIntact(t *testing.T) {
	const wantBody = `{"hello":"world","count":42}`

	var (
		gotBodyMu sync.Mutex
		gotBody   string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBodyMu.Lock()
		gotBody = string(body)
		gotBodyMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fake := &fakeInternalClient{debug: true}
	httpClient := &http.Client{Transport: NewTransport(http.DefaultTransport, fake)}

	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(wantBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "super-secret-api-key")
	req.Header.Set("x-xdr-auth-id", "42")
	req.Header.Set("x-xdr-nonce", "deadbeef")
	req.Header.Set("x-xdr-timestamp", "1700000000000")

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	gotBodyMu.Lock()
	defer gotBodyMu.Unlock()
	assert.Equal(t, wantBody, gotBody, "request body must reach the server intact")
}

func TestTransport_RoundTrip_DebugDumpRedactsRequestCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "super-secret-api-key", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()

	fake := &fakeInternalClient{debug: true}
	httpClient := &http.Client{Transport: NewTransport(http.DefaultTransport, fake)}

	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(`{"x":1}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "super-secret-api-key")
	req.Header.Set("x-xdr-auth-id", "42")
	req.Header.Set("x-xdr-nonce", "deadbeef")
	req.Header.Set("x-xdr-timestamp", "1700000000000")

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	logs := fake.joined()
	assert.NotContains(t, logs, "super-secret-api-key", "raw API key must not appear in debug log")
	assert.Contains(t, logs, redactedValue)
	// prettyPrintJsonLines reformats the body JSON, so match the field name only.
	assert.Contains(t, logs, `"x"`)
	// Nonce and timestamp are no longer redacted — they are not secrets.
	assert.Contains(t, logs, "deadbeef")
	assert.Contains(t, logs, "1700000000000")
}

func TestTransport_RoundTrip_DebugDumpRedactsResponseSetCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "session=super-secret-token; HttpOnly")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()

	fake := &fakeInternalClient{debug: true}
	httpClient := &http.Client{Transport: NewTransport(http.DefaultTransport, fake)}

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	logs := fake.joined()
	assert.NotContains(t, logs, "super-secret-token", "Set-Cookie value must not appear in debug log")
	assert.Contains(t, logs, redactedValue)
}

func TestTransport_RoundTrip_DebugDisabledDoesNotLogRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fake := &fakeInternalClient{debug: false}
	httpClient := &http.Client{Transport: NewTransport(http.DefaultTransport, fake)}

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "super-secret-api-key")

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Empty(t, fake.messages, "no debug log should be emitted when debug level is off")
}

// TestTransport_RoundTrip_RedactedDumpStillParsesAsHTTPRequest verifies that
// redaction preserves valid HTTP/1 wire framing.
func TestTransport_RoundTrip_RedactedDumpStillParsesAsHTTPRequest(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/foo", strings.NewReader(`{"a":1}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "secret")
	req.Header.Set("x-xdr-auth-id", "42")

	dump, err := httputil.DumpRequestOut(req, true)
	require.NoError(t, err)

	redacted := redactSensitiveHeaders(dump, sensitiveRequestHeaders)

	parsed, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(redacted)))
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, parsed.Method)
	assert.Equal(t, "/v1/foo", parsed.URL.Path)
	assert.Equal(t, redactedValue, parsed.Header.Get("Authorization"))
	assert.Equal(t, redactedValue, parsed.Header.Get("X-Xdr-Auth-Id"))
	assert.Equal(t, "application/json", parsed.Header.Get("Content-Type"))

	body, err := io.ReadAll(parsed.Body)
	require.NoError(t, err)
	assert.Equal(t, `{"a":1}`, string(body))
}
