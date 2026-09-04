// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
)

// InternalClient abstracts the core client's logging and log-level settings.
type InternalClient interface {
	LogLevelIsSetTo(string) bool
	Log(ctx context.Context, level, msg string)
}

type transport struct {
	transport http.RoundTripper
	client    InternalClient
}

// sensitiveRequestHeaders lists header names whose values are redacted in debug logs.
var sensitiveRequestHeaders = map[string]struct{}{
	"Authorization": {},
	"X-Xdr-Auth-Id": {},
}

// sensitiveResponseHeaders lists response header names whose values are redacted in debug logs.
var sensitiveResponseHeaders = map[string]struct{}{
	"Set-Cookie":    {},
	"Authorization": {},
}

const redactedValue = "[REDACTED]"

// RoundTrip implements http.RoundTripper, logging requests and responses at debug level.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	requestID := GetRequestID(ctx)

	logLevelIsDebug := t.client.LogLevelIsSetTo("debug")

	if logLevelIsDebug {
		reqData, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			redacted := redactSensitiveHeaders(reqData, sensitiveRequestHeaders)
			t.client.Log(ctx, "debug", fmt.Sprintf(logReqMsg, requestID, prettyPrintJsonLines(redacted)))
		} else {
			t.client.Log(ctx, "error", fmt.Sprintf("[ERROR] Failed to dump HTTP request: %v", err))
		}
	}

	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		t.client.Log(ctx, "error", fmt.Sprintf("[ERROR] [%s] HTTP request failed: %v", requestID, err))
		return resp, err
	}

	if logLevelIsDebug {
		respData, err := httputil.DumpResponse(resp, true)
		if err == nil {
			redacted := redactSensitiveHeaders(respData, sensitiveResponseHeaders)
			t.client.Log(ctx, "debug", fmt.Sprintf(logRespMsg, requestID, prettyPrintJsonLines(redacted)))
		} else {
			t.client.Log(ctx, "error", fmt.Sprintf("[ERROR] Failed to dump HTTP response: %v", err))
		}
	}

	return resp, nil
}

// NewTransport wraps t with debug-level request/response logging via client.
func NewTransport(t http.RoundTripper, client InternalClient) *transport {
	return &transport{t, client}
}

// redactSensitiveHeaders replaces the value of any header in dump whose name
// (case-insensitive) appears in sensitive with redactedValue. Only the header
// section (before \r\n\r\n) is scanned; body bytes are never modified. Returns
// dump unchanged if no header terminator is found.
func redactSensitiveHeaders(dump []byte, sensitive map[string]struct{}) []byte {
	const headerEnd = "\r\n\r\n"

	bodyStart := bytes.Index(dump, []byte(headerEnd))
	if bodyStart < 0 {
		return dump
	}

	headerSection := dump[:bodyStart]
	rest := dump[bodyStart:]

	lines := bytes.Split(headerSection, []byte("\r\n"))
	for i, line := range lines {
		if i == 0 { // skip the request/status line
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name := string(bytes.TrimSpace(line[:colon]))
		if _, isSensitive := sensitive[http.CanonicalHeaderKey(name)]; !isSensitive {
			continue
		}
		lines[i] = []byte(name + ": " + redactedValue)
	}

	out := bytes.Join(lines, []byte("\r\n"))
	return append(out, rest...)
}

// prettyPrintJsonLines pretty-prints any line in b that is valid JSON.
func prettyPrintJsonLines(b []byte) string {
	parts := strings.Split(string(b), "\n")
	for i, p := range parts {
		if b := []byte(p); json.Valid(b) {
			var out bytes.Buffer
			_ = json.Indent(&out, b, "", " ")
			parts[i] = out.String()
		}
	}
	return strings.Join(parts, "\n")
}

const logReqMsg = `
---[ REQUEST %s ]-----------------------------
%s
-----------------------------------------------------`

const logRespMsg = `
---[ RESPONSE %s ]----------------------------
%s
-----------------------------------------------------`
