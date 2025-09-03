// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package app

import (
	"bytes"
	"context" // Import context
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
)

// InternalClient is an interface that the transport layer uses to interact
// with the core client's logging and validation settings.
// This interface allows for a clean separation of concerns and avoids direct
// dependency on the concrete Client struct, promoting testability.
type InternalClient interface {
	LogLevelIsSetTo(string) bool
	Log(ctx context.Context, level, msg string)
	PreRequestValidationEnabled() bool
}

type transport struct {
	transport http.RoundTripper
	client    InternalClient
}

// RoundTrip implements the http.RoundTripper interface.
// It logs HTTP requests and responses based on the client's configured log level.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	// Check if debug-level logging is enabled for detailed request/response dumps.
	logLevelIsDebug := t.client.LogLevelIsSetTo("debug")

	// Log request
	if logLevelIsDebug {
		reqData, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			// Use "debug" as the explicit log level for request dumps.
			t.client.Log(ctx, "debug", fmt.Sprintf(logReqMsg, prettyPrintJsonLines(reqData)))
		} else {
			// Log errors during request dumping at the "error" level.
			t.client.Log(ctx, "error", fmt.Sprintf("[ERROR] Failed to dump HTTP request: %v", err))
		}
	}

	// Execute request
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		// Log network/transport errors at the "error" level.
		t.client.Log(ctx, "error", fmt.Sprintf("[ERROR] HTTP request failed: %v", err))
		return resp, err
	}

	// Log response
	if logLevelIsDebug {
		respData, err := httputil.DumpResponse(resp, true)
		if err == nil {
			// Use "debug" as the explicit log level for response dumps.
			t.client.Log(ctx, "debug", fmt.Sprintf(logRespMsg, prettyPrintJsonLines(respData)))
		} else {
			// Log errors during response dumping at the "error" level.
			t.client.Log(ctx, "error", fmt.Sprintf("[ERROR] Failed to dump HTTP response: %v", err))
		}
	}

	return resp, nil
}

// NewTransport creates a wrapper around an http.RoundTripper,
// designed to be used for the `Transport` field of http.Client.
//
// This logs each pair of HTTP request/response that it handles.
// The logging is done via the `InternalClient` interface.
func NewTransport(t http.RoundTripper, client InternalClient) *transport {
	return &transport{t, client}
}

// prettyPrintJsonLines iterates through a []byte line-by-line,
// transforming any lines that are complete JSON into pretty-printed JSON.
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
---[ REQUEST ]---------------------------------------
%s
-----------------------------------------------------`

const logRespMsg = `
---[ RESPONSE ]--------------------------------------
%s
-----------------------------------------------------`
