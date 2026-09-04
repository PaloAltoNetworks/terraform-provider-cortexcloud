// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// requestIDKey is the context key for request ID
	requestIDKey contextKey = "cortex-request-id"
)

// generateRequestID creates a unique request identifier
// Format: req_<32-char-hex> (similar to AWS request IDs)
func generateRequestID() string {
	// Generate 16 random bytes (128 bits)
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if random fails
		return fmt.Sprintf("req_fallback_%d", time.Now().UnixNano())
	}

	// Convert to hex and prefix
	return "req_" + hex.EncodeToString(b)
}

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestID retrieves the request ID from context
// Returns empty string if not found
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// GetOrGenerateRequestID retrieves existing request ID or generates new one
func GetOrGenerateRequestID(ctx context.Context) (context.Context, string) {
	if id := GetRequestID(ctx); id != "" {
		return ctx, id
	}

	id := generateRequestID()
	return WithRequestID(ctx, id), id
}
