// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package log

import (
	"context"
	"log"
)

// DefaultLogger implements the Logger interface using Go's standard log package.
type DefaultLogger struct {
	*log.Logger
}

func (l DefaultLogger) Debug(ctx context.Context, msg string, args ...map[string]any) {
	l.Printf("DEBUG: %s %v", msg, args)
}

func (l DefaultLogger) Info(ctx context.Context, msg string, args ...map[string]any) {
	l.Printf("INFO: %s %v", msg, args)
}

func (l DefaultLogger) Warn(ctx context.Context, msg string, args ...map[string]any) {
	l.Printf("WARN: %s %v", msg, args)
}

func (l DefaultLogger) Error(ctx context.Context, msg string, args ...map[string]any) {
	l.Printf("ERROR: %s %v", msg, args)
}
