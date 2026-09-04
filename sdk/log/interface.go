// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package log provides a standard logging interface.
package log

import (
	"context"
)

type Logger interface {
	Debug(ctx context.Context, msg string, args ...map[string]any)
	Info(ctx context.Context, msg string, args ...map[string]any)
	Warn(ctx context.Context, msg string, args ...map[string]any)
	Error(ctx context.Context, msg string, args ...map[string]any)
}
