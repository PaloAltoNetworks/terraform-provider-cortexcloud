// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package log

import (
	"context"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type TflogAdapter struct{}

func (TflogAdapter) Debug(ctx context.Context, msg string, args ...map[string]any) {
	tflog.Debug(ctx, msg, args...)
}

func (TflogAdapter) Info(ctx context.Context, msg string, args ...map[string]any) {
	tflog.Info(ctx, msg, args...)
}

func (TflogAdapter) Warn(ctx context.Context, msg string, args ...map[string]any) {
	tflog.Warn(ctx, msg, args...)
}

func (TflogAdapter) Error(ctx context.Context, msg string, args ...map[string]any) {
	tflog.Error(ctx, msg, args...)
}
