// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"context"
	"time"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/log"
)

type CortexClient interface {
	IsCortexClient()
	ValidateAPIKey(ctx context.Context) (bool, error)
	APIURL() string
	APIKeyType() string
	SkipSSLVerify() bool
	Timeout() time.Duration
	MaxRetries() int
	RetryMaxDelay() time.Duration
	CrashStackDir() string
	LogLevel() string
	Logger() log.Logger
	SkipLoggingTransport() bool
}
