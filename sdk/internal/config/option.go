// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	//"log"
	"maps"
	"net/http"

	sdkLog "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/log"
)

type Option func(*Config)

// WithCortexAPIURL returns an Option that sets the CortexAPIURL field.
func WithCortexAPIURL(apiURL string) Option {
	return func(c *Config) {
		c.cortexAPIURL = apiURL
	}
}

// WithCortexAPIKey returns an Option that sets the CortexAPIKey field.
func WithCortexAPIKey(apiKey string) Option {
	return func(c *Config) {
		c.cortexAPIKey = apiKey
	}
}

// WithCortexAPIKeyID returns an Option that sets the CortexAPIKeyID field.
func WithCortexAPIKeyID(apiKeyID int) Option {
	return func(c *Config) {
		c.cortexAPIKeyID = apiKeyID
	}
}

// WithCortexAPIKeyType returns an Option that sets the CortexAPIKeyType field.
func WithCortexAPIKeyType(keyType string) Option {
	return func(c *Config) {
		if keyType != "" {
			c.cortexAPIKeyType = keyType
		}
	}
}

// WithHeaders returns an Option that sets or adds to the Headers map.
func WithHeaders(headers map[string]string) Option {
	return func(c *Config) {
		if c.headers == nil {
			c.headers = make(map[string]string)
		}
		maps.Copy(c.headers, headers)
	}
}

// WithAgent returns an Option that sets the Agent field.
func WithAgent(agent string) Option {
	return func(c *Config) {
		c.agent = agent
	}
}

// WithSkipSSLVerify returns an Option that sets the SkipSSLVerify field.
func WithSkipSSLVerify(skip bool) Option {
	return func(c *Config) {
		c.skipSSLVerify = skip
	}
}

// WithTransport returns an Option that sets the Transport field.
func WithTransport(transport *http.Transport) Option {
	return func(c *Config) {
		c.transport = transport
	}
}

// WithTimeout returns an Option that sets the Timeout field (in seconds).
func WithTimeout(timeout int) Option {
	return func(c *Config) {
		c.timeout = timeout
	}
}

// WithMaxRetries returns an Option that sets the MaxRetries field.
func WithMaxRetries(retries int) Option {
	return func(c *Config) {
		c.maxRetries = retries
	}
}

// WithRetryMaxDelay returns an Option that sets the RetryMaxDelay field (in seconds).
func WithRetryMaxDelay(delay int) Option {
	return func(c *Config) {
		c.retryMaxDelay = delay
	}
}

// WithCrashStackDir returns an Option that sets the CrashStackDir field.
func WithCrashStackDir(dir string) Option {
	return func(c *Config) {
		c.crashStackDir = dir
	}
}

// WithLogLevel returns an Option that sets the LogLevel field.
func WithLogLevel(level string) Option {
	return func(c *Config) {
		c.logLevel = level
	}
}

// WithLogger returns an Option that sets the Logger field.
func WithLogger(l sdkLog.Logger) Option {
	return func(c *Config) {
		c.logger = l
	}
}

// WithSkipLoggingTransport returns an Option that sets the SkipLoggingTransport field.
func WithSkipLoggingTransport(skip bool) Option {
	return func(c *Config) {
		c.skipLoggingTransport = skip
	}
}
