// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	//"log"
	"maps"
	"net/http"

	sdkLog "github.com/PaloAltoNetworks/cortex-cloud-go/log"
)

type Option func(*Config)

// WithApiPort returns an Option that sets the ApiPort field.
func WithApiPort(port int) Option {
	return func(c *Config) {
		c.ApiPort = port
	}
}

// WithHeaders returns an Option that sets or adds to the Headers map.
func WithHeaders(headers map[string]string) Option {
	return func(c *Config) {
		if c.Headers == nil {
			c.Headers = make(map[string]string)
		}
		maps.Copy(c.Headers, headers)
	}
}

// WithAgent returns an Option that sets the Agent field.
func WithAgent(agent string) Option {
	return func(c *Config) {
		c.Agent = agent
	}
}

// WithSkipVerifyCertificate returns an Option that sets the SkipVerifyCertificate field.
func WithSkipVerifyCertificate(skip bool) Option {
	return func(c *Config) {
		c.SkipVerifyCertificate = skip
	}
}

// WithTransport returns an Option that sets the Transport field.
func WithTransport(transport *http.Transport) Option {
	return func(c *Config) {
		c.Transport = transport
	}
}

// WithTimeout returns an Option that sets the Timeout field (in seconds).
func WithTimeout(timeout int) Option {
	return func(c *Config) {
		c.Timeout = timeout
	}
}

// WithMaxRetries returns an Option that sets the MaxRetries field.
func WithMaxRetries(retries int) Option {
	return func(c *Config) {
		c.MaxRetries = retries
	}
}

// WithRetryMaxDelay returns an Option that sets the RetryMaxDelay field (in seconds).
func WithRetryMaxDelay(delay int) Option {
	return func(c *Config) {
		c.RetryMaxDelay = delay
	}
}

// WithCrashStackDir returns an Option that sets the CrashStackDir field.
func WithCrashStackDir(dir string) Option {
	return func(c *Config) {
		c.CrashStackDir = dir
	}
}

// WithLogLevel returns an Option that sets the LogLevel field.
func WithLogLevel(level string) Option {
	return func(c *Config) {
		c.LogLevel = level
	}
}

// WithLogger returns an Option that sets the Logger field.
func WithLogger(l sdkLog.Logger) Option {
	return func(c *Config) {
		c.Logger = l
	}
}

// WithSkipLoggingTransport returns an Option that sets the SkipLoggingTransport field.
func WithSkipLoggingTransport(skip bool) Option {
	return func(c *Config) {
		c.SkipLoggingTransport = skip
	}
}

// WithSkipPreRequestValidation returns an Option that sets the SkipPreRequestValidation field.
func WithSkipPreRequestValidation(skip bool) Option {
	return func(c *Config) {
		c.SkipPreRequestValidation = skip
	}
}
