// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package config handles client configuration.
package config

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	cortexLog "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/log"
)

const (
	CORTEXCLOUD_API_URL_ENV_VAR                = "CORTEXCLOUD_API_URL"
	CORTEXCLOUD_API_KEY_ENV_VAR                = "CORTEXCLOUD_API_KEY"
	CORTEXCLOUD_API_KEY_ID_ENV_VAR             = "CORTEXCLOUD_API_KEY_ID"
	CORTEXCLOUD_API_KEY_TYPE_ENV_VAR           = "CORTEXCLOUD_API_KEY_TYPE"
	CORTEXCLOUD_HEADERS_ENV_VAR                = "CORTEXCLOUD_HEADERS"
	CORTEXCLOUD_AGENT_ENV_VAR                  = "CORTEXCLOUD_AGENT"
	CORTEXCLOUD_SKIP_SSL_VERIFY_ENV_VAR        = "CORTEXCLOUD_SKIP_SSL_VERIFY"
	CORTEXCLOUD_CONFIG_FILE_ENV_VAR            = "CORTEXCLOUD_CONFIG_FILE"
	CORTEXCLOUD_TIMEOUT_ENV_VAR                = "CORTEXCLOUD_TIMEOUT"
	CORTEXCLOUD_MAX_RETRIES_ENV_VAR            = "CORTEXCLOUD_MAX_RETRIES"
	CORTEXCLOUD_RETRY_MAX_DELAY_ENV_VAR        = "CORTEXCLOUD_RETRY_MAX_DELAY"
	CORTEXCLOUD_CRASH_STACK_DIR_ENV_VAR        = "CORTEXCLOUD_CRASH_STACK_DIR"
	CORTEXCLOUD_LOG_LEVEL_ENV_VAR              = "CORTEXCLOUD_LOG_LEVEL"
	CORTEXCLOUD_SKIP_LOGGING_TRANSPORT_ENV_VAR = "CORTEXCLOUD_SKIP_LOGGING_TRANSPORT"
)

type Config struct {
	cortexAPIURL         string
	cortexAPIKey         string
	cortexAPIKeyID       int
	cortexAPIKeyType     string
	headers              map[string]string
	agent                string
	skipSSLVerify        bool
	transport            *http.Transport
	timeout              int
	maxRetries           int
	retryMaxDelay        int
	crashStackDir        string
	logLevel             string
	logger               cortexLog.Logger
	skipLoggingTransport bool
}

// CortexAPIURL returns the API URL for the Cortex.
func (c *Config) CortexAPIURL() string { return c.cortexAPIURL }

// CortexAPIKeyType returns the Cortex API key type.
func (c *Config) CortexAPIKeyType() string { return c.cortexAPIKeyType }

// CortexAPIKey returns the Cortex API key.
func (c *Config) CortexAPIKey() string { return c.cortexAPIKey }

// CortexAPIKeyID returns the Cortex API key ID.
func (c *Config) CortexAPIKeyID() int { return c.cortexAPIKeyID }

// Headers returns the HTTP headers.
func (c *Config) Headers() map[string]string { return c.headers }

// Agent returns the user agent.
func (c *Config) Agent() string { return c.agent }

// SkipSSLVerify returns whether to skip TLS certificate verification.
func (c *Config) SkipSSLVerify() bool { return c.skipSSLVerify }

// Transport returns the HTTP transport.
func (c *Config) Transport() *http.Transport { return c.transport }

// Timeout returns the HTTP timeout.
func (c *Config) Timeout() int { return c.timeout }

// MaxRetries returns the maximum number of retries.
func (c *Config) MaxRetries() int { return c.maxRetries }

// RetryMaxDelay returns the maximum retry delay.
func (c *Config) RetryMaxDelay() int { return c.retryMaxDelay }

// CrashStackDir returns the crash stack directory.
func (c *Config) CrashStackDir() string { return c.crashStackDir }

// LogLevel returns the log level.
func (c *Config) LogLevel() string { return c.logLevel }

// Logger returns the logger.
func (c *Config) Logger() cortexLog.Logger { return c.logger }

// SkipLoggingTransport returns whether to skip logging transport.
func (c *Config) SkipLoggingTransport() bool { return c.skipLoggingTransport }

// UnmarshalJSON unmarshals the provided byte array into the calling Config struct.
func (c *Config) UnmarshalJSON(data []byte) error {
	type Alias struct {
		CortexAPIURL         string            `json:"api_url"`
		CortexAPIKey         string            `json:"api_key"`
		CortexAPIKeyID       int               `json:"api_key_id"`
		CortexAPIKeyType     string            `json:"api_key_type"`
		Headers              map[string]string `json:"headers"`
		Agent                string            `json:"agent"`
		SkipSSLVerify        bool              `json:"skip_ssl_verify"`
		Transport            *http.Transport   `json:"-"`
		Timeout              int               `json:"timeout"`
		MaxRetries           int               `json:"max_retries"`
		RetryMaxDelay        int               `json:"retry_max_delay"`
		CrashStackDir        string            `json:"crash_stack_dir"`
		LogLevel             string            `json:"log_level"`
		Logger               cortexLog.Logger  `json:"-"`
		SkipLoggingTransport bool              `json:"skip_logging_transport"`
	}

	var aux Alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("failed to unmarshal JSON data into Config: %s", err.Error())
	}

	c.cortexAPIURL = aux.CortexAPIURL
	c.cortexAPIKey = aux.CortexAPIKey
	c.cortexAPIKeyID = aux.CortexAPIKeyID
	c.cortexAPIKeyType = aux.CortexAPIKeyType
	c.headers = aux.Headers
	c.agent = aux.Agent
	c.skipSSLVerify = aux.SkipSSLVerify
	c.timeout = aux.Timeout
	c.maxRetries = aux.MaxRetries
	c.retryMaxDelay = aux.RetryMaxDelay
	c.crashStackDir = aux.CrashStackDir
	c.logLevel = aux.LogLevel
	c.skipLoggingTransport = aux.SkipLoggingTransport

	return nil
}

func NewConfig(opts ...Option) *Config {
	config := &Config{
		cortexAPIURL:         "",
		cortexAPIKeyType:     "advanced",
		headers:              make(map[string]string),
		agent:                "",
		skipSSLVerify:        false,
		transport:            http.DefaultTransport.(*http.Transport),
		timeout:              30, // 30 seconds
		maxRetries:           3,
		retryMaxDelay:        60, // 60 seconds
		crashStackDir:        os.TempDir(),
		logLevel:             "info",
		logger:               nil,
		skipLoggingTransport: false,
	}

	config.overwriteFromEnvVars()

	for _, opt := range opts {
		opt(config)
	}

	return config
}

func NewConfigFromFile(filepath string) (*Config, error) {
	cBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("Error reading configuration file: %s", err)
	}

	var cFile Config
	if err = json.Unmarshal(cBytes, &cFile); err != nil {
		return nil, fmt.Errorf("Error unmarshalling configuration file: %s", err)
	}

	return NewConfig(
		WithCortexAPIURL(cFile.cortexAPIURL),
		WithCortexAPIKey(cFile.cortexAPIKey),
		WithCortexAPIKeyID(cFile.cortexAPIKeyID),
		WithCortexAPIKeyType(cFile.cortexAPIKeyType),
		WithHeaders(cFile.headers),
		WithAgent(cFile.agent),
		WithSkipSSLVerify(cFile.skipSSLVerify),
		WithTransport(cFile.transport),
		WithTimeout(cFile.timeout),
		WithMaxRetries(cFile.maxRetries),
		WithRetryMaxDelay(cFile.retryMaxDelay),
		WithCrashStackDir(cFile.crashStackDir),
		WithLogLevel(cFile.logLevel),
		WithLogger(cFile.logger),
		WithSkipLoggingTransport(cFile.skipLoggingTransport),
	), nil
}

func (c *Config) GetOptions() []Option {
	return []Option{
		WithCortexAPIURL(c.cortexAPIURL),
		WithCortexAPIKey(c.cortexAPIKey),
		WithCortexAPIKeyID(c.cortexAPIKeyID),
		WithCortexAPIKeyType(c.cortexAPIKeyType),
		WithHeaders(c.headers),
		WithAgent(c.agent),
		WithSkipSSLVerify(c.skipSSLVerify),
		WithTransport(c.transport),
		WithTimeout(c.timeout),
		WithMaxRetries(c.maxRetries),
		WithRetryMaxDelay(c.retryMaxDelay),
		WithCrashStackDir(c.crashStackDir),
		WithLogLevel(c.logLevel),
		WithLogger(c.logger),
		WithSkipLoggingTransport(c.skipLoggingTransport),
	}
}

func (c Config) Validate() error {
	if c.cortexAPIURL == "" {
		return fmt.Errorf("API URL not set")
	}

	if c.cortexAPIKey == "" {
		return fmt.Errorf("API key not set")
	}

	if c.cortexAPIKeyID == 0 {
		return fmt.Errorf("API key ID not set")
	}

	if c.cortexAPIKeyID < 0 {
		return fmt.Errorf("Invalid API key ID: %d", c.cortexAPIKeyID)
	}

	if c.cortexAPIKeyType != "standard" && c.cortexAPIKeyType != "advanced" {
		return fmt.Errorf("Invalid API key type: %s", c.cortexAPIKeyType)
	}

	return nil
}

// SetDefaults sets default values for the configuration.
func (c *Config) SetDefaults() {
	if c.logger == nil {
		c.logger = cortexLog.DefaultLogger{Logger: log.Default()}
	}
	if c.cortexAPIKeyType == "" {
		c.cortexAPIKeyType = "advanced"
	}
}

func (c *Config) overwriteFromEnvVars() {
	if envAPIURL, ok := os.LookupEnv(CORTEXCLOUD_API_URL_ENV_VAR); ok {
		c.cortexAPIURL = envAPIURL
	}

	if envAPIKey, ok := os.LookupEnv(CORTEXCLOUD_API_KEY_ENV_VAR); ok {
		c.cortexAPIKey = envAPIKey
	}

	if envAPIKeyID, ok := os.LookupEnv(CORTEXCLOUD_API_KEY_ID_ENV_VAR); ok {
		if parsedInt, err := strconv.Atoi(envAPIKeyID); err == nil {
			c.cortexAPIKeyID = parsedInt
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected integer.\n", CORTEXCLOUD_API_KEY_ID_ENV_VAR, envAPIKeyID)
		}
	}

	if envAPIKeyType, ok := os.LookupEnv(CORTEXCLOUD_API_KEY_TYPE_ENV_VAR); ok {
		c.cortexAPIKeyType = envAPIKeyType
	}

	if envHeaders, ok := os.LookupEnv(CORTEXCLOUD_HEADERS_ENV_VAR); ok {
		// Example: HEADERS="Content-Type=application/json,Authorization=Bearer xyz"
		if c.headers == nil {
			c.headers = make(map[string]string)
		}

		for pair := range strings.SplitSeq(envHeaders, ",") {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				c.headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	if envAgent, ok := os.LookupEnv(CORTEXCLOUD_AGENT_ENV_VAR); ok {
		c.agent = envAgent
	}

	if envSkipSSLVerify, ok := os.LookupEnv(CORTEXCLOUD_SKIP_SSL_VERIFY_ENV_VAR); ok {
		if parsedBool, err := strconv.ParseBool(envSkipSSLVerify); err == nil {
			c.skipSSLVerify = parsedBool
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected true/false.\n", CORTEXCLOUD_SKIP_SSL_VERIFY_ENV_VAR, envSkipSSLVerify)
		}
	}

	if envTimeout, ok := os.LookupEnv(CORTEXCLOUD_TIMEOUT_ENV_VAR); ok {
		if parsedInt, err := strconv.Atoi(envTimeout); err == nil {
			c.timeout = parsedInt
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected integer.\n", CORTEXCLOUD_TIMEOUT_ENV_VAR, envTimeout)
		}
	}

	if envMaxRetries, ok := os.LookupEnv(CORTEXCLOUD_MAX_RETRIES_ENV_VAR); ok {
		if parsedInt, err := strconv.Atoi(envMaxRetries); err == nil {
			c.maxRetries = parsedInt
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected integer.\n", CORTEXCLOUD_MAX_RETRIES_ENV_VAR, envMaxRetries)
		}
	}

	if envRetryMaxDelay, ok := os.LookupEnv(CORTEXCLOUD_RETRY_MAX_DELAY_ENV_VAR); ok {
		if parsedInt, err := strconv.Atoi(envRetryMaxDelay); err == nil {
			c.retryMaxDelay = parsedInt
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected integer.\n", CORTEXCLOUD_RETRY_MAX_DELAY_ENV_VAR, envRetryMaxDelay)
		}
	}

	if envCrashStackDir, ok := os.LookupEnv(CORTEXCLOUD_CRASH_STACK_DIR_ENV_VAR); ok {
		c.crashStackDir = envCrashStackDir
	}

	if envLogLevel, ok := os.LookupEnv(CORTEXCLOUD_LOG_LEVEL_ENV_VAR); ok {
		c.logLevel = envLogLevel
	}

	if envSkipLoggingTransport, ok := os.LookupEnv(CORTEXCLOUD_SKIP_LOGGING_TRANSPORT_ENV_VAR); ok {
		if parsedBool, err := strconv.ParseBool(envSkipLoggingTransport); err == nil {
			c.skipLoggingTransport = parsedBool
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected true/false.\n", CORTEXCLOUD_SKIP_LOGGING_TRANSPORT_ENV_VAR, envSkipLoggingTransport)
		}
	}
}
