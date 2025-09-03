// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	_log "github.com/PaloAltoNetworks/cortex-cloud-go/log"
)

const (
	CORTEXCLOUD_API_URL_ENV_VAR                 = "CORTEXCLOUD_API_URL"
	CORTEXCLOUD_API_PORT_ENV_VAR                = "CORTEXCLOUD_API_PORT"
	CORTEXCLOUD_API_KEY_ENV_VAR                 = "CORTEXCLOUD_API_KEY"
	CORTEXCLOUD_API_KEY_ID_ENV_VAR              = "CORTEXCLOUD_API_KEY_ID"
	CORTEXCLOUD_HEADERS_ENV_VAR                 = "CORTEXCLOUD_HEADERS"
	CORTEXCLOUD_AGENT_ENV_VAR                   = "CORTEXCLOUD_AGENT"
	CORTEXCLOUD_SKIP_VERIFY_CERTIFICATE_ENV_VAR = "CORTEXCLOUD_SKIP_VERIFY_CERTIFICATE"
	CORTEXCLOUD_CONFIG_FILE_ENV_VAR             = "CORTEXCLOUD_CONFIG_FILE"
	CORTEXCLOUD_TIMEOUT_ENV_VAR                 = "CORTEXCLOUD_TIMEOUT"
	CORTEXCLOUD_MAX_RETRIES_ENV_VAR             = "CORTEXCLOUD_MAX_RETRIES"
	CORTEXCLOUD_RETRY_MAX_DELAY_ENV_VAR         = "CORTEXCLOUD_RETRY_MAX_DELAY"
	CORTEXCLOUD_CRASH_STACK_DIR_ENV_VAR         = "CORTEXCLOUD_CRASH_STACK_DIR"
	CORTEXCLOUD_LOG_LEVEL_ENV_VAR               = "CORTEXCLOUD_LOG_LEVEL"
	CORTEXCLOUD_SKIP_LOGGING_TRANSPORT_ENV_VAR  = "CORTEXCLOUD_SKIP_LOGGING_TRANSPORT"
	CORTEXCLOUD_SKIP_PRE_REQUEST_VALIDATION     = "CORTEXCLOUD_SKIP_PRE_REQUEST_VALIDATION"
)

type Config struct {
	ApiUrl                   string            `json:"api_url" validate:"required,url"`
	ApiKey                   string            `json:"api_key" validate:"required,base64"`
	ApiKeyId                 int               `json:"api_key_id" validate:"required,gte=1"`
	ApiPort                  int               `json:"api_port" validate:"gte=1,lte=65535"`
	Headers                  map[string]string `json:"headers"`
	Agent                    string            `json:"agent"`
	SkipVerifyCertificate    bool              `json:"skip_verify_certificate"`
	Transport                *http.Transport   `json:"-"`
	Timeout                  int               `json:"timeout"`
	MaxRetries               int               `json:"max_retries"`
	RetryMaxDelay            int               `json:"retry_max_delay"`
	CrashStackDir            string            `json:"crash_stack_dir"`
	LogLevel                 string            `json:"log_level"`
	Logger                   _log.Logger       `json:"-"`
	SkipLoggingTransport     bool              `json:"skip_logging_transport"`
	SkipPreRequestValidation bool              `json:"skip_pre_request_validation"`
}

func NewConfig(apiUrl, apiKey string, apiKeyId int, checkEnvironment bool, opts ...Option) *Config {
	config := &Config{
		ApiUrl:                   apiUrl,
		ApiKey:                   apiKey,
		ApiKeyId:                 apiKeyId,
		ApiPort:                  443,
		Headers:                  make(map[string]string),
		Agent:                    "",
		SkipVerifyCertificate:    false,
		Transport:                http.DefaultTransport.(*http.Transport),
		Timeout:                  30, // 30 seconds
		MaxRetries:               3,
		RetryMaxDelay:            60, // 60 seconds
		CrashStackDir:            os.TempDir(),
		LogLevel:                 "info",
		Logger:                   nil,
		SkipLoggingTransport:     false,
		SkipPreRequestValidation: false,
	}

	for _, opt := range opts {
		opt(config)
	}

	if checkEnvironment {
		config.overwriteFromEnvVars()
	}

	return config
}

func NewConfigFromFile(filepath string, checkEnvironment bool) (*Config, error) {
	cBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("Error reading configuration file: %s", err)
	}

	var cFile Config
	if err = json.Unmarshal(cBytes, &cFile); err != nil {
		return nil, fmt.Errorf("Error unmarshalling configuration file: %s", err)
	}

	return NewConfig(
		cFile.ApiUrl,
		cFile.ApiKey,
		cFile.ApiKeyId,
		checkEnvironment,
		WithHeaders(cFile.Headers),
		WithAgent(cFile.Agent),
		WithSkipVerifyCertificate(cFile.SkipVerifyCertificate),
		WithTransport(cFile.Transport),
		WithTimeout(cFile.Timeout),
		WithMaxRetries(cFile.MaxRetries),
		WithRetryMaxDelay(cFile.RetryMaxDelay),
		WithCrashStackDir(cFile.CrashStackDir),
		WithLogLevel(cFile.LogLevel),
		WithLogger(cFile.Logger),
		WithSkipLoggingTransport(cFile.SkipLoggingTransport),
	), nil
}

func (c Config) Validate() error {
	// TODO
	return nil
}

func (c *Config) overwriteFromEnvVars() {
	if envApiUrl, ok := os.LookupEnv(CORTEXCLOUD_API_URL_ENV_VAR); ok {
		c.ApiUrl = envApiUrl
	}

	if envApiKey, ok := os.LookupEnv(CORTEXCLOUD_API_KEY_ENV_VAR); ok {
		c.ApiKey = envApiKey
	}

	if envApiKeyId, ok := os.LookupEnv(CORTEXCLOUD_API_KEY_ID_ENV_VAR); ok {
		if parsedInt, err := strconv.Atoi(envApiKeyId); err == nil {
			c.ApiKeyId = parsedInt
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected integer.\n", CORTEXCLOUD_API_KEY_ID_ENV_VAR, envApiKeyId)
		}
	}

	if envApiPort, ok := os.LookupEnv(CORTEXCLOUD_API_PORT_ENV_VAR); ok {
		if parsedInt, err := strconv.Atoi(envApiPort); err == nil {
			c.ApiPort = parsedInt
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected integer.\n", CORTEXCLOUD_API_PORT_ENV_VAR, envApiPort)
		}
	}

	if envHeaders, ok := os.LookupEnv(CORTEXCLOUD_HEADERS_ENV_VAR); ok {
		// Example: HEADERS="Content-Type=application/json,Authorization=Bearer xyz"
		if c.Headers == nil {
			c.Headers = make(map[string]string)
		}

		for pair := range strings.SplitSeq(envHeaders, ",") {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				c.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	if envAgent, ok := os.LookupEnv(CORTEXCLOUD_AGENT_ENV_VAR); ok {
		c.Agent = envAgent
	}

	if envSkipVerifyCertificate, ok := os.LookupEnv(CORTEXCLOUD_SKIP_VERIFY_CERTIFICATE_ENV_VAR); ok {
		if parsedBool, err := strconv.ParseBool(envSkipVerifyCertificate); err == nil {
			c.SkipVerifyCertificate = parsedBool
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected true/false.\n", CORTEXCLOUD_SKIP_VERIFY_CERTIFICATE_ENV_VAR, envSkipVerifyCertificate)
		}
	}

	if envTimeout, ok := os.LookupEnv(CORTEXCLOUD_TIMEOUT_ENV_VAR); ok {
		if parsedInt, err := strconv.Atoi(envTimeout); err == nil {
			c.Timeout = parsedInt
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected integer.\n", CORTEXCLOUD_TIMEOUT_ENV_VAR, envTimeout)
		}
	}

	if envMaxRetries, ok := os.LookupEnv(CORTEXCLOUD_MAX_RETRIES_ENV_VAR); ok {
		if parsedInt, err := strconv.Atoi(envMaxRetries); err == nil {
			c.MaxRetries = parsedInt
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected integer.\n", CORTEXCLOUD_MAX_RETRIES_ENV_VAR, envMaxRetries)
		}
	}

	if envRetryMaxDelay, ok := os.LookupEnv(CORTEXCLOUD_RETRY_MAX_DELAY_ENV_VAR); ok {
		if parsedInt, err := strconv.Atoi(envRetryMaxDelay); err == nil {
			c.RetryMaxDelay = parsedInt
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected integer.\n", CORTEXCLOUD_RETRY_MAX_DELAY_ENV_VAR, envRetryMaxDelay)
		}
	}

	if envCrashStackDir, ok := os.LookupEnv(CORTEXCLOUD_CRASH_STACK_DIR_ENV_VAR); ok {
		c.CrashStackDir = envCrashStackDir
	}

	if envLogLevel, ok := os.LookupEnv(CORTEXCLOUD_LOG_LEVEL_ENV_VAR); ok {
		c.LogLevel = envLogLevel
	}

	if envSkipLoggingTransport, ok := os.LookupEnv(CORTEXCLOUD_SKIP_LOGGING_TRANSPORT_ENV_VAR); ok {
		if parsedBool, err := strconv.ParseBool(envSkipLoggingTransport); err == nil {
			c.SkipLoggingTransport = parsedBool
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected true/false.\n", CORTEXCLOUD_SKIP_LOGGING_TRANSPORT_ENV_VAR, envSkipLoggingTransport)
		}
	}

	if envSkipPreRequestValidation, ok := os.LookupEnv(CORTEXCLOUD_SKIP_PRE_REQUEST_VALIDATION); ok {
		if parsedBool, err := strconv.ParseBool(envSkipPreRequestValidation); err == nil {
			c.SkipPreRequestValidation = parsedBool
		} else {
			fmt.Printf("Warning: Invalid value for %s environment variable: %s. Expected true/false.\n", CORTEXCLOUD_SKIP_PRE_REQUEST_VALIDATION, envSkipPreRequestValidation)
		}
	}
}
