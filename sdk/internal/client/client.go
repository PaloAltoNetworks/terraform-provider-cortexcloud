// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package client provides the core HTTP client for making API requests.
package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mathRand "math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/errors"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/config"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/log"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/version"
)

const (
	// NonceLength defines the length of the cryptographic nonce used in
	// authentication headers.
	NonceLength = 64
	// AuthCharset is the character set used for generating the nonce.
	AuthCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// ValidateAPIKeyEndpoint is the path for the API key validation
	// endpoint.
	ValidateAPIKeyEndpoint = "api_keys/validate"
)

// Client is the core HTTP client for interacting with the Cortex Cloud API.
//
// This client is intended for internal use by higher-level SDK modules.
// All configuration is passed during its creation via a Config object.
type Client struct {
	config     *config.Config
	httpClient *http.Client
	apiKeyId   string // String representation of ApiKeyId for headers

	// testData and testIndex are for internal testing/mocking purposes.
	testData  []*http.Response
	testIndex int
}

// Marker method for CortexClient interface compliance.
func (Client) IsCortexClient() {}

// APIURL returns the API URL for the Cortex.
func (c *Client) APIURL() string { return c.config.CortexAPIURL() }

// APIKeyType returns the Cortex API key type.
func (c *Client) APIKeyType() string { return c.config.CortexAPIKeyType() }

// APIKeyID returns the Cortex API key ID.
func (c *Client) APIKeyID() int { return c.config.CortexAPIKeyID() }

// SkipSSLVerify returns whether to skip TLS certificate verification.
func (c *Client) SkipSSLVerify() bool { return c.config.SkipSSLVerify() }

// Timeout returns the HTTP timeout.
func (c *Client) Timeout() time.Duration {
	return time.Duration(c.config.Timeout()) * time.Second
}

// MaxRetries returns the maximum number of retries.
func (c *Client) MaxRetries() int { return c.config.MaxRetries() }

// RetryMaxDelay returns the maximum retry delay.
func (c *Client) RetryMaxDelay() time.Duration {
	return time.Duration(c.config.RetryMaxDelay()) * time.Second
}

// CrashStackDir returns the crash stack directory.
func (c *Client) CrashStackDir() string { return c.config.CrashStackDir() }

// LogLevel returns the log level.
func (c *Client) LogLevel() string { return c.config.LogLevel() }

// Logger returns the logger.
func (c *Client) Logger() log.Logger { return c.config.Logger() }

// SkipLoggingTransport returns whether to skip logging transport.
func (c *Client) SkipLoggingTransport() bool { return c.config.SkipLoggingTransport() }

// NewClientFromConfig creates and initializes a new core HTTP client from a config object.
// It takes a pointer to a Config, which should be fully configured.
func NewClientFromConfig(cfg *config.Config) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("received nil Config")
	}

	// Validate the configuration from the api module
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid API configuration: %w", err)
	}

	cfg.SetDefaults()

	// Set up the HTTP transport based on config
	transport := cfg.Transport()
	if transport == nil {
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.SkipSSLVerify(),
			},
		}
	}

	// Create the HTTP client
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout()) * time.Second,
	}

	// Wrap transport with logging if not skipped
	if !cfg.SkipLoggingTransport() {
		httpClient.Transport = NewTransport(httpClient.Transport, &internalClientAdapter{cfg})
	}

	return &Client{
		config:     cfg,
		httpClient: httpClient,
		apiKeyId:   strconv.Itoa(cfg.CortexAPIKeyID()),
	}, nil
}

// internalClientAdapter adapts the Config to the InternalClient interface
// required by the transport. This allows the transport to access logging and
// pre-request validation settings directly from the config.
type internalClientAdapter struct {
	cfg *config.Config
}

// logLevelStringToInt maps string log levels to an integer for comparison.
// Higher integer means higher severity.
// This helper is internal to the logging logic.
func logLevelStringToInt(level string) int {
	switch strings.ToLower(level) {
	case "quiet":
		return -1 // Represents "off"
	case "error":
		return 0
	case "warn":
		return 1
	case "info":
		return 2
	case "debug":
		return 3
	default:
		return -1 // Default to "off" for unknown configured levels
	}
}

// LogLevelIsSetTo checks if the client's configured log level allows for a given specific level.
// This method is primarily used by the transport layer to decide whether to dump detailed request/response.
func (a *internalClientAdapter) LogLevelIsSetTo(v string) bool {
	return logLevelStringToInt(a.cfg.LogLevel()) >= logLevelStringToInt(v)
}

// Log writes the given message to the logger according to the configured LogLevel.
func (a *internalClientAdapter) Log(ctx context.Context, level, msg string) {
	if a.cfg.Logger() == nil {
		return
	}

	configuredLevelInt := logLevelStringToInt(a.cfg.LogLevel())
	msgLevelInt := logLevelStringToInt(level)

	// Only log if the message's severity is greater than or equal to the configured minimum level
	if msgLevelInt >= configuredLevelInt {
		switch strings.ToLower(level) {
		case "debug":
			a.cfg.Logger().Debug(ctx, msg)
		case "info":
			a.cfg.Logger().Info(ctx, msg)
		case "warn":
			a.cfg.Logger().Warn(ctx, msg)
		case "error":
			a.cfg.Logger().Error(ctx, msg)
		default:
			a.cfg.Logger().Info(ctx, msg)
		}
	}
}

// ValidateAPIKey validates the configured API Key against the target
// Cortex tenant.
func (c *Client) ValidateAPIKey(ctx context.Context) (bool, error) {
	var validateResp string
	if _, err := c.Do(ctx, http.MethodGet, ValidateAPIKeyEndpoint, nil, nil, nil, &validateResp, nil); err != nil {
		return false, err
	}
	return (validateResp == "true"), nil
}

// generateHeaders creates all header key-value pairs for the current request
// using the client's configuration.
func (c *Client) generateHeaders(ctx context.Context, setContentType bool) (map[string]string, error) {
	headers := make(map[string]string)

	if setContentType {
		headers["Content-Type"] = "application/json"
	}

	// User-Agent: Use configured or generate default
	if c.config.Agent() != "" {
		headers["User-Agent"] = c.config.Agent()
	} else {
		// Fallback to basic SDK User-Agent
		headers["User-Agent"] = version.UserAgent()
	}

	// X-Request-ID: Generate or retrieve from context
	requestID := GetRequestID(ctx)
	if requestID == "" {
		requestID = generateRequestID()
	}
	headers["X-Request-ID"] = requestID

	headers["x-xdr-auth-id"] = c.apiKeyId

	switch strings.ToLower(c.config.CortexAPIKeyType()) {
	case "standard":
		headers["Authorization"] = c.config.CortexAPIKey()
	default:
		// Generate nonce
		nonceBytes := make([]byte, NonceLength)
		if _, err := rand.Read(nonceBytes); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}

		var nonceBuilder strings.Builder
		for _, b := range nonceBytes {
			nonceBuilder.WriteByte(AuthCharset[b%byte(len(AuthCharset))])
		}
		nonce := nonceBuilder.String()

		// Calculate Authorization hash
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		authKey := fmt.Sprintf("%s%s%s", c.config.CortexAPIKey(), nonce, timestamp)
		hasher := sha256.New()
		hasher.Write([]byte(authKey))
		apiKeyHash := hex.EncodeToString(hasher.Sum(nil))

		// Set XDR authentication headers
		headers["x-xdr-nonce"] = nonce
		headers["x-xdr-timestamp"] = timestamp
		headers["Authorization"] = apiKeyHash
	}

	return headers, nil
}

// calculateRetryDelay determines the sleep duration for retries using
// exponential backoff with jitter, based on the client's configuration.
func (c *Client) calculateRetryDelay(attempt int) time.Duration {
	// Apply default if not configured
	retryMaxDelay := c.config.RetryMaxDelay()
	if retryMaxDelay == 0 {
		retryMaxDelay = 60 // seconds
	}

	// Exponential backoff: 2^attempt seconds, with jitter
	baseDelay := time.Duration(1<<uint(attempt)) * time.Second
	maxDelay := time.Duration(retryMaxDelay) * time.Second

	if baseDelay > maxDelay {
		baseDelay = maxDelay // Cap the delay at RetryMaxDelay
	}

	// Add jitter (±25% randomization) to prevent thundering herd problem
	jitter := time.Duration(mathRand.Int63n(int64(baseDelay/2))) - baseDelay/4
	return baseDelay + jitter
}

// buildRequestURL constructs and validates the complete API URL from
// the base URL, endpoint, path parameters, and query parameters.
func (c *Client) buildRequestURL(endpoint string, pathParams *[]string, queryParams *url.Values) (string, error) {
	if c == nil {
		return "", fmt.Errorf("self is nil")
	}

	if c.config == nil {
		return "", fmt.Errorf("config is nil")
	}

	// Validate base URL
	baseURL, err := url.Parse(c.config.CortexAPIURL())
	if err != nil {
		return "", fmt.Errorf("invalid base API URL '%s': %w", c.config.CortexAPIURL(), err)
	}

	// Handle path parameters
	pathComponents := []string{strings.TrimPrefix(endpoint, "/")}
	if pathParams != nil && len(*pathParams) > 0 {
		for _, p := range *pathParams {
			pathComponents = append(pathComponents, strings.Trim(p, "/"))
		}
	}

	urlWithPathValues, err := url.JoinPath(baseURL.String(), pathComponents...)
	if err != nil {
		return "", fmt.Errorf("failed to construct URL with path components: %w", err)
	}

	parsedURL, err := url.Parse(urlWithPathValues)
	if err != nil {
		return "", fmt.Errorf("failed to parse constructed URL: %w", err)
	}

	// Handle query parameters
	if queryParams != nil && len(*queryParams) > 0 {
		parsedURL.RawQuery = queryParams.Encode()
	}

	// Validate full URL
	// (optional, as url.Parse already provides some validation)
	finalURLString := parsedURL.String()
	if _, err := url.Parse(finalURLString); err != nil {
		return "", fmt.Errorf("constructed URL '%s' is invalid: %w", finalURLString, err)
	}

	return finalURLString, nil
}

// isRetryableHTTPStatus checks if the given HTTP status code indicates a retryable error.
func isRetryableHTTPStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusUnauthorized, // 401: Might be temporary token issue, retry once
		http.StatusTooManyRequests,    // 429
		http.StatusBadGateway,         // 502
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout:     // 504
		return true
	default:
		return false
	}
}

// handleResponseStatus processes HTTP response status codes and returns a structured
// error if the status code indicates an API error. It does not handle retries directly.
func (c *Client) handleResponseStatus(ctx context.Context, statusCode int, body []byte) *errors.CortexCloudAPIError {
	if statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
		return nil
	}

	var apiError errors.CortexCloudAPIError
	unmarshalErr := json.Unmarshal(body, &apiError)

	if unmarshalErr == nil && apiError.HasContent() {
		return &apiError
	}

	// Either JSON unmarshaling failed, or it succeeded but none of the
	// known error fields were populated (e.g. the API returned a JSON
	// shape we don't recognise).  Fall back to including the raw HTTP
	// status code and response body so the user always sees actionable
	// diagnostic information.
	if unmarshalErr != nil {
		c.config.Logger().Error(ctx, fmt.Sprintf("Failed to unmarshal API error response (HTTP %d): %v, raw body: %s", statusCode, unmarshalErr, string(body)))
	} else {
		c.config.Logger().Error(ctx, fmt.Sprintf("API error response (HTTP %d) did not match any known error format, raw body: %s", statusCode, string(body)))
	}
	return &errors.CortexCloudAPIError{
		Code:    types.ToPointer(fmt.Sprintf("HTTP_%d", statusCode)),
		Message: types.ToPointer(fmt.Sprintf("API error (HTTP %d): %s", statusCode, string(body))),
	}
}

type DoOptions struct {
	RequestWrapperKeys  []string
	ResponseWrapperKeys []string
}

// Do performs the given API request.
//
// This is the core method for making authenticated HTTP calls to the Cortex Cloud
// API. It returns the raw response body and a structured SDK error if any
// error occurs.
func (c *Client) Do(ctx context.Context, method string, endpoint string, pathParams *[]string, queryParams *url.Values, input, output any, opts *DoOptions) ([]byte, error) {
	if c.httpClient == nil {
		return nil, errors.NewInternalSDKError(
			errors.CodeSDKInitializationFailure,
			"HTTP client not initialized; call NewClient() first",
			nil,
		)
	}

	// Ensure request ID is in context
	ctx, requestID := GetOrGenerateRequestID(ctx)

	// Log request start with request ID
	c.config.Logger().Info(ctx, "API request started", map[string]any{
		"request_id": requestID,
		"method":     method,
		"endpoint":   endpoint,
	})

	var (
		err  error
		body []byte
		data []byte
		resp *http.Response
	)

	// Marshal input into JSON if present
	if input != nil {
		var payload any = input
		if opts != nil && len(opts.RequestWrapperKeys) > 0 {
			// Reverse loop to wrap from inside out
			for i := len(opts.RequestWrapperKeys) - 1; i >= 0; i-- {
				payload = map[string]any{
					opts.RequestWrapperKeys[i]: payload,
				}
			}
		}
		data, err = json.Marshal(payload)
		if err != nil {
			return nil, errors.NewInternalSDKError(
				errors.CodeRequestSerializationFailure,
				fmt.Sprintf("failed to marshal request input: %v", err),
				err,
			)
		}
	}

	// Build and validate the complete URL
	requestURL, err := c.buildRequestURL(endpoint, pathParams, queryParams)
	if err != nil {
		return nil, errors.NewInternalSDKError(
			errors.CodeURLConstructionFailure,
			fmt.Sprintf("failed to build request URL: %v", err),
			err,
		)
	}

	for attempt := 0; attempt <= c.config.MaxRetries(); attempt++ {
		select {
		case <-ctx.Done():
			return nil, errors.NewInternalSDKError(
				errors.CodeContextCancellation,
				"request cancelled by context",
				ctx.Err(),
			)
		default:
			// Continue
		}

		// Handle test data if available (for internal SDK testing)
		if len(c.testData) != 0 {
			resp = c.testData[c.testIndex%len(c.testData)]
			c.testIndex++
		} else {
			// Create new HTTP request with context
			req, err := http.NewRequestWithContext(ctx, method, requestURL, strings.NewReader(string(data)))
			if err != nil {
				return nil, errors.NewInternalSDKError(
					errors.CodeHTTPRequestCreationFailure,
					fmt.Sprintf("failed to create HTTP request: %v", err),
					err,
				)
			}

			// Generate authentication headers
			authHeaders, err := c.generateHeaders(ctx, input != nil)
			if err != nil {
				return nil, errors.NewInternalSDKError(
					errors.CodeAuthenticationHeaderGenerationFailure,
					fmt.Sprintf("failed to generate request headers: %v", err),
					err,
				)
			}

			// Attach headers to request
			for k, v := range authHeaders {
				req.Header.Set(k, v)
			}

			// Execute HTTP request
			resp, err = c.httpClient.Do(req)
			if err != nil {
				// Check for context cancellation after Do() call
				if ctx.Err() != nil {
					return nil, errors.NewInternalSDKError(
						errors.CodeContextCancellation,
						"request cancelled by context after HTTP client call",
						ctx.Err(),
					)
				}
				// Network or client-side errors (e.g., connection refused, timeout) are generally retryable
				c.config.Logger().Debug(ctx, fmt.Sprintf("[ERROR] HTTP request failed (attempt %d/%d): %v", attempt+1, c.config.MaxRetries()+1, err), map[string]any{
					"request_id":  requestID,
					"attempt":     attempt + 1,
					"max_retries": c.config.MaxRetries() + 1,
				})
				if attempt < c.config.MaxRetries() {
					sleepDelay := c.calculateRetryDelay(attempt)
					c.config.Logger().Debug(ctx, fmt.Sprintf("[INFO] Sleeping %v before retry", sleepDelay), map[string]any{
						"request_id": requestID,
						"delay_ms":   sleepDelay.Milliseconds(),
					})
					if len(c.testData) == 0 { // Only sleep if not in test mode
						time.Sleep(sleepDelay)
					}
					continue
				} else {
					return nil, errors.NewInternalSDKError(
						errors.CodeNetworkError,
						fmt.Sprintf("HTTP request failed after %d retries: %v", c.config.MaxRetries(), err),
						err,
					)
				}
			}
			if resp == nil {
				return nil, errors.NewInternalSDKError(
					errors.CodeNoResponseReceived,
					"no HTTP response received",
					nil,
				)
			}
		}

		// Read the response body content
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, errors.NewInternalSDKError(
				errors.CodeResponseBodyReadFailure,
				fmt.Sprintf("failed to read response body: %v", err),
				err,
			)
		}

		// Handle the response status code and determine if a retry is needed
		apiError := c.handleResponseStatus(ctx, resp.StatusCode, body)
		if apiError != nil {
			if isRetryableHTTPStatus(resp.StatusCode) && attempt < c.config.MaxRetries() {
				c.config.Logger().Debug(ctx, fmt.Sprintf("[INFO] API returned retryable status %d; sleeping %v before retry (attempt %d/%d)", resp.StatusCode, c.calculateRetryDelay(attempt), attempt+1, c.config.MaxRetries()+1))
				sleepDelay := c.calculateRetryDelay(attempt)
				c.config.Logger().Debug(ctx, fmt.Sprintf("[INFO] API returned retryable status %d", resp.StatusCode), map[string]any{
					"request_id":  requestID,
					"status_code": resp.StatusCode,
					"attempt":     attempt + 1,
					"delay_ms":    sleepDelay.Milliseconds(),
				})

				// Skip sleeping between retries if we're in a test
				if len(c.testData) == 0 {
					time.Sleep(sleepDelay)
				}
				continue
			} else {
				// Non-retryable API error or max retries reached for a retryable status
				return body, apiError
			}
		}

		// Exit the retry loop on success
		break
	}

	// Log successful completion
	c.config.Logger().Info(ctx, "API request completed", map[string]any{
		"request_id":  requestID,
		"status_code": resp.StatusCode,
	})

	// Unmarshal the response data into output if output is provided and response data exists
	if output != nil && len(body) > 0 {
		var dataToUnmarshal []byte = body
		if opts != nil && len(opts.ResponseWrapperKeys) > 0 {
			var currentData json.RawMessage = body
			for _, key := range opts.ResponseWrapperKeys {
				var wrapper map[string]json.RawMessage
				if err := json.Unmarshal(currentData, &wrapper); err != nil {
					return body, errors.NewInternalSDKError(
						errors.CodeResponseDeserializationFailure,
						fmt.Sprintf("failed to unmarshal response wrapper for key '%s': %v", key, err),
						err,
					)
				}
				var ok bool
				currentData, ok = wrapper[key]
				if !ok {
					return body, errors.NewInternalSDKError(
						errors.CodeResponseDeserializationFailure,
						fmt.Sprintf("response wrapper key '%s' not found", key),
						nil,
					)
				}
			}
			dataToUnmarshal = currentData
		}
		if err = json.Unmarshal(dataToUnmarshal, output); err != nil {
			// If unmarshaling fails, return the raw body and a structured unmarshaling error
			return body, errors.NewInternalSDKError(
				errors.CodeResponseDeserializationFailure,
				fmt.Sprintf("failed to unmarshal response body into output type: %v", err),
				err,
			)
		}
	}

	// Return the raw body on success
	return body, nil
}
