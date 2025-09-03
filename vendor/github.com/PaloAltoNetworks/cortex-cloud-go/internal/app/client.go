// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathRand "math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PaloAltoNetworks/cortex-cloud-go/api"
	"github.com/PaloAltoNetworks/cortex-cloud-go/errors"
	"github.com/PaloAltoNetworks/cortex-cloud-go/internal/types"
	internalLog "github.com/PaloAltoNetworks/cortex-cloud-go/log"
)

const (
	// NonceLength defines the length of the cryptographic nonce used in authentication headers.
	NonceLength = 64
	// AuthCharset is the character set used for generating the nonce.
	AuthCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// Client is the core HTTP client for interacting with the Cortex Cloud API.
// It is intended for internal use by higher-level SDK modules (e.g., xsiam).
// All configuration is passed during its creation via an api.Config object.
type Client struct {
	config     *api.Config
	httpClient *http.Client
	apiKeyId   string // String representation of ApiKeyId for headers

	// testData and testIndex are for internal testing/mocking purposes.
	testData  []*http.Response
	testIndex int
}

// NewClient creates and initializes a new core HTTP client.
// It takes a pointer to an api.Config, which should be fully configured
// by the user-facing API module.
func NewClient(cfg *api.Config) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("received nil api.Config")
	}

	// Validate the configuration from the api module
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid API configuration: %w", err)
	}

	if cfg.Logger == nil {
		cfg.Logger = internalLog.DefaultLogger{Logger: log.Default()}
	}

	// Set up the HTTP transport based on config
	transport := cfg.Transport
	if transport == nil {
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.SkipVerifyCertificate,
			},
		}
	}

	// Create the HTTP client
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
	}

	// Wrap transport with logging if not skipped
	if !cfg.SkipLoggingTransport {
		// Pass the internal client's logging capabilities to the transport wrapper
		httpClient.Transport = NewTransport(httpClient.Transport, &internalClientAdapter{cfg})
	}

	return &Client{
		config:     cfg,
		httpClient: httpClient,
		apiKeyId:   strconv.Itoa(cfg.ApiKeyId),
	}, nil
}

// internalClientAdapter adapts the api.Config to the InternalClient interface
// required by the transport. This allows the transport to access logging and
// pre-request validation settings directly from the config.
type internalClientAdapter struct {
	cfg *api.Config
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
	return logLevelStringToInt(a.cfg.LogLevel) >= logLevelStringToInt(v)
}

// Log writes the given message to the logger according to the configured LogLevel.
func (a *internalClientAdapter) Log(ctx context.Context, level, msg string) {
	if a.cfg.Logger == nil {
		return
	}

	// Map configured log level string to an integer for comparison
	configuredLevelInt := logLevelStringToInt(a.cfg.LogLevel)

	// Map incoming message level string to an integer for comparison
	msgLevelInt := logLevelStringToInt(level)

	// Only log if the message's severity is greater than or equal to the configured minimum level
	if msgLevelInt >= configuredLevelInt {
		switch strings.ToLower(level) {
		case "debug":
			a.cfg.Logger.Debug(ctx, msg)
		case "info":
			a.cfg.Logger.Info(ctx, msg)
		case "warn":
			a.cfg.Logger.Warn(ctx, msg)
		case "error":
			a.cfg.Logger.Error(ctx, msg)
		default:
			// Fallback for unknown levels, log as info
			a.cfg.Logger.Info(ctx, msg)
		}
	}
}

func (a *internalClientAdapter) PreRequestValidationEnabled() bool {
	return !a.cfg.SkipPreRequestValidation
}

// generateHeaders creates all header key-value pairs for the current request,
// including authentication headers, using the client's configuration.
func (c *Client) generateHeaders(setContentType bool) (map[string]string, error) {
	headers := make(map[string]string)

	// Set Content-Type if requested
	if setContentType {
		headers["Content-Type"] = "application/json"
	}

	// Set User-Agent if configured
	if c.config.Agent != "" {
		headers["User-Agent"] = c.config.Agent
	}

	// Set XDR authentication ID
	headers["x-xdr-auth-id"] = c.apiKeyId

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

	// Generate timestamp
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)

	// Calculate Authorization hash
	authKey := fmt.Sprintf("%s%s%s", c.config.ApiKey, nonce, timestamp)
	hasher := sha256.New()
	hasher.Write([]byte(authKey))
	apiKeyHash := hex.EncodeToString(hasher.Sum(nil))

	// Set XDR authentication headers
	headers["x-xdr-nonce"] = nonce
	headers["x-xdr-timestamp"] = timestamp
	headers["Authorization"] = apiKeyHash

	return headers, nil
}

// calculateRetryDelay determines the sleep duration for retries using
// exponential backoff with jitter, based on the client's configuration.
func (c *Client) calculateRetryDelay(attempt int) time.Duration {
	// Ensure RetryMaxDelay has a sensible default if not set in config
	retryMaxDelay := c.config.RetryMaxDelay
	if retryMaxDelay == 0 {
		// Use a reasonable default if config doesn't specify
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
	// Parse base URL to ensure it's valid
	baseURL, err := url.Parse(c.config.ApiUrl)
	if err != nil {
		return "", fmt.Errorf("invalid base API URL '%s': %w", c.config.ApiUrl, err)
	}

	// Build path components, ensuring the endpoint is properly joined
	pathComponents := []string{strings.TrimPrefix(endpoint, "/")} // Remove leading slash from endpoint if present
	if pathParams != nil && len(*pathParams) > 0 {
		// Append path parameters, ensuring they are also trimmed of leading/trailing slashes if necessary
		for _, p := range *pathParams {
			pathComponents = append(pathComponents, strings.Trim(p, "/"))
		}
	}

	// Construct URL with path components
	urlWithPathValues, err := url.JoinPath(baseURL.String(), pathComponents...)
	if err != nil {
		return "", fmt.Errorf("failed to construct URL with path components: %w", err)
	}

	// Parse the constructed URL to add query parameters
	parsedURL, err := url.Parse(urlWithPathValues)
	if err != nil {
		return "", fmt.Errorf("failed to parse constructed URL: %w", err)
	}

	// Add query parameters if they exist
	if queryParams != nil && len(*queryParams) > 0 {
		parsedURL.RawQuery = queryParams.Encode()
	}

	// Validate the final URL (optional, as url.Parse already provides some validation)
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
	// For successful responses, return nil (no error).
	if statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
		return nil
	}

	var apiError errors.CortexCloudAPIError
	unmarshalErr := json.Unmarshal(body, &apiError)

	if unmarshalErr == nil {
		return &apiError
	} else {
		// If unmarshaling fails, create a generic API error with the raw body
		c.config.Logger.Error(ctx, fmt.Sprintf("Failed to unmarshal API error response (HTTP %d): %v, raw body: %s", statusCode, unmarshalErr, string(body)))
		return &errors.CortexCloudAPIError{
			Code: types.Pointer(errors.CodeAPIResponseParsingFailure),
			Message: types.Pointer(fmt.Sprintf("Failed to parse API error response (HTTP %d): %s", statusCode, string(body))),
		}
	}
}

// Do performs the given API request with iterative retry logic.
// This is the core method for making authenticated calls to the Cortex Cloud API.
// It returns the raw response body and a structured SDK error if any error 
// occurs (network, HTTP status, or unmarshaling).
func (c *Client) Do(ctx context.Context, method string, endpoint string, pathParams *[]string, queryParams *url.Values, input, output any) ([]byte, error) {
	if c.httpClient == nil {
		return nil, errors.NewInternalSDKError(
			errors.CodeSDKInitializationFailure,
			"HTTP client not initialized; call NewClient() first",
			nil,
		)
	}

	var (
		err  error
		body []byte
		data []byte
		resp *http.Response
	)

	// Marshal input into JSON if present
	if input != nil {
		data, err = json.Marshal(input)
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

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		// Check for context cancellation before each attempt
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
			authHeaders, err := c.generateHeaders(input != nil)
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
				c.config.Logger.Debug(ctx, fmt.Sprintf("[ERROR] HTTP request failed (attempt %d/%d): %v", attempt+1, c.config.MaxRetries+1, err))
				if attempt < c.config.MaxRetries {
					sleepDelay := c.calculateRetryDelay(attempt)
					c.config.Logger.Debug(ctx, fmt.Sprintf("[INFO] Sleeping %v before retry (attempt %d/%d)", sleepDelay, attempt+1, c.config.MaxRetries+1))
					if len(c.testData) == 0 { // Only sleep if not in test mode
						time.Sleep(sleepDelay)
					}
					continue
				} else {
					return nil, errors.NewInternalSDKError(
						errors.CodeNetworkError,
						fmt.Sprintf("HTTP request failed after %d retries: %v", c.config.MaxRetries, err),
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
			if isRetryableHTTPStatus(resp.StatusCode) && attempt < c.config.MaxRetries {
				c.config.Logger.Debug(ctx, fmt.Sprintf("[INFO] API returned retryable status %d; sleeping %v before retry (attempt %d/%d)", resp.StatusCode, c.calculateRetryDelay(attempt), attempt+1, c.config.MaxRetries+1))
				sleepDelay := c.calculateRetryDelay(attempt)

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

	// Unmarshal the response data into output if output is provided and response data exists
	if output != nil && len(body) > 0 {
		if err = json.Unmarshal(body, output); err != nil {
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
