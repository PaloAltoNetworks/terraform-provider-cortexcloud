// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	sdk "github.com/PaloAltoNetworks/cortex-cloud-go/api"
	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type CortexCloudProviderModel struct {
	ConfigFile           types.String `tfsdk:"config_file"`
	ApiUrl               types.String `tfsdk:"cortex_cloud_api_url"`
	ApiPort              types.Int32  `tfsdk:"cortex_cloud_api_port"`
	ApiKey               types.String `tfsdk:"cortex_cloud_api_key"`
	ApiKeyId             types.Int32  `tfsdk:"cortex_cloud_api_key_id"`
	SkipSslVerify        types.Bool   `tfsdk:"skip_ssl_verify"`
	SdkLogLevel          types.String `tfsdk:"sdk_log_level"`
	RequestTimeout       types.Int32  `tfsdk:"request_timeout"`
	RequestRetryInterval types.Int32  `tfsdk:"request_retry_interval"`
	CrashStackDir        types.String `tfsdk:"crash_stack_dir"`
	CheckEnvironment     types.Bool   `tfsdk:"check_environment"`
}

var (
	ApiUrlEnvVars = []string{
		"CORTEX_CLOUD_API_URL",
		"CORTEXCLOUD_API_URL",
		"CORTEX_API_URL",
	}
	ApiPortEnvVars = []string{
		"CORTEX_CLOUD_API_PORT",
		"CORTEXCLOUD_API_PORT",
		"CORTEX_API_PORT",
	}
	ApiKeyEnvVars = []string{
		"CORTEX_CLOUD_API_KEY",
		"CORTEXCLOUD_API_KEY",
		"CORTEX_API_KEY",
	}
	ApiKeyIdEnvVars = []string{
		"CORTEX_CLOUD_API_KEY_ID",
		"CORTEXCLOUD_API_KEY_ID",
		"CORTEX_API_KEY_ID",
	}
	SkipSslVerifyEnvVars = []string{
		"CORTEX_CLOUD_SKIP_SSL_VERIFY",
		"CORTEXCLOUD_SKIP_SSL_VERIFY",
		"CORTEX_SKIP_SSL_VERIFY",
	}
	SdkLogLevelEnvVars = []string{
		"CORTEX_CLOUD_SDK_LOG_LEVEL",
		"CORTEXCLOUD_SDK_LOG_LEVEL",
		"CORTEX_SDK_LOG_LEVEL",
	}
	RequestTimeoutEnvVars = []string{
		"CORTEX_CLOUD_REQUEST_TIMEOUT",
		"CORTEXCLOUD_REQUEST_TIMEOUT",
		"CORTEX_REQUEST_TIMEOUT",
	}
	RequestRetryIntervalEnvVars = []string{
		"CORTEX_CLOUD_REQUEST_RETRY_INTERVAL",
		"CORTEXCLOUD_REQUEST_RETRY_INTERVAL",
		"CORTEX_REQUEST_RETRY_INTERVAL",
	}
	CrashStackDirEnvVars = []string{
		"CORTEX_CLOUD_CRASH_STACK_DIR",
		"CORTEXCLOUD_CRASH_STACK_DIR",
		"CORTEX_CRASH_STACK_DIR",
	}
)

type CortexCloudSDKClients struct {
	Config          sdk.Config
	AppSec          *appsec.Client
	CloudOnboarding *cloudonboarding.Client
	Platform        *platform.Client
}

func (m *CortexCloudProviderModel) Validate(ctx context.Context, diagnostics *diag.Diagnostics) {
	if m.ApiUrl.IsNull() || m.ApiUrl.IsUnknown() || m.ApiUrl.ValueString() == "" {
		diagnostics.AddAttributeError(
			path.Root("cortex_cloud_api_url"),
			"Invalid Provider Configuration",
			"value cannot be null or empty",
		)
	}

	if m.ApiKey.IsNull() || m.ApiKey.IsUnknown() || m.ApiKey.ValueString() == "" {
		diagnostics.AddAttributeError(
			path.Root("cortex_cloud_api_key"),
			"Invalid Provider Configuration",
			"value cannot be null or empty",
		)
	}

	if m.ApiKeyId.IsNull() || m.ApiKeyId.IsUnknown() || int(m.ApiKeyId.ValueInt32()) == 0 {
		diagnostics.AddAttributeError(
			path.Root("cortex_cloud_api_key_id"),
			"Invalid Provider Configuration",
			"value cannot be null or zero",
		)
	}
}

// ParseConfigFile reads the JSON file at the filepath specified in the
// provider block `config_file` argument and overwrites the provider
// configuration values with the config file values.
func (m *CortexCloudProviderModel) ParseConfigFile(ctx context.Context, diagnostics *diag.Diagnostics) {
	if m.ConfigFile.IsNull() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Parsing config file at %s", m.ConfigFile.ValueString()))

	// Handle different OS path formats
	cleanedPath := filepath.Clean(m.ConfigFile.ValueString())

	data, err := os.ReadFile(cleanedPath)
	if err != nil {
		var errMsg string
		if os.IsNotExist(err) {
			errMsg = fmt.Sprintf("file not found: %s", cleanedPath)
		} else if os.IsPermission(err) {
			errMsg = fmt.Sprintf("permission denied: %s", err.Error())
		} else {
			errMsg = fmt.Sprintf("error reading file: %s", err.Error())
		}

		diagnostics.AddAttributeError(
			path.Root("config_file"),
			"Provider Configuration Error",
			fmt.Sprintf("Error occured reading config file: %s", errMsg),
		)

		return
	}

	config := struct {
		ApiUrl               *string `json:"cortex_cloud_api_url"`
		ApiPort              *int32  `json:"cortex_cloud_api_port"`
		ApiKey               *string `json:"cortex_cloud_api_key"`
		ApiKeyId             *int32  `json:"cortex_cloud_api_key_id"`
		SkipSslVerify        *bool   `json:"skip_ssl_verify"`
		SdkLogLevel          *string `json:"sdk_log_level"`
		RequestTimeout       *int32  `json:"request_timeout"`
		RequestRetryInterval *int32  `json:"request_retry_interval"`
		CrashStackDir        *string `json:"crash_stack_dir"`
		CheckEnvironment     *bool   `json:"check_environment"`
	}{}

	if err := json.Unmarshal(data, &config); err != nil {

		diagnostics.AddAttributeError(
			path.Root("config_file"),
			"Provider Configuration Error",
			fmt.Sprintf("Error occured unmarshalling config file: %s", err.Error()),
		)
		return
	}

	tflog.Debug(ctx, "Config file successfully parsed -- overwriting provider block configuration")

	if config.ApiUrl != nil {
		m.ApiUrl = types.StringValue(*config.ApiUrl)
	}
	if config.ApiPort != nil {
		m.ApiPort = types.Int32Value(*config.ApiPort)
	}
	if config.ApiKey != nil {
		m.ApiKey = types.StringValue(*config.ApiKey)
	}
	if config.ApiKeyId != nil {
		m.ApiKeyId = types.Int32Value(*config.ApiKeyId)
	}
	if config.SkipSslVerify != nil {
		m.SkipSslVerify = types.BoolValue(*config.SkipSslVerify)
	}
	if config.SdkLogLevel != nil {
		m.SdkLogLevel = types.StringValue(*config.SdkLogLevel)
	}
	if config.RequestTimeout != nil {
		m.RequestTimeout = types.Int32Value(*config.RequestTimeout)
	}
	if config.RequestRetryInterval != nil {
		m.RequestRetryInterval = types.Int32Value(*config.RequestRetryInterval)
	}
	if config.CrashStackDir != nil {
		m.CrashStackDir = types.StringValue(*config.CrashStackDir)
	}
	if config.CheckEnvironment != nil {
		m.CheckEnvironment = types.BoolValue(*config.CheckEnvironment)
	}
}

// ParseEnvVars
func (m *CortexCloudProviderModel) ParseEnvVars(ctx context.Context, diagnostics *diag.Diagnostics) {
	if m.CheckEnvironment.IsNull() || !m.CheckEnvironment.ValueBool() {
		tflog.Debug(ctx, "Skipping environment variable parsing (check_environment = false)")
		return
	}

	tflog.Debug(ctx, "Parsing environment variables for provider configuration")

	// String types
	if val, ok := MultiEnvGet(ApiUrlEnvVars); ok {
		if val != m.ApiUrl.ValueString() {
			tflog.Debug(ctx, fmt.Sprintf("Overwriting api_url with value from environment variable (%s)", val))
			m.ApiUrl = types.StringValue(val)
		}
	}
	if val, ok := MultiEnvGet(ApiKeyEnvVars); ok {
		if val != m.ApiKey.ValueString() {
			tflog.Debug(ctx, fmt.Sprintf("Overwriting api_key with value from environment variable (%s)", val))
			m.ApiKey = types.StringValue(val)
		}
	}
	if val, ok := MultiEnvGet(SdkLogLevelEnvVars); ok {
		if val != m.SdkLogLevel.ValueString() {
			tflog.Debug(ctx, fmt.Sprintf("Overwriting sdk_log_level with value from environment variable (%s)", val))
			m.SdkLogLevel = types.StringValue(val)
		}
	}
	if val, ok := MultiEnvGet(CrashStackDirEnvVars); ok {
		if val != m.CrashStackDir.ValueString() {
			tflog.Debug(ctx, fmt.Sprintf("Overwriting crash_stack_dir with value from environment variable (%s)", val))
			m.CrashStackDir = types.StringValue(val)
		}
	}

	// Integer types
	if val, ok := MultiEnvGet(ApiPortEnvVars); ok {
		if i, err := strconv.ParseInt(val, 10, 32); err == nil {
			parsedVal := int32(i)
			if m.ApiPort.IsNull() || parsedVal != m.ApiPort.ValueInt32() {
				tflog.Debug(ctx, fmt.Sprintf("Overwriting api_port with value from environment variable (%d)", parsedVal))
				m.ApiPort = types.Int32Value(parsedVal)
			}
		} else {
			diagnostics.AddAttributeWarning(path.Root("cortex_cloud_api_port"), "Environment Variable Parsing Error", fmt.Sprintf("Failed to parse value from environment variable \"%s\" to integer\nError: %s", val, err.Error()))
		}
	}
	if val, ok := MultiEnvGet(ApiKeyIdEnvVars); ok {
		if i, err := strconv.ParseInt(val, 10, 32); err == nil {
			parsedVal := int32(i)
			if m.ApiKeyId.IsNull() || parsedVal != m.ApiKeyId.ValueInt32() {
				tflog.Debug(ctx, fmt.Sprintf("Overwriting cortex_cloud_api_key_id with value from environment variable (%d)", parsedVal))
				m.ApiKeyId = types.Int32Value(parsedVal)
			}
		} else {
			diagnostics.AddAttributeWarning(path.Root("cortex_cloud_api_key_id"), "Environment Variable Parsing Error", fmt.Sprintf("Failed to parse value from environment variable \"%s\" to integer\nError: %s", val, err.Error()))
		}
	}
	if val, ok := MultiEnvGet(RequestTimeoutEnvVars); ok {
		if i, err := strconv.ParseInt(val, 10, 32); err == nil {
			parsedVal := int32(i)
			if m.RequestTimeout.IsNull() || parsedVal != m.RequestTimeout.ValueInt32() {
				tflog.Debug(ctx, fmt.Sprintf("Overwriting request_timeout with value from environment variable (%d)", parsedVal))
				m.RequestTimeout = types.Int32Value(parsedVal)
			}
		} else {
			diagnostics.AddAttributeWarning(path.Root("request_timeout"), "Environment Variable Parsing Error", fmt.Sprintf("Failed to parse value from environment variable \"%s\" to integer\nError: %s", val, err.Error()))
		}
	}
	if val, ok := MultiEnvGet(RequestRetryIntervalEnvVars); ok {
		if i, err := strconv.ParseInt(val, 10, 32); err == nil {
			parsedVal := int32(i)
			if m.RequestRetryInterval.IsNull() || parsedVal != m.RequestRetryInterval.ValueInt32() {
				tflog.Debug(ctx, fmt.Sprintf("Overwriting request_retry_interval with value from environment variable (%d)", parsedVal))
				m.RequestRetryInterval = types.Int32Value(parsedVal)
			}
		} else {
			diagnostics.AddAttributeWarning(path.Root("request_retry_interval"), "Environment Variable Parsing Error", fmt.Sprintf("Failed to parse value from environment variable \"%s\" to integer\nError: %s", val, err.Error()))
		}
	}

	// Boolean types
	if val, ok := MultiEnvGet(SkipSslVerifyEnvVars); ok {
		if b, err := strconv.ParseBool(val); err == nil {
			if m.SkipSslVerify.IsNull() || b != m.SkipSslVerify.ValueBool() {
				tflog.Debug(ctx, fmt.Sprintf("Overwriting skip_ssl_verify with value from environment variable (%t)", b))
				m.SkipSslVerify = types.BoolValue(b)
			}
		} else {
			diagnostics.AddAttributeWarning(path.Root("skip_ssl_verify"), "Environment Variable Parsing Error", fmt.Sprintf("Failed to parse value from environment variable \"%s\" to boolean\nError: %s", val, err.Error()))
		}
	}
}

// MultiEnvGet is a helper function that returns the value of the first
// environment variable in the given list that returns a non-empty value.
func MultiEnvGet(ks []string) (string, bool) {
	for _, k := range ks {
		if v := os.Getenv(k); v != "" {
			return v, true
		}
	}
	return "", false
}
