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

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/cwp"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// TODO: keep removing duplicate logic in favor of SDK calls
// TODO: add support for `CORTEX_TF_*` env var names

type CortexCloudProviderModel struct {
	ConfigFile           types.String `tfsdk:"config_file"`
	FQDN                 types.String `tfsdk:"fqdn"`
	APIURL               types.String `tfsdk:"api_url"`
	APIKey               types.String `tfsdk:"api_key"`
	APIKeyID             types.Int32  `tfsdk:"api_key_id"`
	APIKeyType           types.String `tfsdk:"api_key_type"`
	SkipSSLVerify        types.Bool   `tfsdk:"skip_ssl_verify"`
	SDKLogLevel          types.String `tfsdk:"sdk_log_level"`
	RequestTimeout       types.Int32  `tfsdk:"request_timeout"`
	RequestRetryInterval types.Int32  `tfsdk:"request_retry_interval"`
	CrashStackDir        types.String `tfsdk:"crash_stack_dir"`
	CheckEnvironment     types.Bool   `tfsdk:"check_environment"`
}

var (
	FQDNEnvVars = []string{
		"CORTEX_CLOUD_FQDN",
		"CORTEXCLOUD_FQDN",
		"CORTEX_FQDN",
	}
	APIURLEnvVars = []string{
		"CORTEX_CLOUD_API_URL",
		"CORTEXCLOUD_API_URL",
		"CORTEX_API_URL",
	}
	APIKeyEnvVars = []string{
		"CORTEX_CLOUD_API_KEY",
		"CORTEXCLOUD_API_KEY",
		"CORTEX_API_KEY",
	}
	APIKeyTypeEnvVars = []string{
		"CORTEX_CLOUD_API_KEY_TYPE",
		"CORTEXCLOUD_API_KEY_TYPE",
		"CORTEX_API_KEY_TYPE",
	}
	APIKeyIDEnvVars = []string{
		"CORTEX_CLOUD_API_KEY_ID",
		"CORTEXCLOUD_API_KEY_ID",
		"CORTEX_API_KEY_ID",
	}
	SkipSSLVerifyEnvVars = []string{
		"CORTEX_CLOUD_SKIP_SSL_VERIFY",
		"CORTEXCLOUD_SKIP_SSL_VERIFY",
		"CORTEX_SKIP_SSL_VERIFY",
	}
	SDKLogLevelEnvVars = []string{
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
	AppSec          *appsec.Client
	CloudOnboarding *cloudonboarding.Client
	Platform        *platform.Client
	CWP             *cwp.Client
}

func (m *CortexCloudProviderModel) Validate(ctx context.Context, diags *diag.Diagnostics) {
	tflog.Debug(ctx, "Validating provider configuration")

	cortexFQDN := m.FQDN
	cortexAPIURL := m.APIURL
	cortexAPIKey := m.APIKey
	cortexAPIKeyID := m.APIKeyID

	urlIsConfigured := (!cortexAPIURL.IsNull() && !cortexAPIURL.IsUnknown() && cortexAPIURL.ValueString() != "")
	fqdnIsConfigured := (!cortexFQDN.IsNull() && !cortexFQDN.IsUnknown() && cortexFQDN.ValueString() != "")
	if !urlIsConfigured && !fqdnIsConfigured {
		diags.AddError(
			"Invalid Provider Configuration",
			`must define at least one of "fqdn" or "api_url" (preference will be given to "api_url" if both are defined)`,
		)
	}

	if cortexAPIKey.IsNull() || cortexAPIKey.IsUnknown() || cortexAPIKey.ValueString() == "" {
		diags.AddAttributeError(
			path.Root("api_key"),
			"Invalid Provider Configuration",
			"value cannot be null or empty",
		)
	}

	if cortexAPIKeyID.IsNull() || cortexAPIKeyID.IsUnknown() || int(cortexAPIKeyID.ValueInt32()) == 0 {
		diags.AddAttributeError(
			path.Root("api_key_id"),
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
		FQDN                 *string `json:"fqdn"`
		APIURL               *string `json:"api_url"`
		APIKey               *string `json:"api_key"`
		APIKeyID             *int32  `json:"api_key_id"`
		APIKeyType           *string `json:"api_key_type"`
		SkipSSLVerify        *bool   `json:"skip_ssl_verify"`
		SDKLogLevel          *string `json:"sdk_log_level"`
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

	if config.FQDN != nil {
		m.FQDN = types.StringValue(*config.FQDN)
	}
	if config.APIURL != nil {
		m.APIURL = types.StringValue(*config.APIURL)
	}
	if config.APIKey != nil {
		m.APIKey = types.StringValue(*config.APIKey)
	}
	if config.APIKeyID != nil {
		m.APIKeyID = types.Int32Value(*config.APIKeyID)
	}
	if config.APIKeyType != nil {
		m.APIKeyType = types.StringValue(*config.APIKeyType)
	}
	if config.SkipSSLVerify != nil {
		m.SkipSSLVerify = types.BoolValue(*config.SkipSSLVerify)
	}
	if config.SDKLogLevel != nil {
		m.SDKLogLevel = types.StringValue(*config.SDKLogLevel)
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
	if val, ok := MultiEnvGet(FQDNEnvVars); ok {
		if val != m.FQDN.ValueString() {
			tflog.Debug(ctx, fmt.Sprintf("Overwriting fqdn with value from environment variable (%s)", val))
			m.FQDN = types.StringValue(val)
		}
	}
	if val, ok := MultiEnvGet(APIURLEnvVars); ok {
		if val != m.APIURL.ValueString() {
			tflog.Debug(ctx, fmt.Sprintf("Overwriting api_url with value from environment variable (%s)", val))
			m.APIURL = types.StringValue(val)
		}
	}
	if val, ok := MultiEnvGet(APIKeyEnvVars); ok {
		if val != m.APIKey.ValueString() {
			tflog.Debug(ctx, fmt.Sprintf("Overwriting api_key with value from environment variable (%s)", val))
			m.APIKey = types.StringValue(val)
		}
	}
	if val, ok := MultiEnvGet(APIKeyTypeEnvVars); ok {
		if val != m.APIKeyType.ValueString() {
			tflog.Debug(ctx, fmt.Sprintf("Overwriting api_key_type with value from environment variable (%s)", val))
			m.APIKeyType = types.StringValue(val)
		}
	}
	if val, ok := MultiEnvGet(SDKLogLevelEnvVars); ok {
		if val != m.SDKLogLevel.ValueString() {
			tflog.Debug(ctx, fmt.Sprintf("Overwriting sdk_log_level with value from environment variable (%s)", val))
			m.SDKLogLevel = types.StringValue(val)
		}
	}
	if val, ok := MultiEnvGet(CrashStackDirEnvVars); ok {
		if val != m.CrashStackDir.ValueString() {
			tflog.Debug(ctx, fmt.Sprintf("Overwriting crash_stack_dir with value from environment variable (%s)", val))
			m.CrashStackDir = types.StringValue(val)
		}
	}

	// Integer types
	if val, ok := MultiEnvGet(APIKeyIDEnvVars); ok {
		if i, err := strconv.ParseInt(val, 10, 32); err == nil {
			parsedVal := int32(i)
			if m.APIKeyID.IsNull() || parsedVal != m.APIKeyID.ValueInt32() {
				tflog.Debug(ctx, fmt.Sprintf("Overwriting api_key_id with value from environment variable (%d)", parsedVal))
				m.APIKeyID = types.Int32Value(parsedVal)
			}
		} else {
			diagnostics.AddAttributeWarning(path.Root("api_key_id"), "Environment Variable Parsing Error", fmt.Sprintf("Failed to parse value from environment variable \"%s\" to integer\nError: %s", val, err.Error()))
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
	if val, ok := MultiEnvGet(SkipSSLVerifyEnvVars); ok {
		if b, err := strconv.ParseBool(val); err == nil {
			if m.SkipSSLVerify.IsNull() || b != m.SkipSSLVerify.ValueBool() {
				tflog.Debug(ctx, fmt.Sprintf("Overwriting skip_ssl_verify with value from environment variable (%t)", b))
				m.SkipSSLVerify = types.BoolValue(b)
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
