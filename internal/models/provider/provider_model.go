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

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	APIURLEnvVar               = "CORTEXCLOUD_API_URL"
	APIKeyEnvVar               = "CORTEXCLOUD_API_KEY"
	APIKeyIDEnvVar             = "CORTEXCLOUD_API_KEY_ID"
	APIKeyTypeEnvVar           = "CORTEXCLOUD_API_KEY_TYPE"
	SDKLogLevelEnvVar          = "CORTEXCLOUD_SDK_LOG_LEVEL"
	SkipSSLVerifyEnvVar        = "CORTEXCLOUD_SKIP_SSL_VERIFY"
	RequestTimeoutEnvVar       = "CORTEXCLOUD_REQUEST_TIMEOUT"
	RequestMaxRetriesEnvVar    = "CORTEXCLOUD_REQUEST_MAX_RETRIES"
	RequestMaxRetryDelayEnvVar = "CORTEXCLOUD_REQUEST_MAX_RETRY_DELAY"
	CrashStackDirEnvVar        = "CORTEXCLOUD_CRASH_STACK_DIR"
)

type CortexCloudProviderModel struct {
	APIURL               types.String `tfsdk:"api_url"`
	APIKey               types.String `tfsdk:"api_key"`
	APIKeyID             types.Int32  `tfsdk:"api_key_id"`
	APIKeyType           types.String `tfsdk:"api_key_type"`
	ConfigFile           types.String `tfsdk:"config_file"`
	SkipSSLVerify        types.Bool   `tfsdk:"skip_ssl_verify"`
	SDKLogLevel          types.String `tfsdk:"sdk_log_level"`
	RequestTimeout       types.Int32  `tfsdk:"request_timeout"`
	RequestMaxRetries    types.Int32  `tfsdk:"request_max_retries"`
	RequestMaxRetryDelay types.Int32  `tfsdk:"request_max_retry_delay"`
	CrashStackDir        types.String `tfsdk:"crash_stack_dir"`
}

type CortexCloudSDKClients struct {
	CloudOnboarding *cloudonboarding.Client
	Platform        *platform.Client
}

// ParseConfigFile reads the JSON file at the filepath specified in the
// provider block's `config_file` argument and overwrites the provider
// configuration values with their respective non-nil config file values.
func (m *CortexCloudProviderModel) ParseConfigFile(ctx context.Context, diagnostics *diag.Diagnostics) {
	if m.ConfigFile.IsNull() {
		tflog.Debug(ctx, "No config file specified -- Skipping parsing.")
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
		APIURL               *string `json:"api_url"`
		APIKey               *string `json:"api_key"`
		APIKeyID             *int32  `json:"api_key_id"`
		APIKeyType           *string `json:"api_key_type"`
		SkipSSLVerify        *bool   `json:"skip_ssl_verify"`
		SDKLogLevel          *string `json:"sdk_log_level"`
		RequestTimeout       *int32  `json:"request_timeout"`
		RequestMaxRetries    *int32  `json:"request_max_retries"`
		RequestMaxRetryDelay *int32  `json:"request_max_retry_delay"`
		CrashStackDir        *string `json:"crash_stack_dir"`
	}{}

	if err := json.Unmarshal(data, &config); err != nil {
		diagnostics.AddAttributeError(
			path.Root("config_file"),
			"Provider Configuration Error",
			fmt.Sprintf("Error occured unmarshalling config file: %s", err.Error()),
		)
		return
	}

	tflog.Debug(ctx, "Config file successfully parsed")

	if config.APIURL != nil && *config.APIURL != "" {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting api_url from config file: "%s" => "%s"`, m.APIURL.ValueString(), *config.APIURL))
		m.APIURL = types.StringValue(*config.APIURL)
	}
	if config.APIKey != nil && *config.APIKey != "" {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting api_key from config file: "%s" => "%s"`, m.APIKey.ValueString(), *config.APIKey))
		m.APIKey = types.StringValue(*config.APIKey)
	}
	if config.APIKeyID != nil {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting api_key_id from config file: "%d" => "%d"`, m.APIKeyID.ValueInt32(), *config.APIKeyID))
		m.APIKeyID = types.Int32Value(*config.APIKeyID)
	}
	if config.APIKeyType != nil && *config.APIKeyType != "" {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting api_key_type from config file: "%s" => "%s"`, m.APIKeyType.ValueString(), *config.APIKeyType))
		m.APIKeyType = types.StringValue(*config.APIKeyType)
	}
	if config.SkipSSLVerify != nil {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting skip_ssl_verify from config file: "%t" => "%t"`, m.SkipSSLVerify.ValueBool(), *config.SkipSSLVerify))
		m.SkipSSLVerify = types.BoolValue(*config.SkipSSLVerify)
	}
	if config.SDKLogLevel != nil && *config.SDKLogLevel != "" {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting sdk_log_level from config file: "%s" => "%s"`, m.SDKLogLevel.ValueString(), *config.SDKLogLevel))
		m.SDKLogLevel = types.StringValue(*config.SDKLogLevel)
	}
	if config.RequestTimeout != nil {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting request_timeout from config file: "%d" => "%d"`, m.RequestTimeout.ValueInt32(), *config.RequestTimeout))
		m.RequestTimeout = types.Int32Value(*config.RequestTimeout)
	}
	if config.RequestMaxRetries != nil {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting request_max_retries from config file: "%d" => "%d"`, m.RequestMaxRetries.ValueInt32(), *config.RequestMaxRetries))
		m.RequestMaxRetries = types.Int32Value(*config.RequestMaxRetries)
	}
	if config.RequestMaxRetryDelay != nil {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting request_max_retry_delay from config file: "%d" => "%d"`, m.RequestMaxRetryDelay.ValueInt32(), *config.RequestMaxRetryDelay))
		m.RequestMaxRetryDelay = types.Int32Value(*config.RequestMaxRetryDelay)
	}
	if config.CrashStackDir != nil && *config.CrashStackDir != "" {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting crash_stack_dir from config file: "%s" => "%s"`, m.CrashStackDir.ValueString(), *config.CrashStackDir))
		m.CrashStackDir = types.StringValue(*config.CrashStackDir)
	}
}

func (m *CortexCloudProviderModel) ParseEnvVars(ctx context.Context, diagnostics *diag.Diagnostics) {
	tflog.Debug(ctx, "Parsing environment variables")

	if envAPIURL, ok := os.LookupEnv(APIURLEnvVar); ok && envAPIURL != "" {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting api_url from %s: "%s" => "%s"`, APIURLEnvVar, m.APIURL.ValueString(), envAPIURL))
		m.APIURL = types.StringValue(envAPIURL)
	}
	if envAPIKey, ok := os.LookupEnv(APIKeyEnvVar); ok && envAPIKey != "" {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting api_key from %s: "%s" => "%s"`, APIKeyEnvVar, m.APIKey.ValueString(), envAPIKey))
		m.APIKey = types.StringValue(envAPIKey)
	}
	if envAPIKeyID, ok := os.LookupEnv(APIKeyIDEnvVar); ok && envAPIKeyID != "" {
		if val, err := strconv.ParseInt(envAPIKeyID, 10, 32); err == nil {
			tflog.Debug(ctx, fmt.Sprintf(`Overwriting api_key_id from %s: "%d" => "%d"`, APIKeyIDEnvVar, m.APIKeyID.ValueInt32(), val))
			m.APIKeyID = types.Int32Value(int32(val))
		} else {
			diagnostics.AddError(
				"Environment Variable Parse Error",
				fmt.Sprintf("Failed to parse %s as int32: %s", APIKeyIDEnvVar, err.Error()),
			)
		}
	}
	if envAPIKeyType, ok := os.LookupEnv(APIKeyTypeEnvVar); ok && envAPIKeyType != "" {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting api_key_type from %s: "%s" => "%s"`, APIKeyTypeEnvVar, m.APIKeyType.ValueString(), envAPIKeyType))
		m.APIKeyType = types.StringValue(envAPIKeyType)
	}
	if envSkipSSLVerify, ok := os.LookupEnv(SkipSSLVerifyEnvVar); ok && envSkipSSLVerify != "" {
		if val, err := strconv.ParseBool(envSkipSSLVerify); err == nil {
			tflog.Debug(ctx, fmt.Sprintf(`Overwriting skip_ssl_verify from %s: "%t" => "%t"`, SkipSSLVerifyEnvVar, m.SkipSSLVerify.ValueBool(), val))
			m.SkipSSLVerify = types.BoolValue(val)
		} else {
			diagnostics.AddError(
				"Environment Variable Parse Error",
				fmt.Sprintf("Failed to parse %s as bool: %s", SkipSSLVerifyEnvVar, err.Error()),
			)
		}
	}
	if envSDKLogLevel, ok := os.LookupEnv(SDKLogLevelEnvVar); ok && envSDKLogLevel != "" {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting sdk_log_level from %s: "%s" => "%s"`, SDKLogLevelEnvVar, m.SDKLogLevel.ValueString(), envSDKLogLevel))
		m.SDKLogLevel = types.StringValue(envSDKLogLevel)
	}
	if envRequestTimeout, ok := os.LookupEnv(RequestTimeoutEnvVar); ok && envRequestTimeout != "" {
		if val, err := strconv.ParseInt(envRequestTimeout, 10, 32); err == nil {
			tflog.Debug(ctx, fmt.Sprintf(`Overwriting request_timeout from %s: "%d" => "%d"`, RequestTimeoutEnvVar, m.RequestTimeout.ValueInt32(), val))
			m.RequestTimeout = types.Int32Value(int32(val))
		} else {
			diagnostics.AddError(
				"Environment Variable Parse Error",
				fmt.Sprintf("Failed to parse %s as int32: %s", RequestTimeoutEnvVar, err.Error()),
			)
		}
	}
	if envRequestMaxRetries, ok := os.LookupEnv(RequestMaxRetriesEnvVar); ok && envRequestMaxRetries != "" {
		if val, err := strconv.ParseInt(envRequestMaxRetries, 10, 32); err == nil {
			tflog.Debug(ctx, fmt.Sprintf(`Overwriting request_max_retries from %s: "%d" => "%d"`, RequestMaxRetriesEnvVar, m.RequestMaxRetries.ValueInt32(), val))
			m.RequestMaxRetries = types.Int32Value(int32(val))
		} else {
			diagnostics.AddError(
				"Environment Variable Parse Error",
				fmt.Sprintf("Failed to parse %s as int32: %s", RequestMaxRetriesEnvVar, err.Error()),
			)
		}
	}
	if envRequestMaxRetryDelay, ok := os.LookupEnv(RequestMaxRetryDelayEnvVar); ok && envRequestMaxRetryDelay != "" {
		if val, err := strconv.ParseInt(envRequestMaxRetryDelay, 10, 32); err == nil {
			tflog.Debug(ctx, fmt.Sprintf(`Overwriting request_max_retry_delay from %s: "%d" => "%d"`, RequestMaxRetryDelayEnvVar, m.RequestMaxRetryDelay.ValueInt32(), val))
			m.RequestMaxRetryDelay = types.Int32Value(int32(val))
		} else {
			diagnostics.AddError(
				"Environment Variable Parse Error",
				fmt.Sprintf("Failed to parse %s as int32: %s", RequestMaxRetryDelayEnvVar, err.Error()),
			)
		}
	}
	if envCrashStackDir, ok := os.LookupEnv(CrashStackDirEnvVar); ok && envCrashStackDir != "" {
		tflog.Debug(ctx, fmt.Sprintf(`Overwriting crash_stack_dir from %s: "%s" => "%s"`, CrashStackDirEnvVar, m.CrashStackDir.ValueString(), envCrashStackDir))
		m.CrashStackDir = types.StringValue(envCrashStackDir)
	}
}

func (m *CortexCloudProviderModel) Validate(ctx context.Context, diags *diag.Diagnostics) {
	tflog.Debug(ctx, "Validating provider configuration")

	if m.APIURL.IsNull() || m.APIURL.IsUnknown() || m.APIURL.ValueString() == "" {
		util.AddMissingRequiredProviderConfigurationValue(diags, "api_url", "Cortex Cloud API URL", APIURLEnvVar)
	}
	if m.APIKey.IsNull() || m.APIKey.IsUnknown() || m.APIKey.ValueString() == "" {
		util.AddMissingRequiredProviderConfigurationValue(diags, "api_key", "Cortex Cloud API Key", APIKeyEnvVar)
	}
	if m.APIKeyID.IsNull() || m.APIKeyID.IsUnknown() || m.APIKeyID.ValueInt32() == 0 {
		util.AddMissingRequiredProviderConfigurationValue(diags, "api_key_id", "Cortex Cloud API Key ID", APIKeyIDEnvVar)
	}
}
