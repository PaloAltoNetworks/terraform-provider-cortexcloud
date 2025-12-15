// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// Shared test values
const (
	testAPIKeyID             int32 = 999
	testAPIKeyType                 = "advanced"
	testSDKLogLevel                = "debug"
	testSkipSSLVerify              = true
	testRequestTimeout       int32 = 111
	testRequestMaxRetries    int32 = 222
	testRequestMaxRetryDelay int32 = 333
)

// TestProviderBlockConfiguration verifies that the provider is able to be
// fully configured using the values passed in the provider block
func TestProviderBlockConfiguration(t *testing.T) {
	const (
		providerBlockAPIURL        = "https://api-provider.block"
		providerBlockAPIKey        = "key-from-provider-block"
		providerBlockCrashStackDir = "/config/file/crash/stack/dir"
	)

	var (
		ctx   = context.Background()
		diags diag.Diagnostics
		model = CortexCloudProviderModel{
			APIURL:               types.StringValue(providerBlockAPIURL),
			APIKey:               types.StringValue(providerBlockAPIKey),
			APIKeyID:             types.Int32Value(testAPIKeyID),
			APIKeyType:           types.StringValue(testAPIKeyType),
			SDKLogLevel:          types.StringValue(testSDKLogLevel),
			SkipSSLVerify:        types.BoolValue(testSkipSSLVerify),
			RequestTimeout:       types.Int32Value(testRequestTimeout),
			RequestMaxRetries:    types.Int32Value(testRequestMaxRetries),
			RequestMaxRetryDelay: types.Int32Value(testRequestMaxRetryDelay),
			CrashStackDir:        types.StringValue(providerBlockCrashStackDir),
		}
	)

	// Create config file with empty values for string attributes (non-string
	// attributes will raise diagnostic errors if mapped to empty strings) to
	// ensure that these attributes are not overwritten by the ParseConfigFile
	// execution
	var configFileData = map[string]any{
		"api_url":         "",
		"api_key":         "",
		"api_key_type":    "",
		"sdk_log_level":   "",
		"crash_stack_dir": "",
	}

	tempConfigFileDir := t.TempDir()
	configFile := createTempConfigFile(t, tempConfigFileDir, configFileData)
	model.ConfigFile = types.StringValue(configFile)

	// Parse config file
	model.ParseConfigFile(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ParseConfigFile produced diagnostics: %v", diags.Errors())
	}

	// Parse env vars to ensure that none of the provider block values are
	// overwritten
	model.ParseEnvVars(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ParseEnvVars produced diagnostics: %v", diags.Errors())
	}

	assert.Equal(t, providerBlockAPIURL, model.APIURL.ValueString())
	assert.Equal(t, providerBlockAPIKey, model.APIKey.ValueString())
	assert.Equal(t, testAPIKeyID, model.APIKeyID.ValueInt32())
	assert.Equal(t, testAPIKeyType, model.APIKeyType.ValueString())
	assert.Equal(t, testSDKLogLevel, model.SDKLogLevel.ValueString())
	assert.True(t, model.SkipSSLVerify.ValueBool())
	assert.Equal(t, testRequestTimeout, model.RequestTimeout.ValueInt32())
	assert.Equal(t, testRequestMaxRetries, model.RequestMaxRetries.ValueInt32())
	assert.Equal(t, testRequestMaxRetryDelay, model.RequestMaxRetryDelay.ValueInt32())
	assert.Equal(t, providerBlockCrashStackDir, model.CrashStackDir.ValueString())
}

// TestConfigFileConfiguration verifies that the provider is able to be fully
// configured using only the specified JSON file in the `config_file`
// attribute
func TestConfigFileConfiguration(t *testing.T) {
	const (
		configFileAPIURL        = "https://api-config.file"
		configFileAPIKey        = "key-from-config-file"
		configFileCrashStackDir = "/config/file/crash/stack/dir"
	)

	var (
		ctx            = context.Background()
		diags          diag.Diagnostics
		model          = CortexCloudProviderModel{}
		configFileData = map[string]any{
			"api_url":                 configFileAPIURL,
			"api_key":                 configFileAPIKey,
			"api_key_id":              testAPIKeyID,
			"api_key_type":            testAPIKeyType,
			"skip_ssl_verify":         testSkipSSLVerify,
			"sdk_log_level":           testSDKLogLevel,
			"request_timeout":         testRequestTimeout,
			"request_max_retries":     testRequestMaxRetries,
			"request_max_retry_delay": testRequestMaxRetryDelay,
			"crash_stack_dir":         configFileCrashStackDir,
		}
	)

	// Create config file and assign its path to the `config_file` attribute
	tempConfigFileDir := t.TempDir()
	configFile := createTempConfigFile(t, tempConfigFileDir, configFileData)
	model.ConfigFile = types.StringValue(configFile)

	// Parse config file
	model.ParseConfigFile(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ParseConfigFile produced diagnostics: %v", diags.Errors())
	}

	// Parse empty env vars to ensure that none of the config file values are
	// overwritten
	model.ParseEnvVars(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ParseEnvVars produced diagnostics: %v", diags.Errors())
	}

	assert.Equal(t, configFileAPIURL, model.APIURL.ValueString())
	assert.Equal(t, configFileAPIKey, model.APIKey.ValueString())
	assert.Equal(t, testAPIKeyID, model.APIKeyID.ValueInt32())
	assert.Equal(t, testAPIKeyType, model.APIKeyType.ValueString())
	assert.Equal(t, testSDKLogLevel, model.SDKLogLevel.ValueString())
	assert.True(t, model.SkipSSLVerify.ValueBool())
	assert.Equal(t, testRequestTimeout, model.RequestTimeout.ValueInt32())
	assert.Equal(t, testRequestMaxRetries, model.RequestMaxRetries.ValueInt32())
	assert.Equal(t, testRequestMaxRetryDelay, model.RequestMaxRetryDelay.ValueInt32())
	assert.Equal(t, configFileCrashStackDir, model.CrashStackDir.ValueString())
}

// TestEnvVarConfiguration verifies that the provider is able to be fully
// configured using only environment variables
func TestEnvVarConfiguration(t *testing.T) {
	const (
		envVarAPIURL        = "https://api-env.var"
		envVarAPIKey        = "key-from-env-var"
		envVarCrashStackDir = "/env/var/crash/stack/dir"
	)

	t.Setenv(APIURLEnvVar, envVarAPIURL)
	t.Setenv(APIKeyEnvVar, envVarAPIKey)
	t.Setenv(APIKeyIDEnvVar, strconv.Itoa(int(testAPIKeyID)))
	t.Setenv(APIKeyTypeEnvVar, testAPIKeyType)
	t.Setenv(SDKLogLevelEnvVar, testSDKLogLevel)
	t.Setenv(SkipSSLVerifyEnvVar, strconv.FormatBool(testSkipSSLVerify))
	t.Setenv(RequestTimeoutEnvVar, strconv.Itoa(int(testRequestTimeout)))
	t.Setenv(RequestMaxRetriesEnvVar, strconv.Itoa(int(testRequestMaxRetries)))
	t.Setenv(RequestMaxRetryDelayEnvVar, strconv.Itoa(int(testRequestMaxRetryDelay)))
	t.Setenv(CrashStackDirEnvVar, envVarCrashStackDir)

	var (
		ctx   = context.Background()
		diags diag.Diagnostics
		model = CortexCloudProviderModel{}
	)

	model.ParseConfigFile(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ParseConfigFile produced diagnostics: %v", diags.Errors())
	}

	model.ParseEnvVars(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ParseEnvVars produced diagnostics: %v", diags.Errors())
	}

	assert.Equal(t, envVarAPIURL, model.APIURL.ValueString())
	assert.Equal(t, envVarAPIKey, model.APIKey.ValueString())
	assert.Equal(t, testAPIKeyID, model.APIKeyID.ValueInt32())
	assert.Equal(t, testAPIKeyType, model.APIKeyType.ValueString())
	assert.Equal(t, testSDKLogLevel, model.SDKLogLevel.ValueString())
	assert.True(t, model.SkipSSLVerify.ValueBool())
	assert.Equal(t, testRequestTimeout, model.RequestTimeout.ValueInt32())
	assert.Equal(t, testRequestMaxRetries, model.RequestMaxRetries.ValueInt32())
	assert.Equal(t, testRequestMaxRetryDelay, model.RequestMaxRetryDelay.ValueInt32())
	assert.Equal(t, envVarCrashStackDir, model.CrashStackDir.ValueString())
}

// TestConfigurationPrecedence verifies that configuration values are applied in the
// correct order of precedence: Environment Variables > Config File > Provider Block
func TestConfigurationPrecedence(t *testing.T) {
	// Expected final values
	const (
		providerBlockAPIURL         = "https://api-provider.block"
		providerBlockAPIKey         = "key-from-provider-block"
		providerBlockAPIKeyID int32 = 123
		configFileAPIURL            = "https://api-provider.block"
		configFileAPIKey            = "key-from-config-file"
		configFileAPIKeyType        = "standard"
		envVarAPIURL                = "https://api-env.var"
		envVarAPIKeyID        int32 = 999
		envVarAPIKeyType            = "advanced"
		expectedAPIURL              = envVarAPIURL     // Provider Block -> Config File -> Env Var
		expectedAPIKey              = configFileAPIKey // Provider Block -> Config File
		expectedAPIKeyID            = envVarAPIKeyID   // Provider Block -> Env Var
		expectedAPIKeyType          = envVarAPIKeyType // Config File -> EnvVar
	)

	// Provider Block (lowest precedence)
	providerBlockValues := CortexCloudProviderModel{
		APIURL:   types.StringValue(providerBlockAPIURL),
		APIKey:   types.StringValue(providerBlockAPIKey),
		APIKeyID: types.Int32Value(providerBlockAPIKeyID),
	}

	// Config File (middle precedence)
	configFileValues := map[string]any{
		"api_url":      configFileAPIURL,
		"api_key":      configFileAPIKey,
		"api_key_type": configFileAPIKeyType,
	}
	tempConfigFileDir := t.TempDir()
	configFile := createTempConfigFile(t, tempConfigFileDir, configFileValues)

	// Environment Variables (highest precedence)
	t.Setenv(APIURLEnvVar, envVarAPIURL)
	t.Setenv(APIKeyIDEnvVar, strconv.Itoa(int(envVarAPIKeyID)))
	t.Setenv(APIKeyTypeEnvVar, envVarAPIKeyType)

	ctx := context.Background()
	var diags diag.Diagnostics

	// Apply provider block values
	model := providerBlockValues

	// Populate config_file attribute with temp config file path
	model.ConfigFile = types.StringValue(configFile)

	// Execute parsing functions in the same order as Configure function
	model.ParseConfigFile(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ParseConfigFile produced diagnostics: %v", diags.Errors())
	}

	assert.Equal(t, configFileAPIURL, model.APIURL.ValueString())
	assert.Equal(t, configFileAPIKey, model.APIKey.ValueString())
	assert.Equal(t, providerBlockAPIKeyID, model.APIKeyID.ValueInt32())
	assert.Equal(t, configFileAPIKeyType, model.APIKeyType.ValueString())

	model.ParseEnvVars(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ParseEnvVars produced diagnostics: %v", diags.Errors())
	}

	assert.Equal(t, expectedAPIURL, model.APIURL.ValueString())
	assert.Equal(t, expectedAPIKey, model.APIKey.ValueString())
	assert.Equal(t, expectedAPIKeyID, model.APIKeyID.ValueInt32())
	assert.Equal(t, expectedAPIKeyType, model.APIKeyType.ValueString())
}

// createTempConfigFile is a helper function to create a temporary JSON
// configuration file
func createTempConfigFile(t *testing.T, filepath string, content map[string]any) string {
	t.Helper()

	t.Logf("Creating temporary config file: %s", filepath)

	data, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("Failed to marshal config data: %v", err)
	}

	file, err := os.CreateTemp(filepath, "test-config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		t.Fatalf("Failed to write to temp config file: %v", err)
	}

	return file.Name()
}
