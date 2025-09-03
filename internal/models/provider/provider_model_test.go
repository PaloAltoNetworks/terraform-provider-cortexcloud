// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// createTempConfigFile is a helper function to create a temporary JSON configuration
// file for testing purposes.
func createTempConfigFile(t *testing.T, content map[string]any) string {
	t.Helper()

	data, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("Failed to marshal config data: %v", err)
	}

	file, err := os.CreateTemp(t.TempDir(), "test-config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		t.Fatalf("Failed to write to temp config file: %v", err)
	}

	return file.Name()
}

// TestConfigurationPrecedence verifies that configuration values are applied in the
// correct order of precedence: Environment Variables > Config File > Provider Block.
func TestConfigurationPrecedence(t *testing.T) {
	// 1. Setup: Define values for each level of configuration.
	// Precedence: Env Var > Config File > Provider Block

	// Provider Block (lowest precedence)
	providerBlockValues := CortexCloudProviderModel{
		ApiUrl:           types.StringValue("http://provider.block"),
		ApiPort:          types.Int32Value(111),
		ApiKey:           types.StringValue("key-from-provider-block"),
		ApiKeyId:         types.Int32Value(123),
		CheckEnvironment: types.BoolValue(true), // Must be true to enable env var parsing
	}

	// Config File (middle precedence)
	configFileValues := map[string]any{
		"cortex_cloud_api_url":  "http://config.file",
		"cortex_cloud_api_port": 222,
		"cortex_cloud_api_key":  "key-from-config-file",
		// ApiKeyId is omitted here to test fallback to provider block value.
	}
	configFile := createTempConfigFile(t, configFileValues)

	// Environment Variables (highest precedence)
	t.Setenv(ApiUrlEnvVars[0], "http://env.var")
	t.Setenv(ApiUrlEnvVars[1], "should-be-skipped")
	t.Setenv(ApiUrlEnvVars[2], "should-be-skipped")
	t.Setenv(ApiKeyIdEnvVars[0], "999")
	t.Setenv(ApiKeyIdEnvVars[1], "should-be-skipped")
	t.Setenv(ApiKeyIdEnvVars[2], "should-be-skipped")
	// ApiPort and ApiKey are omitted here to test fallback to lower precedence values.

	// 2. Execution
	ctx := context.Background()
	var diags diag.Diagnostics

	// Start with provider block values.
	model := providerBlockValues
	model.ConfigFile = types.StringValue(configFile)

	// Run the parsing functions in the same order as the provider's Configure method.
	model.ParseConfigFile(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ParseConfigFile produced diagnostics")
	}

	if model.ApiUrl.ValueString() == "http://provider.block" {
		t.Errorf("ApiUrl precedence incorrect: got %s, want %s", model.ApiUrl.ValueString(), "http://config.file")
	}

	model.ParseEnvVars(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ParseEnvVars produced diagnostics")
	}

	// 3. Assertions
	// Check that the final values respect the precedence rules.

	// Expected: Env Var > Config File > Provider Block
	// ApiUrl: Env Var should win.
	expectedApiUrl := "http://env.var"
	if model.ApiUrl.ValueString() != expectedApiUrl {
		t.Errorf("ApiUrl precedence incorrect: got %s, want %s", model.ApiUrl.ValueString(), expectedApiUrl)
	}

	// Expected: Config File > Provider Block (no Env Var set)
	// ApiPort: Config File should win.
	expectedApiPort := int32(222)
	if model.ApiPort.ValueInt32() != expectedApiPort {
		t.Errorf("ApiPort precedence incorrect: got %d, want %d", model.ApiPort.ValueInt32(), expectedApiPort)
	}

	// Expected: Config File > Provider Block (no Env Var set)
	// ApiKey: Config File should win.
	expectedApiKey := "key-from-config-file"
	if model.ApiKey.ValueString() != expectedApiKey {
		t.Errorf("ApiKey precedence incorrect: got %s, want %s", model.ApiKey.ValueString(), expectedApiKey)
	}

	// Expected: Env Var > Provider Block (no Config File value set)
	// ApiKeyId: Env Var should win.
	expectedApiKeyId := int32(999)
	if model.ApiKeyId.ValueInt32() != expectedApiKeyId {
		t.Errorf("ApiKeyId precedence incorrect: got %d, want %d", model.ApiKeyId.ValueInt32(), expectedApiKeyId)
	}
}

// TestParseEnvVars_Disabled verifies that environment variables are ignored when
// the check_environment attribute is set to false.
func TestParseEnvVars_Disabled(t *testing.T) {
	// 1. Setup
	providerBlockValues := CortexCloudProviderModel{
		ApiUrl:           types.StringValue("http://provider.block"),
		CheckEnvironment: types.BoolValue(false), // Explicitly disable env var parsing
	}

	// Set an env var that should be ignored.
	t.Setenv(ApiUrlEnvVars[0], "http://should.be.ignored")

	// 2. Execution
	ctx := context.Background()
	var diags diag.Diagnostics
	model := providerBlockValues
	model.ParseEnvVars(ctx, &diags)

	// 3. Assertion
	expectedApiUrl := "http://provider.block"
	if model.ApiUrl.ValueString() != expectedApiUrl {
		t.Errorf("ApiUrl should not have been updated from env var, got %s, want %s", model.ApiUrl.ValueString(), expectedApiUrl)
	}
}
