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
	// Provider Block (lowest precedence)
	providerBlockValues := CortexCloudProviderModel{
		FQDN:             types.StringValue("provider.block"),
		APIURL:           types.StringValue("https://api-provider.block"),
		APIKey:           types.StringValue("key-from-provider-block"),
		APIKeyID:         types.Int32Value(123),
		APIKeyType:       types.StringValue("standard"),
		CheckEnvironment: types.BoolValue(true), // Must be true to enable env var parsing
	}

	// Config File (middle precedence)
	configFileValues := map[string]any{
		"fqdn":     "config.file",
		"api_url":  "https://api-config.file",
		"api_port": 222,
		"api_key":  "key-from-config-file",
		// APIKeyID and APIKeyType are omitted here to test fallback to provider block value.
	}
	configFile := createTempConfigFile(t, configFileValues)

	// Environment Variables (highest precedence)
	t.Setenv(APIURLEnvVars[0], "https://api-env.var")
	t.Setenv(APIURLEnvVars[1], "should-be-skipped")
	t.Setenv(APIURLEnvVars[2], "should-be-skipped")
	t.Setenv(APIKeyIDEnvVars[0], "999")
	t.Setenv(APIKeyIDEnvVars[1], "should-be-skipped")
	t.Setenv(APIKeyIDEnvVars[2], "should-be-skipped")
	// APIPort and APIKey are omitted here to test fallback to lower precedence values.

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

	if model.FQDN.ValueString() == "provider.block" {
		t.Errorf("FQDN precedence incorrect: got %s, want %s", model.FQDN.ValueString(), "config.file")
	}

	expectedApiKeyType := "standard"
	if model.APIKeyType.ValueString() != expectedApiKeyType {
		t.Errorf("ApiKeyType precedence incorrect: got %s, want %s", model.APIKeyType.ValueString(), expectedApiKeyType)
	}

	model.ParseEnvVars(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ParseEnvVars produced diagnostics")
	}

	// 3. Assertions
	// Check that the final values respect the precedence rules.

	// Expected: Env Var > Config File > Provider Block
	// ApiUrl: Env Var should win.
	expectedApiUrl := "https://api-env.var"
	if model.APIURL.ValueString() != expectedApiUrl {
		t.Errorf("ApiUrl precedence incorrect: got %s, want %s", model.FQDN.ValueString(), expectedApiUrl)
	}

	// Expected: Config File > Provider Block (no Env Var set)
	// ApiKey: Config File should win.
	expectedApiKey := "key-from-config-file"
	if model.APIKey.ValueString() != expectedApiKey {
		t.Errorf("ApiKey precedence incorrect: got %s, want %s", model.APIKey.ValueString(), expectedApiKey)
	}

	// Expected: Env Var > Provider Block (no Config File value set)
	// ApiKeyId: Env Var should win.
	expectedApiKeyId := int32(999)
	if model.APIKeyID.ValueInt32() != expectedApiKeyId {
		t.Errorf("ApiKeyId precedence incorrect: got %d, want %d", model.APIKeyID.ValueInt32(), expectedApiKeyId)
	}
}

//// TestParseEnvVars_Disabled verifies that environment variables are ignored when
//// the check_environment attribute is set to false.
//func TestParseEnvVars_Disabled(t *testing.T) {
//	// 1. Setup
//	providerBlockValues := CortexCloudProviderModel{
//		FQDN:     types.StringValue("http://provider.block"),
//		CheckEnvironment: types.BoolValue(false), // Explicitly disable env var parsing
//	}
//
//	// Set an env var that should be ignored.
//	t.Setenv(FQDNEnvVars[0], "http://should.be.ignored")
//
//	// 2. Execution
//	ctx := context.Background()
//	var diags diag.Diagnostics
//	model := providerBlockValues
//	model.ParseEnvVars(ctx, &diags)
//
//	// 3. Assertion
//	expectedApiUrl := "http://provider.block"
//	if model.FQDN.ValueString() != expectedApiUrl {
//		t.Errorf("ApiUrl should not have been updated from env var, got %s, want %s", model.FQDN.ValueString(), expectedApiUrl)
//	}
//}
