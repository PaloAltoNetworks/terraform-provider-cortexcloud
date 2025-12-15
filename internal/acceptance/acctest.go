// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/joho/godotenv"
)

var (
	providerName = "cortexcloud"

	dotEnvPath           = filepath.Join("..", "..", ".env.acctest")
	testFQDNEnvVar       = "TEST_CORTEX_FQDN"
	testAPIURLEnvVar     = "TEST_CORTEX_API_URL"
	testAPIKeyEnvVar     = "TEST_CORTEX_API_KEY"
	testAPIKeyIDEnvVar   = "TEST_CORTEX_API_KEY_ID"
	testAPIKeyTypeEnvVar = "TEST_CORTEX_API_KEY_TYPE"

	testFQDN                        string
	testAPIURL                      string
	testAPIKey                      string
	testAPIKeyIDStr                 string
	testAPIKeyID                    int
	testAPIKeyType                  string
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		providerName: providerserver.NewProtocol6WithError(provider.New("test")()),
	}
)

func getProviderConfig(t *testing.T, envFilePath string, enableSDKDebugLogs bool) string {
	err := loadDotEnv(t, envFilePath)
	if err != nil {
		t.Logf("Failed to load env file at \"%s\": %v", envFilePath, err)
	}

	var sdkLogLevelArg string
	if enableSDKDebugLogs {
		sdkLogLevelArg = `sdk_log_level = "debug"`
	} else {
		sdkLogLevelArg = `sdk_log_level = "info"`
	}

	return fmt.Sprintf(`
provider "%s" {
	api_url = "%s"
	api_key = "%s"
	api_key_id = %s
	api_key_type = "%s"
	%s
}
`, providerName, testAPIURL, testAPIKey, testAPIKeyIDStr, testAPIKeyType, sdkLogLevelArg)
}

func loadDotEnv(t *testing.T, envFilePath string) error {
	t.Logf("Loading dot env file at %s", envFilePath)
	err := godotenv.Load(envFilePath)
	if err != nil {
		return fmt.Errorf("Failed to load .env file: %v", err)
	}
	testFQDN = os.Getenv(testFQDNEnvVar)
	testAPIURL = os.Getenv(testAPIURLEnvVar)
	testAPIKey = os.Getenv(testAPIKeyEnvVar)
	testAPIKeyIDStr = os.Getenv(testAPIKeyIDEnvVar)
	testAPIKeyType = os.Getenv(testAPIKeyTypeEnvVar)
	testAPIKeyID, err = strconv.Atoi(testAPIKeyIDStr)
	if err != nil {
		return fmt.Errorf("Error converting API Key ID from string to int: %v", err)
	}
	t.Logf("API URL = %s", testAPIURL)
	t.Logf("API Key = %s", testAPIKey)
	t.Logf("API Key ID = %d", testAPIKeyID)
	return nil
}

func testAccPreCheck(t *testing.T) {
	t.Helper()
	t.Log("Checking provider config env vars")

	configErrs := []string{}
	if testFQDN == "" && testAPIURL == "" {
		configErrs = append(configErrs, fmt.Sprintf("One of %s or %s must be set for acceptance tests", testFQDNEnvVar, testAPIURLEnvVar))
	}

	if testAPIKey == "" {
		configErrs = append(configErrs, fmt.Sprintf("%s must be set for acceptance tests", testAPIKeyEnvVar))
	}

	if testAPIKeyIDStr == "" {
		configErrs = append(configErrs, fmt.Sprintf("%s must be set for acceptance tests", testAPIKeyIDEnvVar))
	}

	var strConvErr error
	testAPIKeyID, strConvErr = strconv.Atoi(testAPIKeyIDStr)
	if strConvErr != nil {
		configErrs = append(configErrs, fmt.Sprintf("Failed to convert %s value \"%s\" to int: %s", testAPIKeyIDEnvVar, testAPIKeyIDStr, strConvErr.Error()))
	}

	if len(configErrs) > 0 {
		t.Fatalf("Pre-check failed:\n\t -%s", strings.Join(configErrs, "\n\t- "))
	}
}
