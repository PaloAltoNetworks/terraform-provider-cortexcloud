package tests

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/joho/godotenv"
)

const (
	providerBlockTmpl = `provider "cortexcloud" {
	api_url = "%s"
	api_key = "%s"
	api_key_id = %s
	api_key_type = "%s"
	%s
}`
)

var (
	testAPIURLEnvVar     = "TEST_CORTEX_API_URL"
	testAPIKeyEnvVar     = "TEST_CORTEX_API_KEY"
	testAPIKeyIDEnvVar   = "TEST_CORTEX_API_KEY_ID"
	testAPIKeyTypeEnvVar = "TEST_CORTEX_API_KEY_TYPE"

	testAPIURL                      string
	testAPIKey                      string
	testAPIKeyIDStr                 string
	testAPIKeyID                    int
	testAPIKeyType                  string
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test")()),
	}
)

func GetProviderConfig(t *testing.T, serverURL *string, envFilePath string, enableSDKDebugLogs bool) string {
	err := SetEnvironmentVariables(t, serverURL, envFilePath)
	if err != nil {
		t.Logf("Failed to set environment variables from file \"%s\": %v", envFilePath, err)
	}

	var testSDKLogLevel string
	if enableSDKDebugLogs {
		testSDKLogLevel = `sdk_log_level = "debug"`
	} else {
		testSDKLogLevel = `sdk_log_level = "info"`
	}

	return fmt.Sprintf(providerBlockTmpl, testAPIURL, testAPIKey, testAPIKeyIDStr, testAPIKeyType, testSDKLogLevel)
}

func SetEnvironmentVariables(t *testing.T, serverURL *string, envFilePath string) error {
	t.Logf("Loading env file at %s", envFilePath)
	err := godotenv.Load(envFilePath)
	if err != nil {
		return fmt.Errorf("Failed to load .env file: %v", err)
	}

	if serverURL == nil {
		testAPIURL = os.Getenv(testAPIURLEnvVar)
	} else {
		testAPIURL = *serverURL
	}
	testAPIKey = os.Getenv(testAPIKeyEnvVar)
	testAPIKeyIDStr = os.Getenv(testAPIKeyIDEnvVar)
	testAPIKeyType = os.Getenv(testAPIKeyTypeEnvVar)
	testAPIKeyID, err = strconv.Atoi(testAPIKeyIDStr)
	if err != nil {
		return fmt.Errorf("Error converting API Key ID from string to int: %v", err)
	}

	t.Log("Environment variables set")
	t.Logf("API URL: \"%s\"", testAPIURL)
	t.Logf("API Key: \"%s\"", testAPIKey)
	t.Logf("API Key ID: %d", testAPIKeyID)
	t.Logf("API Key Type: \"%s\"", testAPIKeyType)

	return nil
}
