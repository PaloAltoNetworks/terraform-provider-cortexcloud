// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package tests

import (
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/config"

	//"net/http"
	//"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

const (
	testAPIURLEnvVar     string = "CORTEXCLOUD_API_URL_TEST"
	testAPIKeyEnvVar     string = "CORTEXCLOUD_API_KEY_TEST"
	testAPIKeyIDEnvVar   string = "CORTEXCLOUD_API_KEY_ID_TEST"
	testAPIKeyTypeEnvVar string = "CORTEXCLOUD_API_KEY_TYPE_TEST"
)

func NewTestConfigFromEnv(t *testing.T) *config.Config {
	t.Helper()

	t.Log("Fetching client configuration values from environment variables")

	apiUrl := os.Getenv(testAPIURLEnvVar)
	apiKey := os.Getenv(testAPIKeyEnvVar)
	apiKeyIDStr := os.Getenv(testAPIKeyIDEnvVar)
	apiKeyType := os.Getenv(testAPIKeyTypeEnvVar)

	apiKeyID, err := strconv.Atoi(apiKeyIDStr)
	if err != nil {
		t.Fatalf("failed to convert API key ID \"%s\" to int: %s", apiKeyIDStr, err.Error())
		return nil
	}

	if apiKeyType == "" {
		t.Log("No API key type specified, defaulting to standard")
		apiKeyType = "standard"
	}

	return config.NewConfig(
		config.WithCortexAPIURL(apiUrl),
		config.WithCortexAPIKey(apiKey),
		config.WithCortexAPIKeyID(apiKeyID),
		config.WithCortexAPIKeyType(apiKeyType),
		config.WithLogLevel("debug"),
	)
}
