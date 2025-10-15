// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"fmt"
	"testing"
	"os"
	"strconv"
	
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

var (
	providerName       = "cortexcloud"

	testFQDNEnvVar   = "TEST_CORTEX_FQDN"
	testAPIURLEnvVar   = "TEST_CORTEX_API_URL"
	testAPIKeyEnvVar   = "TEST_CORTEX_API_KEY"
	testAPIKeyIDEnvVar = "TEST_CORTEX_API_KEY_ID"
	testAPIKeyTypeEnvVar = "TEST_CORTEX_API_KEY_TYPE"

	testFQDN                string = os.Getenv(testFQDNEnvVar)
	testAPIURL                string = os.Getenv(testAPIURLEnvVar)
	testAPIKey 			string = os.Getenv(testAPIKeyEnvVar)
	testAPIKeyIDStr 		string = os.Getenv(testAPIKeyIDEnvVar)
	testAPIKeyID 		int
	testAPIKeyType 			string = os.Getenv(testAPIKeyTypeEnvVar)
	testAccProtoV6ProviderFactories        = map[string]func() (tfprotov6.ProviderServer, error){
		providerName: providerserver.NewProtocol6WithError(provider.New("test")()),
	}
)

func getProviderConfig(t *testing.T, enableSDKDebugLogs bool) string {
	t.Logf("Creating provider config for %s", t.Name())

	var sdkLogLevelArg string
	if enableSDKDebugLogs {
		sdkLogLevelArg= `sdk_log_level = "debug"`
	} else {
		sdkLogLevelArg= `sdk_log_level = "info"`
	}

	return fmt.Sprintf(`
provider "%s" {
	fqdn = "%s"
	api_url = "%s"
	api_key = "%s"
	api_key_id = %s
	api_key_type = "%s"
	%s
}
`, providerName, testFQDN, testAPIURL, testAPIKey, testAPIKeyIDStr, testAPIKeyType, sdkLogLevelArg)
}

func testAccPreCheck(t *testing.T) {
	t.Helper()

	t.Log("Running pre-check")

	// TODO: collect errors and run Fatal at the end if >0
	if testFQDN == "" && testAPIURL == "" {
		t.Fatalf("One of %s or %s must be set for acceptance tests", testFQDNEnvVar, testAPIURLEnvVar)
	}

	if testAPIKey == "" {
		t.Fatalf("%s must be set for acceptance tests", testAPIKeyEnvVar)
	}

	if testAPIKeyIDStr == "" {
		t.Fatalf("%s must be set for acceptance tests", testAPIKeyIDEnvVar)
	}

	var strConvErr error
	testAPIKeyID, strConvErr = strconv.Atoi(testAPIKeyIDStr)
	if strConvErr != nil {
		t.Fatalf("Failed to convert %s value \"%s\" to int: %s", testAPIKeyIDEnvVar, testAPIKeyIDStr, strConvErr.Error())
	}

	t.Log("Pre-check complete")
}
