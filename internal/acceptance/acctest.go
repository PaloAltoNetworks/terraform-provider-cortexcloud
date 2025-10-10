// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"os"
	"strconv"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

const (
	providerName = "cortexcloud"
)

var (
	apiURL string
	apiKey string
	apiKeyID int
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		providerName: providerserver.NewProtocol6WithError(provider.New("test")()),
	}
)

func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("CORTEX_API_KEY_TEST"); v == "" {
		t.Fatal("CORTEX_API_KEY_TEST must be set for acceptance tests")
	} else {
		t.Logf(`CORTEX_API_KEY_TEST="%s"`, v)
		apiKey = v
	}

	if v := os.Getenv("CORTEX_API_KEY_ID_TEST"); v == "" {
		t.Fatal("CORTEX_API_KEY_ID_TEST must be set for acceptance tests")
	} else {
		t.Logf(`CORTEX_API_KEY_ID_TEST=%s`, v)
		i, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("Failed to convert CORTEX_API_KEY_ID_TEST value \"%s\" to int: %s", v, err.Error())
		}
		apiKeyID = i
	}

	if v := os.Getenv("CORTEX_API_URL_TEST"); v == "" {
		t.Fatal("CORTEX_API_URL_TEST must be set for acceptance tests")
	} else {
		t.Logf(`CORTEX_API_URL_TEST="%s"`, v)
		apiURL = v
	}
}
