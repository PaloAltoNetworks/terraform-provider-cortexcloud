// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"os"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

const (
	providerName = "cortexcloud"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	providerName: providerserver.NewProtocol6WithError(provider.New("test")()),
}

func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("CORTEX_API_KEY"); v == "" {
		t.Fatal("CORTEX_API_KEY must be set for acceptance tests")
	} else {
		t.Logf(`CORTEX_API_KEY="%s"`, v)
	}

	if v := os.Getenv("CORTEX_API_KEY_ID"); v == "" {
		t.Fatal("CORTEX_API_KEY_ID must be set for acceptance tests")
	} else {
		t.Logf(`CORTEX_API_KEY_ID=%s`, v)
	}

	if v := os.Getenv("CORTEX_API_URL"); v == "" {
		t.Fatal("CORTEX_API_URL must be set for acceptance tests")
	} else {
		t.Logf(`CORTEX_API_URL="%s"`, v)
	}
}
