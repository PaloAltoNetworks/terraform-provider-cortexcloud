// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/log"
	"github.com/stretchr/testify/require"
)

const (
	TestAPIKey   = "test-key"
	TestAPIKeyID = 123
)

func setupTest(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	t.Logf("running setupTest for %s", t.Name())
	server := httptest.NewServer(handler)
	client, err := NewClient(
		WithCortexAPIURL(server.URL),
		WithCortexAPIKey(TestAPIKey),
		WithCortexAPIKeyID(TestAPIKeyID),
		WithCortexAPIKeyType("standard"),
		WithTransport(server.Client().Transport.(*http.Transport)),
		WithLogger(log.TflogAdapter{}),
	)
	require.NoError(t, err)
	require.NotNil(t, client)
	return client, server
}

// skipIfNotAcceptance skips the test if not running acceptance tests.
func skipIfNotAcceptance(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Skipping acceptance test (TF_ACC not set)")
	}
}
