// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"net/http"
	"net/http/httptest"
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
		WithTransport(server.Client().Transport.(*http.Transport)),
		WithLogger(log.TflogAdapter{}),
	)
	require.NoError(t, err)
	require.NotNil(t, client)
	return client, server
}
