// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/log"
	"github.com/stretchr/testify/assert"
)

func setupTest(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Logf("[%s] Test server URL %s", t.Name(), server.URL)

	client, err := NewClient(
		WithCortexAPIURL(server.URL),
		WithCortexAPIKey("test-key"),
		WithCortexAPIKeyID(123),
		WithCortexAPIKeyType("standard"),
		WithTransport(server.Client().Transport.(*http.Transport)),
		WithLogger(log.TflogAdapter{}),
	)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	return client, server
}
