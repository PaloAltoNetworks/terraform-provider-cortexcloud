// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	//"fmt"
	"net/http"
	"net/http/httptest"
	//"net/url"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/log"
	"github.com/stretchr/testify/assert"
)

//func testServerURLtoCortexAPI(serverURL string) (string, error) {
//	parsedURL, err := url.Parse(serverURL)
//	if err != nil {
//		return "", err
//	}
//
//	return fmt.Sprintf("https://api-%s", parsedURL.Hostname()), nil
//}

func setupTest(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(handler)
	//cortexAPIURL, err := testServerURLtoCortexAPI(server.URL)
	//if err != nil {
	//	t.Fatalf("failed to convert test server URL: %s", err.Error())
	//}
	//server.URL = cortexAPIURL

	t.Logf("[%s] Test server URL %s", t.Name(), server.URL)

	client, err := NewClient(
		WithCortexAPIURL(server.URL),
		WithCortexAPIKey("test-key"),
		WithCortexAPIKeyID(123),
		WithTransport(server.Client().Transport.(*http.Transport)),
		WithLogger(log.TflogAdapter{}),
	)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	return client, server
}
