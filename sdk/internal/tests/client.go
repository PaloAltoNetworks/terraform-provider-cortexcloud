// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package tests

//import (
//	//"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/config"
//	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
//
//	"net/http"
//	"net/http/httptest"
//	//"os"
//	//"strconv"
//	"testing"
//)
//
//var (
//	TestClient     *client.InternalClient = nil
//	TestHTTPServer *httptest.Server       = nil
//)
//
//func GetHTTPServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, error) {
//}
//
//func NewClient(t *testing.T, handler http.HandlerFunc) (*client, *httptest.Server) {
//	t.Helper()
//
//	server := httptest.NewServer(handler)
//	//cortexAPIURL, err := testServerURLtoCortexAPI(server.URL)
//	//if err != nil {
//	//	t.Fatalf("failed to convert test server URL: %s", err.Error())
//	//}
//	//server.URL = cortexAPIURL
//
//	t.Logf("[%s] Test server URL %s", t.Name(), server.URL)
//
//	client, err := NewClient(
//		WithCortexAPIURL(server.URL),
//		WithCortexAPIKey("test-key"),
//		WithCortexAPIKeyID(123),
//		WithTransport(server.Client().Transport.(*http.Transport)),
//		WithLogger(log.TflogAdapter{}),
//	)
//	assert.NoError(t, err)
//	assert.NotNil(t, client)
//	return client, server
//}
