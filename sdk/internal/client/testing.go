// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"os"
	"strconv"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/config"
	"github.com/stretchr/testify/assert"
)

func NewTestClient(t *testing.T) *Client {
	apiUrl := os.Getenv("TEST_CORTEX_API_URL")
	apiKey := os.Getenv("TEST_CORTEX_API_KEY")
	apiKeyIDStr := os.Getenv("TEST_CORTEX_API_KEY_ID")

	apiKeyID, err := strconv.Atoi(apiKeyIDStr)
	if err != nil {
		t.Fatalf("failed to convert API key ID \"%s\" to int: %s", apiKeyIDStr, err.Error())
	}
	client, err := NewClientFromConfig(
		config.NewConfig(
			config.WithCortexAPIURL(apiUrl),
			config.WithCortexAPIKey(apiKey),
			config.WithCortexAPIKeyID(apiKeyID),
			config.WithCortexAPIKeyType("standard"),
			config.WithLogLevel("debug"),
		),
	)
	assert.NoError(t, err)
	assert.NotNil(t, client)

	return client
}
