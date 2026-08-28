// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	t.Run("should create new client with valid config", func(t *testing.T) {
		client, err := NewClient(
			WithCortexAPIURL("https://api.example.com"),
			WithCortexAPIKey("test-key"),
			WithCortexAPIKeyID(123),
		)
		require.NoError(t, err)
		require.NotNil(t, client)
		assert.Equal(t, "https://api.example.com", client.APIURL())
		assert.Equal(t, 123, client.APIKeyID())
		assert.Equal(t, "advanced", client.APIKeyType())
	})
}

func TestNewClientFromFile(t *testing.T) {
	t.Run("should create new client from file", func(t *testing.T) {
		// Create a temporary config file
		content := []byte(`{
			"api_url": "https://api.from.file",
			"api_key": "key-from-file",
			"api_key_id": 456,
			"api_key_type": "standard"
		}`)
		tmpfile, err := os.CreateTemp("", "test-config-*.json")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpfile.Name()) // clean up

		if _, err := tmpfile.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := tmpfile.Close(); err != nil {
			t.Fatal(err)
		}

		// Create client from file
		client, err := NewClientFromFile(tmpfile.Name())
		require.NoError(t, err)
		require.NotNil(t, client)
		assert.Equal(t, "https://api.from.file", client.APIURL())
		assert.Equal(t, 456, client.APIKeyID())
		assert.Equal(t, "standard", client.APIKeyType())
	})

	t.Run("should return error for non-existent file", func(t *testing.T) {
		client, err := NewClientFromFile("/non/existent/file.json")
		assert.Error(t, err)
		assert.Nil(t, client)
	})
}
