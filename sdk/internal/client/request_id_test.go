// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"strings"
	"testing"
)

func TestGenerateRequestID(t *testing.T) {
	t.Run("should generate valid request ID", func(t *testing.T) {
		id := generateRequestID()

		// Check format: req_<32-hex-chars>
		if !strings.HasPrefix(id, "req_") {
			t.Errorf("Expected request ID to start with 'req_', got: %s", id)
		}

		hexPart := strings.TrimPrefix(id, "req_")
		if len(hexPart) != 32 {
			t.Errorf("Expected 32 hex characters, got %d: %s", len(hexPart), hexPart)
		}
	})

	t.Run("should generate unique IDs", func(t *testing.T) {
		id1 := generateRequestID()
		id2 := generateRequestID()

		if id1 == id2 {
			t.Error("Expected unique request IDs, got duplicates")
		}
	})

	t.Run("should generate many unique IDs", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 1000; i++ {
			id := generateRequestID()
			if seen[id] {
				t.Errorf("Duplicate request ID generated: %s", id)
			}
			seen[id] = true
		}
	})
}

func TestRequestIDContext(t *testing.T) {
	t.Run("should store and retrieve request ID", func(t *testing.T) {
		ctx := context.Background()
		expectedID := "req_test123"

		ctx = WithRequestID(ctx, expectedID)
		actualID := GetRequestID(ctx)

		if actualID != expectedID {
			t.Errorf("Expected %s, got %s", expectedID, actualID)
		}
	})

	t.Run("should return empty string when not set", func(t *testing.T) {
		ctx := context.Background()
		id := GetRequestID(ctx)

		if id != "" {
			t.Errorf("Expected empty string, got: %s", id)
		}
	})

	t.Run("should generate new ID if not present", func(t *testing.T) {
		ctx := context.Background()
		newCtx, id := GetOrGenerateRequestID(ctx)

		if id == "" {
			t.Error("Expected non-empty request ID")
		}

		if !strings.HasPrefix(id, "req_") {
			t.Errorf("Expected request ID to start with 'req_', got: %s", id)
		}

		retrievedID := GetRequestID(newCtx)
		if retrievedID != id {
			t.Errorf("Expected %s, got %s", id, retrievedID)
		}
	})

	t.Run("should use existing ID if present", func(t *testing.T) {
		ctx := context.Background()
		existingID := "req_existing"
		ctx = WithRequestID(ctx, existingID)

		newCtx, id := GetOrGenerateRequestID(ctx)

		if id != existingID {
			t.Errorf("Expected existing ID %s, got %s", existingID, id)
		}

		if newCtx != ctx {
			t.Error("Expected same context when ID already exists")
		}
	})

	t.Run("should handle context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		ctx = WithRequestID(ctx, "req_test")

		cancel()

		// Should still be able to retrieve ID even after cancellation
		id := GetRequestID(ctx)
		if id != "req_test" {
			t.Errorf("Expected to retrieve ID after cancellation, got: %s", id)
		}
	})

	t.Run("should handle nested contexts", func(t *testing.T) {
		ctx1 := context.Background()
		ctx1 = WithRequestID(ctx1, "req_parent")

		ctx2 := context.WithValue(ctx1, "other_key", "other_value")

		// Should still have request ID in nested context
		id := GetRequestID(ctx2)
		if id != "req_parent" {
			t.Errorf("Expected parent request ID, got: %s", id)
		}
	})
}
