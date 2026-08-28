// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/appsec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// fullTriggers builds a PolicyTriggers value with every key non-zero so we
// can detect dropped fields unambiguously.
func fullTriggers() types.PolicyTriggers {
	sev := "HIGH"
	return types.PolicyTriggers{
		Periodic: types.PolicyTriggerConfig{
			IsEnabled: true,
			Actions:   types.TriggerActions{ReportIssue: true},
		},
		PR: types.PolicyTriggerConfig{
			IsEnabled: true,
			Actions: types.TriggerActions{
				ReportIssue:     true,
				BlockPR:         true,
				ReportPRComment: true,
			},
		},
		CICD: types.PolicyTriggerConfig{
			IsEnabled: true,
			Actions: types.TriggerActions{
				ReportIssue: true,
				BlockCICD:   true,
				ReportCICD:  true,
			},
			OverrideIssueSeverity: &sev,
		},
		CIImage: types.PolicyTriggerConfig{
			IsEnabled: true,
			Actions: types.TriggerActions{
				ReportIssue: true,
				ReportCICD:  true,
				BlockCICD:   true,
			},
		},
		ImageRegistry: types.PolicyTriggerConfig{
			IsEnabled: true,
			Actions:   types.TriggerActions{ReportIssue: true},
		},
	}
}

// q2ExcessPropertyResponseBody mimics the exact 422 ValidateError shape
// returned by Q2 stage-x5 when ciImage / imageRegistry are sent.
const q2ExcessPropertyResponseBody = `{
  "errorCode": "VALIDATION_ERROR",
  "message": "Validation failed",
  "details": {
    "policy.triggers.ciImage":       { "message": "extra fields not permitted" },
    "policy.triggers.imageRegistry": { "message": "extra fields not permitted" }
  }
}`

// unrelatedValidationResponseBody is a 422 that does NOT mention
// ciImage / imageRegistry — used to verify we do not retry.
const unrelatedValidationResponseBody = `{
  "errorCode": "VALIDATION_ERROR",
  "message": "Validation failed",
  "details": {
    "policy.name": { "message": "must not be empty" }
  }
}`

// readBodyOnce reads and replaces r.Body so subsequent code can still inspect it.
func readBodyOnce(t *testing.T, r *http.Request) []byte {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	_ = r.Body.Close()
	return b
}

// triggerKeysOf decodes a request body and returns the set of keys present
// in policy.triggers.
func triggerKeysOf(t *testing.T, body []byte) map[string]bool {
	t.Helper()
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &top))
	rawTriggers, ok := top["triggers"]
	if !ok {
		return nil
	}
	var triggers map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rawTriggers, &triggers))
	keys := make(map[string]bool, len(triggers))
	for k := range triggers {
		keys[k] = true
	}
	return keys
}

func validCreateRequest() types.CreatePolicyRequest {
	deployed := "has_deployed_assets"
	eq := "EQ"
	return types.CreatePolicyRequest{
		Name:        "Test Policy",
		Description: "Test description",
		Conditions: types.PolicyCondition{
			SearchField: &deployed,
			SearchType:  &eq,
			SearchValue: true,
		},
		Scope: &types.PolicyScope{
			SearchField: &deployed,
			SearchType:  &eq,
			SearchValue: true,
		},
		Triggers: fullTriggers(),
	}
}

func validUpdateRequest() (string, types.UpdatePolicyRequest) {
	name := "Updated Name"
	triggers := fullTriggers()
	return "policy-123", types.UpdatePolicyRequest{
		Name:     &name,
		Triggers: &triggers,
	}
}

// ---------------------------------------------------------------------------
// CreatePolicy tests
// ---------------------------------------------------------------------------

func TestCreatePolicy_Q2RetryOmitsCIImageAndImageRegistry(t *testing.T) {
	var calls atomic.Int32
	var firstBody, secondBody []byte

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		body := readBodyOnce(t, r)
		switch n {
		case 1:
			firstBody = body
			// Q2 rejects the 5-trigger payload as excess properties.
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprint(w, q2ExcessPropertyResponseBody)
		case 2:
			secondBody = body
			w.WriteHeader(http.StatusCreated)
			pol := types.Policy{ID: "policy-q2", Name: "Test Policy", Status: "enabled"}
			require.NoError(t, json.NewEncoder(w).Encode(pol))
		default:
			t.Fatalf("unexpected 3rd call to CreatePolicy")
		}
	})
	client, server := setupTest(t, handler)
	defer server.Close()

	pol, err := client.CreatePolicy(context.Background(), validCreateRequest())
	require.NoError(t, err)
	assert.Equal(t, "policy-q2", pol.ID)
	assert.EqualValues(t, 2, calls.Load(), "expected exactly one retry")

	firstKeys := triggerKeysOf(t, firstBody)
	assert.True(t, firstKeys["ciImage"], "first attempt must include ciImage")
	assert.True(t, firstKeys["imageRegistry"], "first attempt must include imageRegistry")
	assert.True(t, firstKeys["periodic"], "first attempt must include periodic")
	assert.True(t, firstKeys["pr"], "first attempt must include pr")
	assert.True(t, firstKeys["cicd"], "first attempt must include cicd")

	secondKeys := triggerKeysOf(t, secondBody)
	assert.False(t, secondKeys["ciImage"], "retry must NOT include ciImage")
	assert.False(t, secondKeys["imageRegistry"], "retry must NOT include imageRegistry")
	assert.True(t, secondKeys["periodic"], "retry must keep periodic")
	assert.True(t, secondKeys["pr"], "retry must keep pr")
	assert.True(t, secondKeys["cicd"], "retry must keep cicd")
}

func TestCreatePolicy_NoRetryOnUnrelatedValidationError(t *testing.T) {
	var calls atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = readBodyOnce(t, r)
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, unrelatedValidationResponseBody)
	})
	client, server := setupTest(t, handler)
	defer server.Close()

	_, err := client.CreatePolicy(context.Background(), validCreateRequest())
	assert.Error(t, err, "unrelated 422 must surface to caller")
	assert.EqualValues(t, 1, calls.Load(), "must NOT retry on unrelated validation error")
}

func TestCreatePolicy_NoRetryOnSuccess(t *testing.T) {
	var calls atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = readBodyOnce(t, r)
		w.WriteHeader(http.StatusCreated)
		pol := types.Policy{ID: "policy-ok", Name: "Test Policy"}
		require.NoError(t, json.NewEncoder(w).Encode(pol))
	})
	client, server := setupTest(t, handler)
	defer server.Close()

	pol, err := client.CreatePolicy(context.Background(), validCreateRequest())
	require.NoError(t, err)
	assert.Equal(t, "policy-ok", pol.ID)
	assert.EqualValues(t, 1, calls.Load(), "no retry expected on success")
}

func TestCreatePolicy_NoRetryOnNon422Error(t *testing.T) {
	var calls atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = readBodyOnce(t, r)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"errorCode":"INTERNAL","message":"boom"}`)
	})
	client, server := setupTest(t, handler)
	defer server.Close()

	_, err := client.CreatePolicy(context.Background(), validCreateRequest())
	assert.Error(t, err)
	// 500 may be retried by the internal HTTP client but never by our
	// legacy-trigger code path. Assert that the error path did not double
	// the call count due to OUR retry: at most the internal retries
	// configured on the client (default behaviour).
	got := calls.Load()
	assert.LessOrEqual(t, got, int32(4), "no extra legacy-trigger retry expected")
	assert.GreaterOrEqual(t, got, int32(1), "request must be attempted at least once")
}

// ---------------------------------------------------------------------------
// UpdatePolicy tests
// ---------------------------------------------------------------------------

func TestUpdatePolicy_Q2RetryOmitsCIImageAndImageRegistry(t *testing.T) {
	var calls atomic.Int32
	var firstBody, secondBody []byte

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		assert.Equal(t, http.MethodPut, r.Method)
		body := readBodyOnce(t, r)
		switch n {
		case 1:
			firstBody = body
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprint(w, q2ExcessPropertyResponseBody)
		case 2:
			secondBody = body
			w.WriteHeader(http.StatusOK)
			pol := types.Policy{ID: "policy-123", Name: "Updated Name"}
			require.NoError(t, json.NewEncoder(w).Encode(pol))
		default:
			t.Fatalf("unexpected 3rd call to UpdatePolicy")
		}
	})
	client, server := setupTest(t, handler)
	defer server.Close()

	id, req := validUpdateRequest()
	pol, err := client.UpdatePolicy(context.Background(), id, req)
	require.NoError(t, err)
	assert.Equal(t, "policy-123", pol.ID)
	assert.EqualValues(t, 2, calls.Load(), "expected exactly one retry")

	firstKeys := triggerKeysOf(t, firstBody)
	assert.True(t, firstKeys["ciImage"], "first attempt must include ciImage")
	assert.True(t, firstKeys["imageRegistry"], "first attempt must include imageRegistry")

	secondKeys := triggerKeysOf(t, secondBody)
	assert.False(t, secondKeys["ciImage"], "retry must NOT include ciImage")
	assert.False(t, secondKeys["imageRegistry"], "retry must NOT include imageRegistry")
	assert.True(t, secondKeys["periodic"], "retry must keep periodic")
	assert.True(t, secondKeys["pr"], "retry must keep pr")
	assert.True(t, secondKeys["cicd"], "retry must keep cicd")
}

func TestUpdatePolicy_NoRetryOnUnrelatedValidationError(t *testing.T) {
	var calls atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = readBodyOnce(t, r)
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, unrelatedValidationResponseBody)
	})
	client, server := setupTest(t, handler)
	defer server.Close()

	id, req := validUpdateRequest()
	_, err := client.UpdatePolicy(context.Background(), id, req)
	assert.Error(t, err)
	assert.EqualValues(t, 1, calls.Load(), "must NOT retry on unrelated validation error")
}

func TestUpdatePolicy_NoRetryWhenTriggersNil(t *testing.T) {
	// Even if the API returns a Q2-style excess-property error, when the
	// caller did not include any triggers payload there is nothing
	// meaningful to retry — we should pass the original error through
	// rather than spuriously rebuilding the body.
	var calls atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = readBodyOnce(t, r)
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, q2ExcessPropertyResponseBody)
	})
	client, server := setupTest(t, handler)
	defer server.Close()

	name := "Just a name change"
	req := types.UpdatePolicyRequest{Name: &name} // Triggers is nil
	_, err := client.UpdatePolicy(context.Background(), "policy-x", req)
	assert.Error(t, err)
	assert.EqualValues(t, 1, calls.Load(),
		"UpdatePolicy must not retry when input.Triggers == nil")
}

func TestUpdatePolicy_NoRetryOnSuccess(t *testing.T) {
	var calls atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = readBodyOnce(t, r)
		w.WriteHeader(http.StatusOK)
		pol := types.Policy{ID: "policy-123", Name: "Updated Name"}
		require.NoError(t, json.NewEncoder(w).Encode(pol))
	})
	client, server := setupTest(t, handler)
	defer server.Close()

	id, req := validUpdateRequest()
	pol, err := client.UpdatePolicy(context.Background(), id, req)
	require.NoError(t, err)
	assert.Equal(t, "policy-123", pol.ID)
	assert.EqualValues(t, 1, calls.Load(), "no retry expected on success")
}

// ---------------------------------------------------------------------------
// isLegacyTriggerExcessPropertyError unit tests
// ---------------------------------------------------------------------------

func TestIsLegacyTriggerExcessPropertyError(t *testing.T) {
	t.Run("nil error returns false", func(t *testing.T) {
		assert.False(t, isLegacyTriggerExcessPropertyError(nil))
	})

	t.Run("non-API error returns false", func(t *testing.T) {
		assert.False(t, isLegacyTriggerExcessPropertyError(fmt.Errorf("plain error")))
	})

	t.Run("API error referencing ciImage with excess-property message returns true", func(t *testing.T) {
		var bodyOk = `{"errorCode":"VALIDATION_ERROR","message":"x","details":{"policy.triggers.ciImage":{"message":"extra fields not permitted"}}}`
		err := apiErrorFromBody(t, bodyOk)
		assert.True(t, isLegacyTriggerExcessPropertyError(err))
	})

	t.Run("API error referencing imageRegistry returns true", func(t *testing.T) {
		var bodyOk = `{"errorCode":"VALIDATION_ERROR","message":"x","details":{"policy.triggers.imageRegistry":{"message":"unknown property"}}}`
		err := apiErrorFromBody(t, bodyOk)
		assert.True(t, isLegacyTriggerExcessPropertyError(err))
	})

	t.Run("API error on different field returns false", func(t *testing.T) {
		body := `{"errorCode":"VALIDATION_ERROR","message":"x","details":{"policy.name":{"message":"must not be empty"}}}`
		err := apiErrorFromBody(t, body)
		assert.False(t, isLegacyTriggerExcessPropertyError(err))
	})

	t.Run("API error referencing ciImage but with non-excess message returns false", func(t *testing.T) {
		body := `{"errorCode":"VALIDATION_ERROR","message":"x","details":{"policy.triggers.ciImage":{"message":"value out of range"}}}`
		err := apiErrorFromBody(t, body)
		assert.False(t, isLegacyTriggerExcessPropertyError(err))
	})
}

// apiErrorFromBody simulates what the internal HTTP client returns when the
// API responds with a 422 ValidateError. We do this by going through a
// real test handler so the wiring (errors.As unwrapping, Details parsing)
// is exercised end-to-end.
func apiErrorFromBody(t *testing.T, responseBody string) error {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, responseBody)
	})
	client, server := setupTest(t, handler)
	defer server.Close()

	_, err := client.CreatePolicy(context.Background(), validCreateRequest())
	require.Error(t, err)
	return err
}
