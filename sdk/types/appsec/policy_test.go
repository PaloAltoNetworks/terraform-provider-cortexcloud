// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTriggerActions_MarshalJSON_IncludesFalseValues(t *testing.T) {
	t.Run("should include all required boolean fields even when false", func(t *testing.T) {
		actions := TriggerActions{
			ReportIssue:     true,
			BlockPR:         false,
			ReportPRComment: false,
			BlockCICD:       false,
			ReportCICD:      false,
		}

		data, err := json.Marshal(actions)
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}

		// All required fields must be present in JSON output, even when false.
		// The AppSec API returns ValidateError if these are missing.
		requiredFields := []string{"blockPr", "reportPrComment", "blockCicd", "reportCicd", "reportIssue"}
		for _, field := range requiredFields {
			val, ok := result[field]
			if !ok {
				t.Errorf("required field %q missing from JSON output (was likely dropped by omitempty)", field)
				continue
			}
			// blockPr, reportPrComment, blockCicd, reportCicd should be false
			if field != "reportIssue" {
				if val != false {
					t.Errorf("expected %q to be false, got %v", field, val)
				}
			}
		}

		if result["reportIssue"] != true {
			t.Errorf("expected reportIssue to be true, got %v", result["reportIssue"])
		}
	})

	t.Run("should omit ingestedData when false", func(t *testing.T) {
		actions := TriggerActions{
			ReportIssue:  true,
			IngestedData: false,
		}

		data, err := json.Marshal(actions)
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}

		// ingestedData is optional and should be omitted when false
		if _, ok := result["ingestedData"]; ok {
			t.Error("ingestedData should be omitted when false (it has omitempty)")
		}
	})

	t.Run("should include ingestedData when true", func(t *testing.T) {
		actions := TriggerActions{
			ReportIssue:  true,
			IngestedData: true,
		}

		data, err := json.Marshal(actions)
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}

		if _, ok := result["ingestedData"]; !ok {
			t.Error("ingestedData should be present when true")
		}
	})
}

func TestCreatePolicyRequest_MarshalJSON_TriggersIncludeAllFields(t *testing.T) {
	t.Run("should serialize triggers with all required action fields", func(t *testing.T) {
		req := CreatePolicyRequest{
			Name: "test-policy",
			Triggers: PolicyTriggers{
				PR: PolicyTriggerConfig{
					IsEnabled: true,
					Actions: TriggerActions{
						ReportIssue:     true,
						BlockPR:         false,
						ReportPRComment: true,
					},
				},
				CICD: PolicyTriggerConfig{
					IsEnabled: true,
					Actions: TriggerActions{
						ReportIssue: true,
						BlockCICD:   false,
						ReportCICD:  true,
					},
				},
			},
		}

		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}

		jsonStr := string(data)

		// These fields must be present even when false — the API requires them
		expectedSubstrings := []string{
			`"blockPr":false`,
			`"blockCicd":false`,
			`"reportPrComment":true`,
			`"reportCicd":true`,
		}
		for _, substr := range expectedSubstrings {
			if !strings.Contains(jsonStr, substr) {
				t.Errorf("expected JSON to contain %s, got: %s", substr, jsonStr)
			}
		}
	})

	t.Run("should emit all 5 trigger keys", func(t *testing.T) {
		// Even when the PolicyTriggers struct is zero-valued, every trigger key
		// must appear in the output — the API rejects requests that omit any of
		// periodic / pr / cicd / ciImage / imageRegistry with HTTP 422.
		req := CreatePolicyRequest{
			Name:     "test-policy",
			Triggers: PolicyTriggers{},
		}

		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}

		// Re-decode the triggers block so we can assert on its structure.
		var decoded struct {
			Triggers map[string]json.RawMessage `json:"triggers"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}

		expectedKeys := []string{"periodic", "pr", "cicd", "ciImage", "imageRegistry"}
		for _, k := range expectedKeys {
			if _, ok := decoded.Triggers[k]; !ok {
				t.Errorf("trigger key %q missing from output: %s", k, string(data))
			}
		}
		if len(decoded.Triggers) != len(expectedKeys) {
			t.Errorf("expected exactly %d trigger keys, got %d: %v",
				len(expectedKeys), len(decoded.Triggers), keys(decoded.Triggers))
		}
	})

	t.Run("ciImage emits exactly reportIssue, reportCicd, blockCicd in actions", func(t *testing.T) {
		req := CreatePolicyRequest{
			Triggers: PolicyTriggers{
				CIImage: PolicyTriggerConfig{
					IsEnabled: true,
					Actions: TriggerActions{
						ReportIssue: true,
						ReportCICD:  true,
						BlockCICD:   false,
					},
				},
			},
		}
		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded struct {
			Triggers struct {
				CIImage struct {
					IsEnabled bool                   `json:"isEnabled"`
					Actions   map[string]interface{} `json:"actions"`
				} `json:"ciImage"`
			} `json:"triggers"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !decoded.Triggers.CIImage.IsEnabled {
			t.Errorf("expected ciImage.isEnabled=true, got false")
		}
		actions := decoded.Triggers.CIImage.Actions
		// Exactly these three keys
		expected := map[string]bool{"reportIssue": true, "reportCicd": true, "blockCicd": false}
		if len(actions) != len(expected) {
			t.Errorf("ciImage.actions: expected %d keys, got %d (%v)", len(expected), len(actions), actions)
		}
		for k, v := range expected {
			got, ok := actions[k]
			if !ok {
				t.Errorf("ciImage.actions missing %q", k)
				continue
			}
			if got != v {
				t.Errorf("ciImage.actions.%s: expected %v, got %v", k, v, got)
			}
		}
		// And NOT these
		for _, forbidden := range []string{"blockPr", "reportPrComment"} {
			if _, ok := actions[forbidden]; ok {
				t.Errorf("ciImage.actions must NOT contain %q (got: %v)", forbidden, actions)
			}
		}
	})

	t.Run("imageRegistry emits exactly reportIssue in actions", func(t *testing.T) {
		req := CreatePolicyRequest{
			Triggers: PolicyTriggers{
				ImageRegistry: PolicyTriggerConfig{
					IsEnabled: false,
					Actions: TriggerActions{
						ReportIssue: false,
						// even though TriggerActions has these, they must NOT appear
						BlockCICD:       true,
						ReportCICD:      true,
						BlockPR:         true,
						ReportPRComment: true,
					},
				},
			},
		}
		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded struct {
			Triggers struct {
				ImageRegistry struct {
					IsEnabled bool                   `json:"isEnabled"`
					Actions   map[string]interface{} `json:"actions"`
				} `json:"imageRegistry"`
			} `json:"triggers"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.Triggers.ImageRegistry.IsEnabled {
			t.Errorf("expected imageRegistry.isEnabled=false, got true")
		}
		actions := decoded.Triggers.ImageRegistry.Actions
		if len(actions) != 1 {
			t.Errorf("imageRegistry.actions: expected exactly 1 key, got %d (%v)", len(actions), actions)
		}
		if got, ok := actions["reportIssue"]; !ok || got != false {
			t.Errorf("imageRegistry.actions.reportIssue: expected false, got %v (ok=%v)", got, ok)
		}
		for _, forbidden := range []string{"blockPr", "blockCicd", "reportCicd", "reportPrComment"} {
			if _, ok := actions[forbidden]; ok {
				t.Errorf("imageRegistry.actions must NOT contain %q (got: %v)", forbidden, actions)
			}
		}
	})

	t.Run("ciImage and imageRegistry default isEnabled to false on zero value", func(t *testing.T) {
		req := CreatePolicyRequest{Triggers: PolicyTriggers{}}
		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded struct {
			Triggers struct {
				CIImage struct {
					IsEnabled bool `json:"isEnabled"`
				} `json:"ciImage"`
				ImageRegistry struct {
					IsEnabled bool `json:"isEnabled"`
				} `json:"imageRegistry"`
			} `json:"triggers"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.Triggers.CIImage.IsEnabled {
			t.Errorf("ciImage.isEnabled must default to false")
		}
		if decoded.Triggers.ImageRegistry.IsEnabled {
			t.Errorf("imageRegistry.isEnabled must default to false")
		}
	})
}

func TestPolicyTriggers_RoundTrip(t *testing.T) {
	high := "High"
	original := PolicyTriggers{
		Periodic: PolicyTriggerConfig{
			IsEnabled:             true,
			OverrideIssueSeverity: &high,
			Actions:               TriggerActions{ReportIssue: true},
		},
		PR: PolicyTriggerConfig{
			IsEnabled: true,
			Actions: TriggerActions{
				ReportIssue:     true,
				BlockPR:         true,
				ReportPRComment: true,
			},
		},
		CICD: PolicyTriggerConfig{
			IsEnabled: false,
			Actions: TriggerActions{
				ReportIssue: false,
				BlockCICD:   false,
				ReportCICD:  false,
			},
		},
		CIImage: PolicyTriggerConfig{
			IsEnabled: true,
			Actions: TriggerActions{
				ReportIssue: true,
				ReportCICD:  true,
				BlockCICD:   false,
			},
		},
		ImageRegistry: PolicyTriggerConfig{
			IsEnabled: false,
			Actions:   TriggerActions{ReportIssue: false},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var roundTripped PolicyTriggers
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Periodic
	if roundTripped.Periodic.IsEnabled != true {
		t.Errorf("Periodic.IsEnabled: expected true, got %v", roundTripped.Periodic.IsEnabled)
	}
	if roundTripped.Periodic.OverrideIssueSeverity == nil || *roundTripped.Periodic.OverrideIssueSeverity != "High" {
		t.Errorf("Periodic.OverrideIssueSeverity: expected 'High', got %v", roundTripped.Periodic.OverrideIssueSeverity)
	}
	if !roundTripped.Periodic.Actions.ReportIssue {
		t.Errorf("Periodic.Actions.ReportIssue: expected true")
	}
	// PR
	if !roundTripped.PR.IsEnabled || !roundTripped.PR.Actions.BlockPR || !roundTripped.PR.Actions.ReportPRComment {
		t.Errorf("PR round-trip mismatch: %+v", roundTripped.PR)
	}
	// CIImage
	if !roundTripped.CIImage.IsEnabled {
		t.Errorf("CIImage.IsEnabled: expected true, got false")
	}
	if !roundTripped.CIImage.Actions.ReportIssue || !roundTripped.CIImage.Actions.ReportCICD {
		t.Errorf("CIImage.Actions round-trip mismatch: %+v", roundTripped.CIImage.Actions)
	}
	// ImageRegistry
	if roundTripped.ImageRegistry.IsEnabled {
		t.Errorf("ImageRegistry.IsEnabled: expected false, got true")
	}
	if roundTripped.ImageRegistry.Actions.ReportIssue {
		t.Errorf("ImageRegistry.Actions.ReportIssue: expected false")
	}
}

// keys returns the keys of m as a slice (test helper, used by sub-tests above).
func keys(m map[string]json.RawMessage) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}
