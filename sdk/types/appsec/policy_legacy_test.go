// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"testing"
)

// fullTriggersForLegacyTests builds a fully populated PolicyTriggers value
// so we can detect dropped fields unambiguously.
func fullTriggersForLegacyTests() PolicyTriggers {
	sev := "HIGH"
	return PolicyTriggers{
		Periodic: PolicyTriggerConfig{
			IsEnabled: true,
			Actions:   TriggerActions{ReportIssue: true},
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
			IsEnabled: true,
			Actions: TriggerActions{
				ReportIssue: true,
				BlockCICD:   true,
				ReportCICD:  true,
			},
			OverrideIssueSeverity: &sev,
		},
		CIImage: PolicyTriggerConfig{
			IsEnabled: true,
			Actions: TriggerActions{
				ReportIssue: true,
				ReportCICD:  true,
				BlockCICD:   true,
			},
		},
		ImageRegistry: PolicyTriggerConfig{
			IsEnabled: true,
			Actions:   TriggerActions{ReportIssue: true},
		},
	}
}

// TestMarshalPolicyTriggersLegacy_OmitsNewKeys verifies the private legacy
// marshaler emits only periodic / pr / cicd.
func TestMarshalPolicyTriggersLegacy_OmitsNewKeys(t *testing.T) {
	data, err := marshalPolicyTriggersLegacy(fullTriggersForLegacyTests())
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var top map[string]interface{}
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	allowed := map[string]bool{"periodic": true, "pr": true, "cicd": true}
	for k := range top {
		if !allowed[k] {
			t.Errorf("unexpected key %q in legacy triggers payload (only periodic/pr/cicd allowed)", k)
		}
	}
	for k := range allowed {
		if _, ok := top[k]; !ok {
			t.Errorf("legacy triggers payload is missing required key %q", k)
		}
	}

	// Specifically the new keys must be absent.
	if _, ok := top["ciImage"]; ok {
		t.Error("legacy triggers payload must NOT contain ciImage")
	}
	if _, ok := top["imageRegistry"]; ok {
		t.Error("legacy triggers payload must NOT contain imageRegistry")
	}
}

// TestMarshalJSON_StillEmitsAllFiveKeys confirms the public PolicyTriggers
// MarshalJSON behaviour is unchanged.
func TestMarshalJSON_StillEmitsAllFiveKeys(t *testing.T) {
	data, err := json.Marshal(fullTriggersForLegacyTests())
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}
	var top map[string]interface{}
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	required := []string{"periodic", "pr", "cicd", "ciImage", "imageRegistry"}
	for _, k := range required {
		if _, ok := top[k]; !ok {
			t.Errorf("public MarshalJSON regression: required key %q missing", k)
		}
	}
}

// TestMarshalCreatePolicyRequestLegacy_RewritesTriggers verifies the request-
// level helper preserves all other fields and only rewrites triggers.
func TestMarshalCreatePolicyRequestLegacy_RewritesTriggers(t *testing.T) {
	deployed := "has_deployed_assets"
	eq := "EQ"
	req := CreatePolicyRequest{
		Name:        "Test",
		Description: "desc",
		Conditions: PolicyCondition{
			SearchField: &deployed,
			SearchType:  &eq,
			SearchValue: true,
		},
		Scope: &PolicyScope{
			SearchField: &deployed,
			SearchType:  &eq,
			SearchValue: true,
		},
		Triggers: fullTriggersForLegacyTests(),
	}

	data, err := MarshalCreatePolicyRequestLegacy(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("unexpected unmarshal: %v", err)
	}

	for _, must := range []string{"name", "conditions", "scope", "triggers"} {
		if _, ok := top[must]; !ok {
			t.Errorf("legacy create body missing required key %q", must)
		}
	}

	var triggers map[string]interface{}
	if err := json.Unmarshal(top["triggers"], &triggers); err != nil {
		t.Fatalf("triggers not a JSON object: %v", err)
	}
	if _, ok := triggers["ciImage"]; ok {
		t.Error("legacy create body's triggers must NOT contain ciImage")
	}
	if _, ok := triggers["imageRegistry"]; ok {
		t.Error("legacy create body's triggers must NOT contain imageRegistry")
	}
	for _, k := range []string{"periodic", "pr", "cicd"} {
		if _, ok := triggers[k]; !ok {
			t.Errorf("legacy create body's triggers missing %q", k)
		}
	}
}

// TestMarshalUpdatePolicyRequestLegacy_TriggersOnlyRewrittenWhenPresent
// verifies that when input.Triggers is nil, the resulting body has no
// "triggers" key (because UpdatePolicyRequest.Triggers has omitempty), and
// when triggers are set they are rewritten in legacy shape.
func TestMarshalUpdatePolicyRequestLegacy_TriggersOnlyRewrittenWhenPresent(t *testing.T) {
	t.Run("nil triggers -> body has no triggers key", func(t *testing.T) {
		name := "new name"
		req := UpdatePolicyRequest{Name: &name}

		data, err := MarshalUpdatePolicyRequestLegacy(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(data, &top); err != nil {
			t.Fatalf("unexpected unmarshal: %v", err)
		}
		if _, ok := top["triggers"]; ok {
			t.Error("update body must not include triggers when input.Triggers is nil")
		}
		if _, ok := top["name"]; !ok {
			t.Error("update body must still include name")
		}
	})

	t.Run("triggers present -> rewritten in legacy shape", func(t *testing.T) {
		triggers := fullTriggersForLegacyTests()
		req := UpdatePolicyRequest{Triggers: &triggers}

		data, err := MarshalUpdatePolicyRequestLegacy(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(data, &top); err != nil {
			t.Fatalf("unexpected unmarshal: %v", err)
		}
		raw, ok := top["triggers"]
		if !ok {
			t.Fatalf("update body must include triggers when input.Triggers is set")
		}
		var t2 map[string]interface{}
		if err := json.Unmarshal(raw, &t2); err != nil {
			t.Fatalf("triggers not an object: %v", err)
		}
		if _, ok := t2["ciImage"]; ok {
			t.Error("legacy update body's triggers must NOT contain ciImage")
		}
		if _, ok := t2["imageRegistry"]; ok {
			t.Error("legacy update body's triggers must NOT contain imageRegistry")
		}
	})
}
