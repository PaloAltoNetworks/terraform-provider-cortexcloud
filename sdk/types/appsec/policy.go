// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"net/url"
	"strconv"
)

// ---------------------------
// Core structs
// ---------------------------

// Policy represents an Application Security policy.
type Policy struct {
	ID                          string             `json:"id"`
	Name                        string             `json:"name"`
	Description                 string             `json:"description"`
	Status                      string             `json:"status"` // "enabled" or "disabled"
	IsCustom                    bool               `json:"isCustom"`
	Conditions                  PolicyCondition    `json:"conditions"`
	Scope                       *PolicyScope       `json:"scope,omitempty"`
	AssetGroupIds               []int              `json:"assetGroupIds,omitempty"`
	Triggers                    PolicyTriggers     `json:"triggers"`
	Actions                     PolicyActions      `json:"actions"`
	FindingTypes                PolicyFindingTypes `json:"findingTypes"`
	OverrideIssueSeverity       *string            `json:"overrideIssueSeverity,omitempty"`
	DeveloperSuppressionAffects bool               `json:"developerSuppressionAffects"`
	RelatedDetectionRules       []string           `json:"relatedDetectionRules"`
	CreatedBy                   string             `json:"createdBy"`
	DateCreated                 string             `json:"dateCreated"`
	ModifiedBy                  string             `json:"modifiedBy"`
	DateModified                string             `json:"dateModified"`
	LastTriggered               *string            `json:"lastTriggered,omitempty"`
	Version                     float64            `json:"version"`
}

// PolicyCondition represents nested AND/OR conditions for policy matching.
// Supports up to 10 levels of nesting.
type PolicyCondition struct {
	SearchField *string           `json:"SEARCH_FIELD,omitempty"`
	SearchType  *string           `json:"SEARCH_TYPE,omitempty"`
	SearchValue interface{}       `json:"SEARCH_VALUE,omitempty"`
	And         []PolicyCondition `json:"AND,omitempty"`
	Or          []PolicyCondition `json:"OR,omitempty"`
}

// PolicyScope represents asset targeting criteria with nested AND/OR logic.
type PolicyScope struct {
	SearchField *string       `json:"SEARCH_FIELD,omitempty"`
	SearchType  *string       `json:"SEARCH_TYPE,omitempty"`
	SearchValue interface{}   `json:"SEARCH_VALUE,omitempty"`
	And         []PolicyScope `json:"AND,omitempty"`
	Or          []PolicyScope `json:"OR,omitempty"`
}

// PolicyTriggers defines when the policy evaluates.
type PolicyTriggers struct {
	Periodic      PolicyTriggerConfig `json:"periodic"`
	PR            PolicyTriggerConfig `json:"pr"`
	CICD          PolicyTriggerConfig `json:"cicd"`
	CIImage       PolicyTriggerConfig `json:"ciImage"`
	ImageRegistry PolicyTriggerConfig `json:"imageRegistry"`
}

// MarshalJSON implements custom JSON serialization for PolicyTriggers.
// Each trigger type only accepts its own subset of actions:
//   - periodic: reportIssue
//   - pr: reportIssue, blockPr, reportPrComment
//   - cicd: reportIssue, blockCicd, reportCicd
//   - ciImage: reportIssue, reportCicd, blockCicd
//   - imageRegistry: reportIssue
//
// The shared TriggerActions struct contains all action fields for
// deserialization convenience, but the API rejects excess properties
// on each trigger type. This marshaler filters actions per trigger.
//
// All five trigger blocks are emitted unconditionally because the API
// requires them on CREATE/UPDATE — omitting any of ciImage / imageRegistry
// produces an HTTP 422 ValidateError.
func (t PolicyTriggers) MarshalJSON() ([]byte, error) {
	type periodicActions struct {
		ReportIssue bool `json:"reportIssue"`
	}
	type prActions struct {
		ReportIssue     bool `json:"reportIssue"`
		BlockPR         bool `json:"blockPr"`
		ReportPRComment bool `json:"reportPrComment"`
	}
	type cicdActions struct {
		ReportIssue bool `json:"reportIssue"`
		BlockCICD   bool `json:"blockCicd"`
		ReportCICD  bool `json:"reportCicd"`
	}
	type ciImageActions struct {
		ReportIssue bool `json:"reportIssue"`
		ReportCICD  bool `json:"reportCicd"`
		BlockCICD   bool `json:"blockCicd"`
	}
	type imageRegistryActions struct {
		ReportIssue bool `json:"reportIssue"`
	}

	type triggerConfig[A any] struct {
		IsEnabled             bool    `json:"isEnabled"`
		Actions               A       `json:"actions"`
		OverrideIssueSeverity *string `json:"overrideIssueSeverity,omitempty"`
	}

	return json.Marshal(struct {
		Periodic      triggerConfig[periodicActions]      `json:"periodic"`
		PR            triggerConfig[prActions]            `json:"pr"`
		CICD          triggerConfig[cicdActions]          `json:"cicd"`
		CIImage       triggerConfig[ciImageActions]       `json:"ciImage"`
		ImageRegistry triggerConfig[imageRegistryActions] `json:"imageRegistry"`
	}{
		Periodic: triggerConfig[periodicActions]{
			IsEnabled:             t.Periodic.IsEnabled,
			Actions:               periodicActions{ReportIssue: t.Periodic.Actions.ReportIssue},
			OverrideIssueSeverity: t.Periodic.OverrideIssueSeverity,
		},
		PR: triggerConfig[prActions]{
			IsEnabled: t.PR.IsEnabled,
			Actions: prActions{
				ReportIssue:     t.PR.Actions.ReportIssue,
				BlockPR:         t.PR.Actions.BlockPR,
				ReportPRComment: t.PR.Actions.ReportPRComment,
			},
			OverrideIssueSeverity: t.PR.OverrideIssueSeverity,
		},
		CICD: triggerConfig[cicdActions]{
			IsEnabled: t.CICD.IsEnabled,
			Actions: cicdActions{
				ReportIssue: t.CICD.Actions.ReportIssue,
				BlockCICD:   t.CICD.Actions.BlockCICD,
				ReportCICD:  t.CICD.Actions.ReportCICD,
			},
			OverrideIssueSeverity: t.CICD.OverrideIssueSeverity,
		},
		CIImage: triggerConfig[ciImageActions]{
			IsEnabled: t.CIImage.IsEnabled,
			Actions: ciImageActions{
				ReportIssue: t.CIImage.Actions.ReportIssue,
				ReportCICD:  t.CIImage.Actions.ReportCICD,
				BlockCICD:   t.CIImage.Actions.BlockCICD,
			},
			OverrideIssueSeverity: t.CIImage.OverrideIssueSeverity,
		},
		ImageRegistry: triggerConfig[imageRegistryActions]{
			IsEnabled:             t.ImageRegistry.IsEnabled,
			Actions:               imageRegistryActions{ReportIssue: t.ImageRegistry.Actions.ReportIssue},
			OverrideIssueSeverity: t.ImageRegistry.OverrideIssueSeverity,
		},
	})
}

// marshalPolicyTriggersLegacy emits ONLY periodic / pr / cicd, omitting
// ciImage and imageRegistry. Used internally by the appsec client to retry
// CREATE/UPDATE on tenants whose API does not yet support the new triggers
// on some legacy stacks — the API rejects the new keys as excess properties
// with HTTP 422 ValidateError.
//
// This helper is intentionally NOT a method on PolicyTriggers (and NOT
// exported) to keep it invisible to public SDK consumers. The public
// MarshalJSON above continues to emit all five trigger keys unconditionally.
func marshalPolicyTriggersLegacy(t PolicyTriggers) ([]byte, error) {
	type periodicActions struct {
		ReportIssue bool `json:"reportIssue"`
	}
	type prActions struct {
		ReportIssue     bool `json:"reportIssue"`
		BlockPR         bool `json:"blockPr"`
		ReportPRComment bool `json:"reportPrComment"`
	}
	type cicdActions struct {
		ReportIssue bool `json:"reportIssue"`
		BlockCICD   bool `json:"blockCicd"`
		ReportCICD  bool `json:"reportCicd"`
	}

	type triggerConfig[A any] struct {
		IsEnabled             bool    `json:"isEnabled"`
		Actions               A       `json:"actions"`
		OverrideIssueSeverity *string `json:"overrideIssueSeverity,omitempty"`
	}

	return json.Marshal(struct {
		Periodic triggerConfig[periodicActions] `json:"periodic"`
		PR       triggerConfig[prActions]       `json:"pr"`
		CICD     triggerConfig[cicdActions]     `json:"cicd"`
	}{
		Periodic: triggerConfig[periodicActions]{
			IsEnabled:             t.Periodic.IsEnabled,
			Actions:               periodicActions{ReportIssue: t.Periodic.Actions.ReportIssue},
			OverrideIssueSeverity: t.Periodic.OverrideIssueSeverity,
		},
		PR: triggerConfig[prActions]{
			IsEnabled: t.PR.IsEnabled,
			Actions: prActions{
				ReportIssue:     t.PR.Actions.ReportIssue,
				BlockPR:         t.PR.Actions.BlockPR,
				ReportPRComment: t.PR.Actions.ReportPRComment,
			},
			OverrideIssueSeverity: t.PR.OverrideIssueSeverity,
		},
		CICD: triggerConfig[cicdActions]{
			IsEnabled: t.CICD.IsEnabled,
			Actions: cicdActions{
				ReportIssue: t.CICD.Actions.ReportIssue,
				BlockCICD:   t.CICD.Actions.BlockCICD,
				ReportCICD:  t.CICD.Actions.ReportCICD,
			},
			OverrideIssueSeverity: t.CICD.OverrideIssueSeverity,
		},
	})
}

// MarshalCreatePolicyRequestLegacy serializes a CreatePolicyRequest using the
// 3-trigger payload (no ciImage, no imageRegistry). Exported for use by the
// appsec client retry path; not intended for direct use by SDK consumers.
func MarshalCreatePolicyRequestLegacy(input CreatePolicyRequest) ([]byte, error) {
	return marshalPolicyRequestWithLegacyTriggers(input)
}

// MarshalUpdatePolicyRequestLegacy serializes an UpdatePolicyRequest using the
// 3-trigger payload (no ciImage, no imageRegistry). When input.Triggers is
// nil, the resulting body has no "triggers" field at all. Exported for use
// by the appsec client retry path; not intended for direct use by SDK
// consumers.
func MarshalUpdatePolicyRequestLegacy(input UpdatePolicyRequest) ([]byte, error) {
	return marshalPolicyRequestWithLegacyTriggers(input)
}

// marshalPolicyRequestWithLegacyTriggers serializes a request struct, then
// rewrites the "triggers" field (if present) using the legacy 3-trigger
// shape. The strategy is: marshal the struct normally (which uses the public
// PolicyTriggers.MarshalJSON), unmarshal into a generic map, then overwrite
// the triggers entry with the legacy bytes, and re-marshal.
//
// This lets us reuse all the per-field omitempty / required-presence rules
// from the request struct tags while only mutating the triggers shape.
func marshalPolicyRequestWithLegacyTriggers(input any) ([]byte, error) {
	full, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(full, &asMap); err != nil {
		return nil, err
	}

	// Replace triggers field if it was emitted. UpdatePolicyRequest uses
	// *PolicyTriggers with omitempty, so a nil triggers field is simply
	// absent from the map — which is the correct behaviour (don't add it).
	if _, ok := asMap["triggers"]; ok {
		triggers := extractPolicyTriggers(input)
		legacyTriggers, err := marshalPolicyTriggersLegacy(triggers)
		if err != nil {
			return nil, err
		}
		asMap["triggers"] = legacyTriggers
	}

	return json.Marshal(asMap)
}

// extractPolicyTriggers pulls out the Triggers field from a CreatePolicyRequest
// or UpdatePolicyRequest. Returns the zero value if the type is unknown or
// the pointer is nil — but in practice marshalPolicyRequestWithLegacyTriggers
// only calls this when the JSON map already contains a "triggers" key, so a
// nil *PolicyTriggers (UpdatePolicyRequest case) cannot occur here.
func extractPolicyTriggers(input any) PolicyTriggers {
	switch v := input.(type) {
	case CreatePolicyRequest:
		return v.Triggers
	case *CreatePolicyRequest:
		if v != nil {
			return v.Triggers
		}
	case UpdatePolicyRequest:
		if v.Triggers != nil {
			return *v.Triggers
		}
	case *UpdatePolicyRequest:
		if v != nil && v.Triggers != nil {
			return *v.Triggers
		}
	}
	return PolicyTriggers{}
}

// PolicyTriggerConfig configuration for each trigger type.
type PolicyTriggerConfig struct {
	IsEnabled             bool           `json:"isEnabled"`
	Actions               TriggerActions `json:"actions"`
	OverrideIssueSeverity *string        `json:"overrideIssueSeverity,omitempty"`
}

// TriggerActions available actions for each trigger type.
// All fields are present for deserialization convenience (the API response
// includes different subsets per trigger type). Serialization is handled by
// PolicyTriggers.MarshalJSON which filters to only the allowed actions.
type TriggerActions struct {
	ReportIssue     bool `json:"reportIssue"`
	BlockPR         bool `json:"blockPr"`
	ReportPRComment bool `json:"reportPrComment"`
	BlockCICD       bool `json:"blockCicd"`
	ReportCICD      bool `json:"reportCicd"`
	IngestedData    bool `json:"ingestedData,omitempty"`
}

// PolicyActions aggregated actions from all triggers.
type PolicyActions struct {
	ReportIssue     bool `json:"reportIssue"`
	BlockPR         bool `json:"blockPr"`
	BlockCICD       bool `json:"blockCicd"`
	ReportPRComment bool `json:"reportPrComment"`
	ReportCICD      bool `json:"reportCicd"`
	IngestedData    bool `json:"ingestedData"`
}

// PolicyFindingTypes supported scanner types for the policy.
type PolicyFindingTypes struct {
	CASCICDRiskScanner        bool `json:"CAS_CI_CD_RISK_SCANNER"`
	CASCVEScanner             bool `json:"CAS_CVE_SCANNER"`
	CASIACScanner             bool `json:"CAS_IAC_SCANNER"`
	CASLicenseScanner         bool `json:"CAS_LICENSE_SCANNER"`
	CASOperationalRiskScanner bool `json:"CAS_OPERATIONAL_RISK_SCANNER"`
	CASSASTScanner            bool `json:"CAS_SAST_SCANNER"`
	CASSecretScanner          bool `json:"CAS_SECRET_SCANNER"`
	CASThirdPartyWeaknesses   bool `json:"CAS_THIRD_PARTY_WEAKNESSES"`
}

// ---------------------------
// Request/Response structs
// ---------------------------

// CreatePolicyRequest handles input for the CreatePolicy function.
// Note: The POST endpoint rejects "developerSuppressionAffects" as an excess
// property, so it is intentionally excluded from this struct. Use the UPDATE
// endpoint (PUT) to set it after creation.
type CreatePolicyRequest struct {
	Name          string          `json:"name"`
	Description   string          `json:"description,omitempty"`
	Conditions    PolicyCondition `json:"conditions"`
	Scope         *PolicyScope    `json:"scope"` // Required by API — must always be present (no omitempty)
	AssetGroupIds []int           `json:"assetGroupIds,omitempty"`
	Triggers      PolicyTriggers  `json:"triggers"`
}

// UpdatePolicyRequest handles input for the UpdatePolicy function.
// All fields are optional to support partial updates.
type UpdatePolicyRequest struct {
	Name                        *string          `json:"name,omitempty"`
	Description                 *string          `json:"description,omitempty"`
	Enabled                     *bool            `json:"enabled,omitempty"`
	Triggers                    *PolicyTriggers  `json:"triggers,omitempty"`
	Conditions                  *PolicyCondition `json:"conditions,omitempty"`
	RelatedDetectionRules       []string         `json:"relatedDetectionRules,omitempty"`
	Scope                       *PolicyScope     `json:"scope,omitempty"`
	Actions                     *PolicyActions   `json:"actions,omitempty"`
	DeveloperSuppressionAffects *bool            `json:"developerSuppressionAffects,omitempty"`
	OverrideIssueSeverity       *string          `json:"overrideIssueSeverity,omitempty"`
	AssetGroupIds               []int            `json:"assetGroupIds,omitempty"`
}

// ListPoliciesRequest handles input for the ListPolicies function.
//
// Each value is serialized as a query value in the request URL.
type ListPoliciesRequest struct {
	FindingTypes                []string
	Actions                     []string
	Status                      string
	Triggers                    []string
	IsCustom                    bool
	DeveloperSuppressionAffects bool
}

func (r ListPoliciesRequest) ToQueryValues() url.Values {
	result := url.Values{}

	for _, findingType := range r.FindingTypes {
		result.Add("findingTypes", findingType)
	}
	for _, action := range r.Actions {
		result.Add("actions", action)
	}
	if r.Status != "" {
		result.Add("status", r.Status)
	}
	for _, trigger := range r.Triggers {
		result.Add("triggers", trigger)
	}
	result.Add("isCustom", strconv.FormatBool(r.IsCustom))
	result.Add("developerSuppressionAffects", strconv.FormatBool(r.DeveloperSuppressionAffects))

	return result
}

// DeletePolicyResponse handles the output for the DeletePolicy function.
type DeletePolicyResponse struct {
	Message string `json:"message"`
}
