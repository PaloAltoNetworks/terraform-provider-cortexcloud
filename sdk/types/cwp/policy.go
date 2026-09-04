// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

// Policy defines the structure for a CWP policy.
type Policy struct {
	ID                  string       `json:"id"`
	Revision            int          `json:"revision"`
	CreatedAt           string       `json:"createdAt"` // BUG: This field is treated like ModifiedBy -- it is updated whenever the policy is updated
	ModifiedAt          string       `json:"modifiedAt"`
	Type                string       `json:"type"`
	CreatedBy           string       `json:"createdBy"` // BUG: This field is configurable by the user and behaves like a regular string input, and will even accept empty strings
	Disabled            bool         `json:"disabled"`
	Name                string       `json:"name"`
	Description         string       `json:"description"`
	EvaluationModes     []string     `json:"evaluationModes"`
	EvaluationStage     string       `json:"evaluationStage"`
	PolicyRules         []PolicyRule `json:"policyRules"`
	Condition           string       `json:"condition"`
	Exception           string       `json:"exception"`
	AssetScope          string       `json:"assetScope"`
	AssetGroupIDs       []int        `json:"assetGroupsIDs"`
	AssetGroups         []string     `json:"assetGroups"`
	PolicyAction        string       `json:"action"`
	PolicySeverity      string       `json:"severity"`
	RemediationGuidance string       `json:"remediationGuidance"`
}

type PolicyRule struct {
	Action                  string  `json:"action" tfsdk:"action"` // Required in create/update request
	ID                      *string `json:"id,omitempty" tfsdk:"id"`
	PolicyID                *string `json:"policy_id,omitempty" tfsdk:"policy_id"`
	PolicyRevision          *int    `json:"policy_revision,omitempty" tfsdk:"policy_revision"`
	RemediationGuidance     *string `json:"remediation_guidance,omitempty" tfsdk:"remediation_guidance"`
	RuleID                  string  `json:"rule_id" tfsdk:"rule_id"` // Required in create/update request
	RuleName                *string `json:"rule_name,omitempty" tfsdk:"rule_name"`
	Severity                string  `json:"severity" tfsdk:"severity"` // Required in create/update request
	UserRemediationGuidance *string `json:"user_remediation_guidance,omitempty" tfsdk:"user_remediation_guidance"`
}

// CreateOrUpdatePolicyRequest is the request for creating or updating a CWP
// policy.
type CreateOrUpdatePolicyRequest struct {
	ID                  string       `json:"id,omitempty"`
	Type                string       `json:"type"`
	Name                string       `json:"name"`
	Description         string       `json:"description,omitempty"`
	Disabled            bool         `json:"disabled,omitempty"`
	EvaluationModes     []string     `json:"evaluationModes,omitempty"`
	EvaluationStage     string       `json:"evaluationStage"`
	PolicyRules         []PolicyRule `json:"policyRules"`
	Condition           string       `json:"condition,omitempty"`
	Exception           string       `json:"exception,omitempty"`
	AssetScope          string       `json:"assetScope,omitempty"`
	AssetGroupIDs       []int        `json:"assetGroupsIDs"`
	PolicyAction        string       `json:"action"`
	PolicySeverity      string       `json:"severity"`
	RemediationGuidance string       `json:"remediationGuidance,omitempty"`
}

// ToCreateOrUpdateRequest is a member function for converting the Policy object
// into a CreateOrUpdateRequest object.
//
// isUpdate denotes whether this will return a request for policy creation
// or a request for a policy update.
func (p *Policy) ToCreateOrUpdateRequest(isUpdate bool) (req CreateOrUpdatePolicyRequest) {
	req = CreateOrUpdatePolicyRequest{
		Type:                p.Type,
		Name:                p.Name,
		Description:         p.Description,
		Disabled:            p.Disabled,
		EvaluationModes:     p.EvaluationModes,
		EvaluationStage:     p.EvaluationStage,
		PolicyRules:         p.PolicyRules,
		Condition:           p.Condition,
		Exception:           p.Exception,
		AssetScope:          p.AssetScope,
		AssetGroupIDs:       p.AssetGroupIDs,
		PolicyAction:        p.PolicyAction,
		PolicySeverity:      p.PolicySeverity,
		RemediationGuidance: p.RemediationGuidance,
	}

	if isUpdate {
		req.ID = p.ID
	}

	return req
}

// CreateOrUpdatePolicyResponse is the response for creating or updating a
// CWP policy.
type CreateOrUpdatePolicyResponse struct {
	PolicyID string `json:"id"`
}

// ListPoliciesRequest is the request for listing CWP policies.
type ListPoliciesRequest struct {
	PolicyTypes []string `json:"policy_types,omitempty"`
}

// DeletePolicyRequest is the request for deleting a CWP policy.
type DeletePolicyRequest struct {
	PolicyID    string `json:"id"`
	CloseIssues bool   `json:"close_issues,omitempty"`
}
