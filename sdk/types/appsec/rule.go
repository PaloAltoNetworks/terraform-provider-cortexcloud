// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"net/url"
	"strconv"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
)

// ---------------------------
// Core structs
// ---------------------------

// Rule represents an Application Security rule.
type Rule struct {
	Category         string           `json:"category"`
	CloudProvider    string           `json:"cloudProvider"`
	CreatedAt        CreatedUpdatedAt `json:"createdAt"`
	Description      string           `json:"description"`
	DetectionMethod  *string          `json:"detectionMethod"`
	DocLink          string           `json:"docLink"`
	Domain           string           `json:"domain"`
	FindingCategory  string           `json:"findingCategory"`
	FindingDocs      string           `json:"findingDocs"`
	FindingTypeId    int              `json:"findingTypeId"`
	FindingTypeName  string           `json:"findingTypeName"`
	Frameworks       []FrameworkData  `json:"frameworks"`
	Id               string           `json:"id"`
	IsCustom         bool             `json:"isCustom"`
	IsEnabled        bool             `json:"isEnabled"`
	Labels           *[]string        `json:"labels"`
	MitreTactics     []string         `json:"mitreTactics"`
	MitreTechniques  []string         `json:"mitreTechniques"`
	Name             string           `json:"name"`
	Owner            string           `json:"owner"`
	Scanner          string           `json:"scanner"`
	Severity         string           `json:"severity"`
	ShortDescription string           `json:"shortDescription"`
	Source           string           `json:"source"`
	SubCategory      string           `json:"subCategory"`
	UpdatedAt        CreatedUpdatedAt `json:"updatedAt"`
}

// CreatedUpdatedAt represents the datetime value that the rule was created
// or updated.
type CreatedUpdatedAt struct {
	Value string `json:"value,omitempty"`
}

// Framework represents a framework or language that the rule applies to.
type Framework struct {
	Name                   string  `json:"name"`
	Definition             string  `json:"definition"`
	DefinitionLink         string  `json:"definitionLink,omitempty"`
	RemediationDescription *string `json:"remediationDescription,omitempty"`
}

// FrameworkData represents a framework or language that the
// Application Security rule applies to.
type FrameworkData struct {
	Name                   string `json:"name"`
	Definition             string `json:"definition"`
	DefinitionLink         string `json:"definitionLink"`
	RemediationDescription string `json:"remediationDescription"`
	// RemediationIds and ResourceTypes are populated by the API on read.
	RemediationIds []string `json:"remediationIds,omitempty"`
	ResourceTypes  []string `json:"resourceTypes,omitempty"`
}

// ---------------------------
// Request/Response structs
// ---------------------------

// ValidateRequest handles input for the Validate function.
type ValidateRequest struct {
	Framework  string `json:"framework"`
	Definition string `json:"definition"`
}

// ValidateRequestPayload represents the payload for the Validate endpoint.
type ValidateRequestPayload struct {
	FrameworksData []FrameworkData         `json:"frameworksData"`
	Name           string                  `json:"name"`
	MetaData       ValidateRequestMetadata `json:"metaData"`
	RuleId         string                  `json:"ruleId"`
}

// ValidateRequestMetadata represents the Application Security rule properties
// that are relevant to the framework or language for which the rule is
// applicable.
type ValidateRequestMetadata struct {
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	Guidelines string `json:"guidelines"`
}

// ValidateResponse handles the output for the Validate function.
type ValidateResponse struct {
	IsValid          *bool                            `json:"isValid"`
	FrameworksErrors []ValidateResponseFrameworkError `json:"frameworkErrors"`
}

// ValidateResponseFrameworkError represents the errors returned by the
// Cortex Cloud API for each framework defined for the rule.
type ValidateResponseFrameworkError struct {
	Framework enums.FrameworkName `json:"framework"`
	Errors    []string            `json:"errors"`
}

// CreateOrCloneRequest handles input for the CreateOrClone function.
type CreateOrCloneRequest struct {
	Category    string          `json:"category,omitempty"`
	Description string          `json:"description"`
	Frameworks  []FrameworkData `json:"frameworks"`
	Labels      []string        `json:"labels"`
	Name        string          `json:"name"`
	Scanner     string          `json:"scanner"`
	Severity    string          `json:"severity"`
	SubCategory string          `json:"subCategory"`
	// CspmRuleId maps this custom rule to a Cloud Security (CSPM) rule. It is
	// an optional, write-only field: the API accepts it on create but does not
	// return it on read. Omitted from the payload when empty.
	CspmRuleId *string `json:"cspmRuleId,omitempty"`
}

// ListRequest handles input for the List function.
//
// Each value is serialized as a query value in the request URL.
type ListRequest struct {
	Enabled        bool
	Frameworks     []string
	IsCustom       bool
	Labels         []string
	Limit          int
	Offset         int
	Scanners       []string
	Severities     []string
	SortBy         string
	SortOrder      int
	Categories     []string
	CloudProviders []string
	SubCategories  []string
}

func (r ListRequest) ToQueryValues() url.Values {
	result := url.Values{}

	result.Add("enabled", strconv.FormatBool(r.Enabled))
	for _, framework := range r.Frameworks {
		result.Add("frameworks", framework)
	}
	result.Add("isCustom", strconv.FormatBool(r.IsCustom))
	for _, label := range r.Labels {
		result.Add("labels", label)
	}
	if r.Limit > 0 {
		result.Add("limit", strconv.Itoa(r.Limit))
	}
	if r.Offset > 0 {
		result.Add("offset", strconv.Itoa(r.Offset))
	}
	for _, scanner := range r.Scanners {
		result.Add("scanners", scanner)
	}
	for _, severity := range r.Severities {
		result.Add("severities", severity)
	}
	// Only add sortBy if it's set (API rejects empty string)
	if r.SortBy != "" {
		result.Add("sortBy", r.SortBy)
	}
	// Only add sortOrder if it's non-zero (API requires -1 or 1, rejects 0)
	if r.SortOrder != 0 {
		result.Add("sortOrder", strconv.Itoa(r.SortOrder))
	}
	for _, category := range r.Categories {
		result.Add("categories", category)
	}
	for _, cloudProvider := range r.CloudProviders {
		result.Add("cloudProviders", cloudProvider)
	}
	for _, subCategory := range r.SubCategories {
		result.Add("subCategories", subCategory)
	}

	return result
}

// ListResponse handles the output for the List function.
//
// NextOffset is nil on the final page; otherwise it is the offset to send
// on the next list request to advance pagination.
type ListResponse struct {
	Offset     float64 `json:"offset"`
	NextOffset *int    `json:"nextOffset"`
	Rules      []Rule  `json:"rules"`
}

// UpdateRequest handles input for the Update function.
//
// The PATCH endpoint accepts a union type with two shapes:
//   - Labels-only update (for OOB rules): only "labels" is allowed.
//   - Full custom rule update: requires "name", "severity", "scanner",
//     "category", "subCategory", and "frameworks"; optionally accepts
//     "description" and "labels".
//
// Fields not accepted by the PATCH endpoint (e.g. cloudProvider, domain,
// findingCategory, isEnabled, owner, etc.) are intentionally excluded to
// prevent ValidateError responses from the API.
type UpdateRequest struct {
	Name        string          `json:"name,omitempty"`
	Severity    string          `json:"severity,omitempty"`
	Scanner     string          `json:"scanner,omitempty"`
	Category    string          `json:"category,omitempty"`
	SubCategory string          `json:"subCategory,omitempty"`
	Description string          `json:"description,omitempty"`
	Frameworks  []FrameworkData `json:"frameworks,omitempty"`
	Labels      []string        `json:"labels"`
	// CspmRuleId maps this custom rule to a Cloud Security (CSPM) rule.
	// Write-only: accepted on update, not returned on read. Omitted when empty.
	CspmRuleId *string `json:"cspmRuleId,omitempty"`
}

func (r Rule) ToUpdateRequest() UpdateRequest {
	var labels []string
	if r.Labels == nil {
		labels = []string{}
	} else {
		labels = *r.Labels
	}

	return UpdateRequest{
		Name:        r.Name,
		Severity:    r.Severity,
		Scanner:     r.Scanner,
		Category:    r.Category,
		SubCategory: r.SubCategory,
		Description: r.Description,
		Frameworks:  r.Frameworks,
		Labels:      labels,
	}
}

// UpdateResponse handles the output for the Update function.
type UpdateResponse struct {
	Rule Rule `json:"rule"`
}

// GetLabelsResponse contains the list of available rule labels.
type GetLabelsResponse struct {
	Labels []string `json:"labels"`
}
