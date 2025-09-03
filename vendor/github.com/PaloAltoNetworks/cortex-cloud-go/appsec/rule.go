// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	"dario.cat/mergo"
)

// ---------------------------
// Core structs
// ---------------------------

// Rule represents an Application Security rule.
type Rule struct {
	Category        string           `json:"category"`
	CloudProvider   string           `json:"cloudProvider"`
	CreatedAt       CreatedUpdatedAt `json:"createdAt"`
	Description     string           `json:"description"`
	DetectionMethod *string          `json:"detectionMethod"`
	DocLink         string           `json:"docLink"`
	Domain          string           `json:"domain"`
	FindingCategory string           `json:"findingCategory"`
	FindingDocs     string           `json:"findingDocs"`
	FindingTypeId   int              `json:"findingTypeId"`
	FindingTypeName string           `json:"findingTypeName"`
	Frameworks      []FrameworkData  `json:"frameworks"`
	Id              string           `json:"id"`
	IsCustom        bool             `json:"isCustom"`
	IsEnabled       bool             `json:"isEnabled"`
	Labels          *[]string        `json:"labels"`
	MitreTactics    []string         `json:"mitreTactics"`
	MitreTechniques []string         `json:"mitreTechniques"`
	Name            string           `json:"name"`
	Owner           string           `json:"owner"`
	Scanner         string           `json:"scanner"`
	Severity        string           `json:"severity"`
	Source          string           `json:"source"`
	SubCategory     string           `json:"subCategory"`
	UpdatedAt       CreatedUpdatedAt `json:"updatedAt"`
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

//func (f Framework) fromData(data FrameworkData) Framework {
//	return Framework{
//		Name:                   data.Name,
//		Definition:             data.Definition,
//		DefinitionLink:         data.DefinitionLink,
//		RemediationDescription: &data.RemediationDescription,
//	}
//}

// ---------------------------
// Request/Response structs
// ---------------------------
// TODO: make helper funcs for creating request structs

// FrameworkData represents a framework or language that the
// Application Security rule applies to.
type FrameworkData struct {
	Name                   string `json:"name"`
	Definition             string `json:"definition"`
	DefinitionLink         string `json:"definitionLink"`
	RemediationDescription string `json:"remediationDescription"`
}

// ValidateRequest handles input for the Validate function.
type ValidateRequest struct {
	Framework  string `json:"framework"`
	Definition string `json:"definition"`
}

//type ValidateRequest struct {
//	// TODO: need enum for Type
//	Type    string                 `json:"type" validate:"required"`
//	Payload ValidateRequestPayload `json:"payload" validate:"required"`
//}

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

func (r ListRequest) toQueryValues() url.Values {
	result := url.Values{}

	result.Add("enabled", strconv.FormatBool(r.Enabled))
	for _, framework := range r.Frameworks {
		result.Add("frameworks", framework)
	}
	result.Add("isCustom", strconv.FormatBool(r.IsCustom))
	for _, label := range r.Labels {
		result.Add("labels", label)
	}
	result.Add("limit", strconv.Itoa(r.Limit))
	result.Add("offset", strconv.Itoa(r.Offset))
	for _, scanner := range r.Scanners {
		result.Add("scanners", scanner)
	}
	for _, severity := range r.Severities {
		result.Add("severities", severity)
	}
	result.Add("sortBy", r.SortBy)
	result.Add("sortOrder", strconv.Itoa(r.SortOrder))
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
type ListResponse struct {
	Offset float64 `json:"offset"`
	Rules  []Rule  `json:"rules"`
}

// UpdateRequest handles input for the Update function.
type UpdateRequest struct {
	CloudProvider   string          `json:"cloudProvider,omitempty"`
	Category        string          `json:"category,omitempty"`
	Description     string          `json:"description,omitempty"`
	DocLink         string          `json:"docLink,omitempty"`
	Domain          string          `json:"domain,omitempty"`
	FindingCategory string          `json:"findingCategory,omitempty"`
	FindingDocs     string          `json:"findingDocs,omitempty"`
	FindingTypeId   int             `json:"findingTypeId,omitempty"`
	FindingTypeName string          `json:"findingTypeName,omitempty"`
	Frameworks      []FrameworkData `json:"frameworks,omitempty"`
	IsEnabled       bool            `json:"isEnabled,omitempty"`
	Labels          []string        `json:"labels"`
	MitreTactics    []string        `json:"mitreTactics,omitempty"`
	MitreTechniques []string        `json:"mitreTechniques,omitempty"`
	Name            string          `json:"name,omitempty"`
	Owner           string          `json:"owner,omitempty"`
	Scanner         string          `json:"scanner,omitempty"`
	Severity        string          `json:"severity,omitempty"`
	Source          string          `json:"source,omitempty"`
	//SourceVersion   *string      `json:"sourceVersion,omitempty"`
	SubCategory string `json:"subCategory,omitempty"`
}

func (r Rule) ToUpdateRequest() UpdateRequest{
	var labels []string
	if r.Labels == nil {
		labels = []string{}
	} else {
		labels = *r.Labels
	}

	return UpdateRequest{
		CloudProvider: r.CloudProvider,
		Category: r.Category,
		Description: r.Description,
		DocLink: r.DocLink,
		Domain: r.Domain,
		FindingCategory: r.FindingCategory,
		FindingDocs: r.FindingDocs,
		FindingTypeId: r.FindingTypeId,
		FindingTypeName: r.FindingTypeName,
		Frameworks: r.Frameworks,
		IsEnabled: r.IsEnabled,
		Labels: labels,
		MitreTactics: r.MitreTactics,
		MitreTechniques: r.MitreTechniques,
		Name: r.Name,
		Owner: r.Owner,
		Scanner: r.Scanner,
		Source: r.Source,
		SubCategory: r.SubCategory,
	}
}

// UpdateResponse handles the output for the Update function.
type UpdateResponse struct {
	Rule Rule `json:"rule"`
}

// ---------------------------
// Request functions
// ---------------------------

// FromCreateOrCloneRequest populates and returns a ValidateRequest using the
// values from the supplied CreateOrCloneRequest.
//func (r ValidateRequest) FromCreateOrCloneRequest(req CreateOrCloneRequest) (ValidateRequest, error) {
//	frameworksData := []FrameworkData{}
//	for _, framework := range req.Frameworks {
//		//var remediationDescription string
//		//if framework.RemediationDescription != nil {
//		//	remediationDescription = *framework.RemediationDescription
//		//} else {
//		//	remediationDescription = ""
//		//}
//
//		frameworksData = append(frameworksData, FrameworkData{
//			Name:           framework.Name,
//			Definition:     framework.Definition,
//			DefinitionLink: framework.DefinitionLink,
//			//RemediationDescription: remediationDescription,
//			RemediationDescription: framework.RemediationDescription,
//		})
//	}
//
//	validateRequest := ValidateRequest{
//		Type: "VALIDATE",
//		Payload: ValidateRequestPayload{
//			Name:           req.Name,
//			FrameworksData: frameworksData,
//			MetaData: ValidateRequestMetadata{
//				Name:       req.Name,
//				Severity:   req.Severity,
//				Category:   req.Category,
//				Guidelines: "",
//			},
//		},
//	}
//
//	return validateRequest, nil
//}

// FromUpdateRequest and returns a ValidateRequest using the values from the
// supplied UpdateRequest.
//func (r ValidateRequest) FromUpdateRequest(req UpdateRequest, ruleId string) (ValidateRequest, error) {
//	frameworksData := []FrameworkData{}
//	if req.Frameworks != nil {
//		for _, framework := range *req.Frameworks {
//			//var remediationDescription string
//			//if framework.RemediationDescription != nil {
//			//	remediationDescription = *framework.RemediationDescription
//			//} else {
//			//	remediationDescription = ""
//			//}
//
//			frameworksData = append(frameworksData, FrameworkData{
//				Name:           framework.Name,
//				Definition:     framework.Definition,
//				DefinitionLink: framework.DefinitionLink,
//				//RemediationDescription: remediationDescription,
//				RemediationDescription: framework.RemediationDescription,
//			})
//		}
//	}
//
//	validateRequest := ValidateRequest{
//		Type: "VALIDATE",
//		Payload: ValidateRequestPayload{
//			Name:           *req.Name,
//			FrameworksData: frameworksData,
//			RuleId:         ruleId,
//			MetaData: ValidateRequestMetadata{
//				Name:       *req.Name,
//				Severity:   *req.Severity,
//				Category:   *req.Category,
//				Guidelines: "",
//			},
//		},
//	}
//
//	return validateRequest, nil
//}

// Validate validates the Application Security rule definition and relevant
// properties to ensure that they align with what is expected by the Cortex
// Cloud API.
//
// This operation occurs within the Cortex Cloud platform as a prerequisite
// step during the rule creation/cloning operation. The purpose of this function
// is to allow for validation of the rule logic prior to executing the
// create/clone request, if users would like to handle any rule logic errors
// separately from any errors that may be raised for the other input values.
//
// The private version of this endpoint is called from the UI by clicking the
// "Validate Code" button in the rule definition creation screen.
//
// The `CreateOrCloneRequest` and `UpdateRequest` classes contain member
// functions (`FromCreateOrCloneRequest` and `FromUpdateRequest`, respectively)
// to easily generate the request payload.
func (c *Client) Validate(ctx context.Context, input []ValidateRequest) (ValidateResponse, error) {
	var ans ValidateResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, RulesValidationEndpoint, nil, nil, input, &ans)

	return ans, err
}

// CreateOrClone creates a new or clones an existing Application Security rule.
//
// (TODO: verify description)
// If an rule with the specified name already exists, that rule will be cloned
// and altered according to the remaining input values.
//
// Otherwise, a new rule will be created with the provided input values.
func (c *Client) CreateOrClone(ctx context.Context, input CreateOrCloneRequest) (Rule, error) {
	var ans Rule
	_, err := c.internalClient.Do(ctx, http.MethodPost, RulesEndpoint, nil, nil, input, &ans)

	return ans, err
}

// Get returns the details of the Application Security rule with the provided
// ID value.
func (c *Client) Get(ctx context.Context, id string) (Rule, error) {
	var ans Rule
	_, err := c.internalClient.Do(ctx, http.MethodGet, RulesEndpoint, &[]string{id}, nil, nil, &ans)

	return ans, err
}

// List retrieves a list of all Application Security rules that match the
// provided filter values.
//
// If no filter values are provided, all rules will be returned.
func (c *Client) List(ctx context.Context, input ListRequest) (ListResponse, error) {
	queryValues := input.toQueryValues()

	var ans ListResponse
	_, err := c.internalClient.Do(ctx, http.MethodGet, RulesEndpoint, nil, &queryValues, nil, &ans)

	return ans, err
}

// Update modifies an existing Application Security rule.
//
// If the target rule is an out-of-the-box rule, only the labels can be
// modified. For custom rules, all fields can be modified.
//
// To customize an out-of-the-box rule, first clone it using `CreateOrClone`,
// then use `Update` to set the desired configuration.
func (c *Client) Update(ctx context.Context, ruleId string, input UpdateRequest) (UpdateResponse, error) {
	var ans UpdateResponse

	rule, err := c.Get(ctx, ruleId)
	if err != nil {
		return ans, err
	}

	src := rule.ToUpdateRequest()

	if err := mergo.Merge(&input, src); err != nil {
		return ans, err
	}

	_, err = c.internalClient.Do(ctx, http.MethodPatch, RulesEndpoint, &[]string{ruleId}, nil, input, &ans)

	return ans, err
}

// Delete deletes the specified Application Security rule.
func (c *Client) Delete(ctx context.Context, id string) error {
	_, err := c.internalClient.Do(ctx, http.MethodDelete, RulesEndpoint, &[]string{id}, nil, nil, nil)

	return err
}
