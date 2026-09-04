// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

// ----------------------------------------------------------------------------
// Assessment Profile
// ----------------------------------------------------------------------------

// AssessmentProfile represents a compliance assessment profile.
type AssessmentProfile struct {
	ID              string   `json:"ID"`
	Name            string   `json:"NAME"`
	StandardID      string   `json:"STANDARD_ID"`
	StandardName    string   `json:"STANDARD_NAME"`
	AssetGroupID    int      `json:"ASSET_GROUP_ID"`
	AssetGroupName  string   `json:"ASSET_GROUP_NAME"`
	Description     string   `json:"DESCRIPTION"`
	ReportFrequency *string  `json:"REPORT_FREQUENCY"`
	ReportTargets   []string `json:"REPORT_TARGETS"`
	ReportType      string   `json:"REPORT_TYPE"`
	Enabled         bool     `json:"ENABLED"`
	InsertTS        int64    `json:"INSERT_TS"`
	ModifyTS        int64    `json:"MODIFY_TS"`
	CreatedBy       string   `json:"CREATED_BY"`
	ModifiedBy      string   `json:"MODIFIED_BY"`
}

// CreateAssessmentProfileRequest is the request for creating an assessment profile.
type CreateAssessmentProfileRequest struct {
	ProfileName         string   `json:"profile_name"`
	AssetGroupID        string   `json:"asset_group_id"`
	StandardID          string   `json:"standard_id"`
	Description         string   `json:"description,omitempty"`
	ReportTargets       []string `json:"report_targets,omitempty"`
	ReportType          string   `json:"report_type,omitempty"`
	EvaluationFrequency string   `json:"evaluation_frequency,omitempty"`
}

// UpdateAssessmentProfileRequest is the request for updating an assessment profile.
type UpdateAssessmentProfileRequest struct {
	ID                  string   `json:"id"`
	ProfileName         string   `json:"profile_name,omitempty"`
	AssetGroupID        string   `json:"asset_group_id,omitempty"`
	StandardID          string   `json:"standard_id,omitempty"`
	Description         string   `json:"description,omitempty"`
	ReportTargets       []string `json:"report_targets,omitempty"`
	ReportType          string   `json:"report_type,omitempty"`
	EvaluationFrequency string   `json:"evaluation_frequency,omitempty"`
	Enabled             string   `json:"enabled,omitempty"` // "yes" or "no"
}

// DeleteAssessmentProfileRequest is the request for deleting an assessment profile.
type DeleteAssessmentProfileRequest struct {
	ID string `json:"id"`
}

// GetAssessmentProfileRequest is the request for getting an assessment profile by ID.
type GetAssessmentProfileRequest struct {
	ID string `json:"id"`
}

// GetAssessmentProfileResponse is the response for getting an assessment profile by ID.
type GetAssessmentProfileResponse struct {
	AssessmentProfiles []AssessmentProfile `json:"assessment_profile"` // Array to match API response (API uses singular "assessment_profile")
}

// ListAssessmentProfilesRequest is the request for listing assessment profiles.
type ListAssessmentProfilesRequest struct {
	Filters    []Filter    `json:"filters,omitempty"`
	Sort       *SortFilter `json:"sort,omitempty"`
	SearchFrom *int        `json:"search_from,omitempty"`
	SearchTo   *int        `json:"search_to,omitempty"`
}

// Filter represents a filter condition for compliance API queries.
type Filter struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    any    `json:"value"`
}

// SortFilter represents sorting configuration.
type SortFilter struct {
	Field   string `json:"field"`
	Keyword string `json:"keyword"` // "asc" or "desc"
}

// ListAssessmentProfilesResponse is the response for listing assessment profiles.
type ListAssessmentProfilesResponse struct {
	TotalCount         int                 `json:"total_count"`
	ResultCount        int                 `json:"result_count"`
	AssessmentProfiles []AssessmentProfile `json:"assessment_profiles"`
}

// Pagination is retained as a no-op deprecation shim. The compliance
// List*Request structs no longer wrap pagination in a nested object; set
// SearchFrom and SearchTo on the request directly instead.
//
// Deprecated: use ListAssessmentProfilesRequest.SearchFrom / .SearchTo (and
// the equivalent root-level fields on ListStandardsRequest and
// ListControlsRequest). This type will be removed in a future major release.
type Pagination struct {
	SearchFrom int `json:"search_from,omitempty"`
	SearchTo   int `json:"search_to,omitempty"`
}
