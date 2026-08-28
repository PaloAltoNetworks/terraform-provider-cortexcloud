// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

// ----------------------------------------------------------------------------
// Standard
// ----------------------------------------------------------------------------

// Standard represents a compliance standard.
type Standard struct {
	ID                       string   `json:"id"`
	Name                     string   `json:"name"`
	Description              string   `json:"description"`
	Version                  string   `json:"version"`
	AssessmentsProfilesCount int      `json:"assessments_profiles_count"`
	ControlsIDs              []string `json:"controls_ids"`
	Labels                   []string `json:"labels"`
	Revision                 int64    `json:"revision"`
	Publisher                string   `json:"publisher"`
	ReleaseDate              string   `json:"release_date"`
	CreatedDate              string   `json:"created_date"`
	CreatedBy                string   `json:"created_by"`
	InsertTS                 int64    `json:"insert_ts"`
	ModifyTS                 int64    `json:"modify_ts"`
	IsCustom                 bool     `json:"is_custom"`
}

// CreateStandardRequest is the request for creating a standard.
type CreateStandardRequest struct {
	StandardName string   `json:"standard_name"`
	Description  string   `json:"description,omitempty"`
	Labels       []string `json:"labels,omitempty"`
	ControlsIDs  []string `json:"controls_ids,omitempty"`
}

// UpdateStandardRequest is the request for updating a standard.
type UpdateStandardRequest struct {
	ID           string   `json:"id"`
	StandardName string   `json:"standard_name,omitempty"`
	Description  string   `json:"description,omitempty"`
	Labels       []string `json:"labels"`       // API requires this field to always be present as a list
	ControlsIDs  []string `json:"controls_ids"` // API requires this field to always be present as a list
}

// DeleteStandardRequest is the request for deleting a standard.
type DeleteStandardRequest struct {
	ID string `json:"id"`
}

// GetStandardRequest is the request for getting a standard by ID.
type GetStandardRequest struct {
	ID string `json:"id"`
}

// GetStandardResponse is the response for getting a standard by ID.
type GetStandardResponse struct {
	Standards []Standard `json:"standard"` // Array to match API response (API uses singular "standard")
}

// ListStandardsRequest is the request for listing standards.
type ListStandardsRequest struct {
	Filters    []Filter    `json:"filters,omitempty"`
	Sort       *SortFilter `json:"sort,omitempty"`
	SearchFrom *int        `json:"search_from,omitempty"`
	SearchTo   *int        `json:"search_to,omitempty"`
}

// ListStandardsResponse is the response for listing standards.
type ListStandardsResponse struct {
	TotalCount  int        `json:"total_count"`
	ResultCount int        `json:"result_count"`
	Standards   []Standard `json:"standards"`
}
