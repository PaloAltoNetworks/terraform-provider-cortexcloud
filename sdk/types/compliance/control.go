// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

// ----------------------------------------------------------------------------
// Control
// ----------------------------------------------------------------------------

// Control represents a compliance control.
type Control struct {
	ID                     string   `json:"CONTROL_ID"`
	Name                   string   `json:"CONTROL_NAME"`
	Description            string   `json:"DESCRIPTION"`
	Category               string   `json:"CATEGORY"`
	CategoryDescription    string   `json:"CATEGORY_DESCRIPTION"`
	Subcategory            string   `json:"SUBCATEGORY"`
	SubcategoryDescription string   `json:"SUBCATEGORY_DESCRIPTION"`
	Standards              []string `json:"STANDARDS"`
	Severity               string   `json:"SEVERITY"`
	Supported              bool     `json:"SUPPORTED"`
	InsertionTime          int64    `json:"INSERTION_TIME"`
	ModificationTime       int64    `json:"MODIFICATION_TIME"`
	ModifiedBy             *string  `json:"MODIFIED_BY"`
	CreatedBy              string   `json:"CREATED_BY"`
	Mitigation             *string  `json:"MITIGATION"`
	AdditionalData         []any    `json:"ADDITIONAL_DATA"`
	ComplianceRules        []any    `json:"COMPLIANCE_RULES"`
	Rules                  int      `json:"RULES"`
	Revision               string   `json:"REVISION"`
	Impact                 *string  `json:"IMPACT"`
	AutomationStatus       string   `json:"AUTOMATION_STATUS"`
	AuditProcedure         *string  `json:"AUDIT_PROCEDURE"`
	Enabled                bool     `json:"ENABLED"`
	IsCustom               bool     `json:"IS_CUSTOM"`
	Status                 string   `json:"STATUS"`
}

// CreateControlResponse is the response for creating a control.
type CreateControlResponse struct {
	Success   bool   `json:"success"`
	ControlID string `json:"control_id"`
}

// CreateControlRequest is the request for creating a control.
type CreateControlRequest struct {
	ControlName string `json:"control_name"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category"`
	Subcategory string `json:"subcategory"`
}

// UpdateControlRequest is the request for updating a control.
type UpdateControlRequest struct {
	ID          string `json:"id"`
	ControlName string `json:"control_name,omitempty"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
	Subcategory string `json:"subcategory,omitempty"`
}

// DeleteControlRequest is the request for deleting a control.
type DeleteControlRequest struct {
	ID string `json:"id"`
}

// GetControlRequest is the request for getting a control by ID.
type GetControlRequest struct {
	ID string `json:"id"`
}

// GetControlResponse is the response for getting a control by ID.
// The API returns the control wrapped in an array.
type GetControlResponse struct {
	Control []Control `json:"control"`
}

// ListControlsRequest is the request for listing controls.
type ListControlsRequest struct {
	Filters    []Filter    `json:"filters,omitempty"`
	Sort       *SortFilter `json:"sort,omitempty"`
	SearchFrom *int        `json:"search_from,omitempty"`
	SearchTo   *int        `json:"search_to,omitempty"`
}

// ListControlsResponse is the response for listing controls.
type ListControlsResponse struct {
	TotalCount  int       `json:"total_count"`
	ResultCount int       `json:"result_count"`
	Controls    []Control `json:"controls"`
}
