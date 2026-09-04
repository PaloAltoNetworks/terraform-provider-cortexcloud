// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

// QueryRequest represents the query object for a detection rule.
type QueryRequest struct {
	XQL string `json:"xql"`
}

// QueryResponse represents the query object in a rule response.
type QueryResponse struct {
	XQL string `json:"xql"`
}

// IssueRequest represents issue information in metadata.
type IssueRequest struct {
	Recommendation string `json:"recommendation,omitempty"` // Optional in request
}

// IssueResponse represents issue information in a response.
type IssueResponse struct {
	Recommendation string `json:"recommendation"`
}

// MetadataRequest represents metadata for a rule request.
type MetadataRequest struct {
	Issue *IssueRequest `json:"issue,omitempty"` // Optional in request
}

// MetadataResponse represents metadata in a rule response.
type MetadataResponse struct {
	Issue *IssueResponse `json:"issue"`
}

// ComplianceMetadata represents full compliance metadata in a response.
type ComplianceMetadata struct {
	StandardID   string `json:"standard_id"`
	StandardName string `json:"standard_name"`
	ControlID    string `json:"control_id"`
	ControlName  string `json:"control_name"`
}

// ComplianceMetadataInput represents compliance metadata for rule create/update requests.
// Only control_id is required — the API resolves standard_name and control_name automatically.
type ComplianceMetadataInput struct {
	ControlID  string `json:"control_id"`
	StandardID string `json:"standard_id,omitempty"`
}

// CreateRuleRequest represents the request body for creating a detection rule.
// Note: The API accepts compliance mappings via the "compliance_metadata" field
// as an array of objects with "control_id" (required) and "standard_id" (optional).
// GET responses return enriched compliance_metadata with resolved names.
type CreateRuleRequest struct {
	Name               string                    `json:"name"`
	Description        string                    `json:"description,omitempty"`
	Class              string                    `json:"rule_class"`
	Type               string                    `json:"type,omitempty"`
	AssetTypes         []string                  `json:"asset_types"`
	Severity           string                    `json:"severity"`
	Query              QueryRequest              `json:"query"`
	Metadata           *MetadataRequest          `json:"metadata,omitempty"`
	ComplianceMetadata []ComplianceMetadataInput `json:"compliance_metadata,omitempty"`
	Labels             []string                  `json:"labels,omitempty"`
	Enabled            *bool                     `json:"enabled,omitempty"`
}

// UpdateRuleRequest represents the request body for updating a detection rule.
// All fields are optional for partial updates.
// Note: The API accepts compliance mappings via the "compliance_metadata" field
// as an array of objects with "control_id" (required) and "standard_id" (optional).
// GET responses return enriched compliance_metadata with resolved names.
type UpdateRuleRequest struct {
	Name               string                    `json:"name,omitempty"`
	Description        string                    `json:"description,omitempty"`
	Class              string                    `json:"rule_class,omitempty"`
	Type               string                    `json:"type,omitempty"`
	AssetTypes         []string                  `json:"asset_types,omitempty"`
	Severity           string                    `json:"severity,omitempty"`
	Query              *QueryResponse            `json:"query,omitempty"`
	Metadata           *MetadataRequest          `json:"metadata,omitempty"`
	ComplianceMetadata []ComplianceMetadataInput `json:"compliance_metadata,omitempty"`
	Labels             []string                  `json:"labels,omitempty"`
	Enabled            *bool                     `json:"enabled,omitempty"`
}

// RuleResponse represents the response for rule operations.
type RuleResponse struct {
	ID                 string               `json:"id"`
	Name               string               `json:"name"`
	Description        string               `json:"description"`
	Class              string               `json:"rule_class"`
	Type               string               `json:"type"`
	Providers          []string             `json:"providers"`
	AssetTypes         []string             `json:"asset_types"`
	Severity           string               `json:"severity"`
	Query              *QueryResponse       `json:"query"`
	Metadata           *MetadataResponse    `json:"metadata"`
	ComplianceMetadata []ComplianceMetadata `json:"compliance_metadata"`
	Labels             []string             `json:"labels"`
	Enabled            bool                 `json:"enabled"`
	SystemDefault      bool                 `json:"system_default"`
	CreatedBy          string               `json:"created_by"`
	CreatedOn          int64                `json:"created_on"`
	LastModifiedBy     string               `json:"last_modified_by"`
	LastModifiedOn     int64                `json:"last_modified_on"`
	Deleted            bool                 `json:"deleted"`
	DeletedAt          int64                `json:"deleted_at"`
	DeletedBy          string               `json:"deleted_by"`
}

// FilterCriteria represents filter criteria supporting AND/OR logical operations.
type FilterCriteria struct {
	AND         []FilterCriteria `json:"AND,omitempty"`
	OR          []FilterCriteria `json:"OR,omitempty"`
	SearchField string           `json:"SEARCH_FIELD,omitempty"`
	SearchType  string           `json:"SEARCH_TYPE,omitempty"`
	SearchValue any              `json:"SEARCH_VALUE,omitempty"`
}

// SortCriteria represents sort criteria for search results.
type SortCriteria struct {
	Field string `json:"FIELD"`
	Order string `json:"ORDER,omitempty"` // Use enums.SortOrder values: "ASC" or "DESC"
}

// SearchRulesRequest represents the request body for searching detection rules.
type SearchRulesRequest struct {
	Filter     *FilterCriteria `json:"filter,omitempty"`
	SearchFrom int32           `json:"search_from,omitempty"`
	SearchTo   int32           `json:"search_to,omitempty"`
	Sort       []SortCriteria  `json:"sort,omitempty"`
}

// RuleData represents the configuration for an individual detection rule in search results.
type RuleData struct {
	ID                  string               `json:"id"`                             // Required
	Name                string               `json:"name"`                           // Required
	Description         string               `json:"description"`                    // Required
	Class               string               `json:"rule_class"`                     // Required
	Type                string               `json:"type"`                           // Required
	AssetTypes          []string             `json:"asset_types,omitempty"`          // Optional array
	Severity            string               `json:"severity"`                       // Required - use enums.CloudSecSeverity values
	Enabled             bool                 `json:"enabled"`                        // Required
	SystemDefault       bool                 `json:"system_default"`                 // Required
	Providers           []string             `json:"providers,omitempty"`            // Optional array
	ComplianceMetadata  []ComplianceMetadata `json:"compliance_metadata,omitempty"`  // Optional array
	ComplianceStandards []string             `json:"compliance_standards,omitempty"` // Optional array
	Labels              []string             `json:"labels,omitempty"`               // Optional array
	CreatedBy           string               `json:"created_by"`                     // Required
	CreatedOn           int64                `json:"created_on"`                     // Required
	LastModifiedBy      string               `json:"last_modified_by"`               // Required
	LastModifiedOn      int64                `json:"last_modified_on"`               // Required
	Module              string               `json:"module"`                         // Required
}

// SearchMetadata represents metadata about the search response.
type SearchMetadata struct {
	FilterCount int64 `json:"filter_count"`
	TotalCount  int64 `json:"total_count"`
}

// SearchRulesResponse represents the response for searching detection rules.
type SearchRulesResponse struct {
	Data     []RuleData     `json:"data"`
	Metadata SearchMetadata `json:"metadata"`
}
