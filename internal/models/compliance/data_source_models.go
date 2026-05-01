// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"strconv"
	"strings"

	complianceTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/compliance"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ControlsDataSourceModel is the model for the controls list data source.
type ControlsDataSourceModel struct {
	ID         types.String   `tfsdk:"id"`
	Filter     *FilterModel   `tfsdk:"filter"`
	SearchFrom types.Int64    `tfsdk:"search_from"`
	SearchTo   types.Int64    `tfsdk:"search_to"`
	Controls   []ControlModel `tfsdk:"controls"`
}

// StandardsDataSourceModel is the model for the standards list data source.
type StandardsDataSourceModel struct {
	ID         types.String    `tfsdk:"id"`
	Filter     *FilterModel    `tfsdk:"filter"`
	SearchFrom types.Int64     `tfsdk:"search_from"`
	SearchTo   types.Int64     `tfsdk:"search_to"`
	Standards  []StandardModel `tfsdk:"standards"`
}

// AssessmentProfilesDataSourceModel is the model for the assessment profiles list data source.
type AssessmentProfilesDataSourceModel struct {
	ID                 types.String             `tfsdk:"id"`
	Filter             *FilterModel             `tfsdk:"filter"`
	SearchFrom         types.Int64              `tfsdk:"search_from"`
	SearchTo           types.Int64              `tfsdk:"search_to"`
	AssessmentProfiles []AssessmentProfileModel `tfsdk:"assessment_profiles"`
}

// FilterModel represents a filter for list data sources.
type FilterModel struct {
	Field    types.String `tfsdk:"field"`
	Operator types.String `tfsdk:"operator"`
	Value    types.String `tfsdk:"value"`
}

// coerceFilterValue attempts to convert a string filter value to its appropriate
// Go type for JSON serialization. If the value can be parsed as an integer, it
// returns an int64 so that the JSON encoder emits a number (e.g., 1770000000000)
// instead of a string (e.g., "1770000000000"). This is required because the API
// rejects string values for numeric fields like insertion_time.
func coerceFilterValue(s string) interface{} {
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v
	}
	return s
}

// validateFilter checks that when a filter block is present, all 3 fields
// (field, operator, value) are provided. Returns true if the filter should be
// applied, false if it should be skipped (nil or all-null). Adds a diagnostic
// error if the filter is partially specified.
func validateFilter(filter *FilterModel, diags *diag.Diagnostics) bool {
	if filter == nil {
		return false
	}

	fieldSet := !filter.Field.IsNull() && !filter.Field.IsUnknown()
	operatorSet := !filter.Operator.IsNull() && !filter.Operator.IsUnknown()
	valueSet := !filter.Value.IsNull() && !filter.Value.IsUnknown()

	allSet := fieldSet && operatorSet && valueSet
	noneSet := !fieldSet && !operatorSet && !valueSet

	if noneSet {
		return false
	}

	if !allSet {
		var missing []string
		if !fieldSet {
			missing = append(missing, "field")
		}
		if !operatorSet {
			missing = append(missing, "operator")
		}
		if !valueSet {
			missing = append(missing, "value")
		}
		diags.AddError(
			"Incomplete Filter Configuration",
			"When specifying a filter block, all three attributes (field, operator, value) must be provided. "+
				"Missing: "+strings.Join(missing, ", ")+".",
		)
		return false
	}

	return true
}

// buildFilters validates the filter model and converts it to a slice of SDK
// Filter objects. Returns nil if no filter is configured or if validation fails
// (in which case a diagnostic error is added). This centralises the filter
// building logic shared by all compliance list data sources.
func buildFilters(ctx context.Context, filter *FilterModel, diags *diag.Diagnostics) []complianceTypes.Filter {
	if !validateFilter(filter, diags) {
		return nil
	}

	filterValue := filter.Value.ValueString()
	var apiValue interface{} = coerceFilterValue(filterValue)
	operator := filter.Operator.ValueString()

	// API workaround: The is_custom field only accepts the "in" operator,
	// not "eq". Automatically convert eq → in so users don't hit the
	// confusing API 500 error. The "in" operator requires an array value.
	fieldLower := strings.ToLower(filter.Field.ValueString())
	if fieldLower == "is_custom" && strings.ToLower(operator) == "eq" {
		tflog.Warn(ctx, "Automatically converting is_custom filter operator from 'eq' to 'in' due to API limitation")
		diags.AddWarning(
			"Filter operator automatically adjusted",
			"The Cortex Cloud API does not support the 'eq' operator for the 'is_custom' field. "+
				"The operator has been automatically changed to 'in' which provides equivalent functionality. "+
				"To suppress this warning, use operator = \"in\" in your filter configuration.",
		)
		operator = "in"
	}

	// For 'in' operator, API expects array not string
	if strings.ToLower(operator) == "in" {
		apiValue = []string{filterValue}
	}

	// API bug workaround: The labels field advertises "eq" as the allowed
	// operator but rejects it at runtime. The "contains" operator is the
	// one that actually works for labels filtering. Automatically convert
	// eq → contains so users don't hit the confusing API error.
	if fieldLower == "labels" && strings.ToLower(operator) == "eq" {
		tflog.Warn(ctx, "Automatically converting labels filter operator from 'eq' to 'contains' due to API limitation")
		diags.AddWarning(
			"Labels filter operator automatically adjusted",
			"The Cortex Cloud API does not support the 'eq' operator for the 'labels' field despite advertising it. "+
				"The operator has been automatically changed to 'contains' which provides equivalent functionality. "+
				"To suppress this warning, use operator = \"contains\" in your filter configuration.",
		)
		operator = "contains"
		// The contains operator requires a plain string value, not a numeric coercion
		apiValue = filterValue
	}

	return []complianceTypes.Filter{
		{
			Field:    filter.Field.ValueString(),
			Operator: operator,
			Value:    apiValue,
		},
	}
}

// ToListControlsRequest converts the data source model to an SDK list request.
func (m *ControlsDataSourceModel) ToListRequest(ctx context.Context, diags *diag.Diagnostics) complianceTypes.ListControlsRequest {
	tflog.Debug(ctx, "Converting controls data source model to list request")

	req := complianceTypes.ListControlsRequest{
		SearchFrom: int(m.SearchFrom.ValueInt64()),
		SearchTo:   int(m.SearchTo.ValueInt64()),
	}

	req.Filters = buildFilters(ctx, m.Filter, diags)

	return req
}

// RefreshFromRemote updates the data source model from the SDK response.
func (m *ControlsDataSourceModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote []complianceTypes.Control) {
	tflog.Debug(ctx, "Refreshing controls data source model from remote")

	m.ID = types.StringValue("compliance_controls")

	m.Controls = make([]ControlModel, len(remote))
	for i, control := range remote {
		m.Controls[i].RefreshFromRemote(ctx, diags, &control)
		if diags.HasError() {
			return
		}
	}
}

// ToListStandardsRequest converts the data source model to an SDK list request.
func (m *StandardsDataSourceModel) ToListRequest(ctx context.Context, diags *diag.Diagnostics) complianceTypes.ListStandardsRequest {
	tflog.Debug(ctx, "Converting standards data source model to list request")

	req := complianceTypes.ListStandardsRequest{
		Pagination: &complianceTypes.Pagination{
			SearchFrom: int(m.SearchFrom.ValueInt64()),
			SearchTo:   int(m.SearchTo.ValueInt64()),
		},
	}

	req.Filters = buildFilters(ctx, m.Filter, diags)

	return req
}

// RefreshFromRemote updates the data source model from the SDK response.
func (m *StandardsDataSourceModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote []complianceTypes.Standard) {
	tflog.Debug(ctx, "Refreshing standards data source model from remote")

	m.ID = types.StringValue("compliance_standards")

	m.Standards = make([]StandardModel, len(remote))
	for i, standard := range remote {
		m.Standards[i].RefreshFromRemote(ctx, diags, &standard)
		if diags.HasError() {
			return
		}
	}
}

// ToListAssessmentProfilesRequest converts the data source model to an SDK list request.
func (m *AssessmentProfilesDataSourceModel) ToListRequest(ctx context.Context, diags *diag.Diagnostics) complianceTypes.ListAssessmentProfilesRequest {
	tflog.Debug(ctx, "Converting assessment profiles data source model to list request")

	req := complianceTypes.ListAssessmentProfilesRequest{
		Pagination: &complianceTypes.Pagination{
			SearchFrom: int(m.SearchFrom.ValueInt64()),
			SearchTo:   int(m.SearchTo.ValueInt64()),
		},
	}

	req.Filters = buildFilters(ctx, m.Filter, diags)

	return req
}

// RefreshFromRemote updates the data source model from the SDK response.
func (m *AssessmentProfilesDataSourceModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote []complianceTypes.AssessmentProfile) {
	tflog.Debug(ctx, "Refreshing assessment profiles data source model from remote")

	m.ID = types.StringValue("compliance_assessment_profiles")

	m.AssessmentProfiles = make([]AssessmentProfileModel, len(remote))
	for i, profile := range remote {
		m.AssessmentProfiles[i].RefreshFromRemote(ctx, diags, &profile)
		if diags.HasError() {
			return
		}
	}
}
