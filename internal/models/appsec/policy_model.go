// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"reflect"

	appsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/appsec"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ---------------------------
// Trigger object type maps
// ---------------------------
//
// The AppSec Policy API requires five trigger blocks on every CREATE/UPDATE:
// periodic, pr, cicd, ciImage, imageRegistry. Each trigger has its own subset
// of allowed `actions` keys. The provider exposes them as five separate
// SingleNestedAttribute attributes so that users can configure them with
// strong typing. Omitted triggers default to {enabled=false, all actions=false}.

// PeriodicTriggerActionsAttrTypes describes the action sub-block for the
// `periodic` trigger.
var PeriodicTriggerActionsAttrTypes = map[string]attr.Type{
	"report_issue": types.BoolType,
}

// PRTriggerActionsAttrTypes describes the action sub-block for the `pr` trigger.
var PRTriggerActionsAttrTypes = map[string]attr.Type{
	"report_issue":      types.BoolType,
	"block_pr":          types.BoolType,
	"report_pr_comment": types.BoolType,
}

// CICDTriggerActionsAttrTypes describes the action sub-block for the `cicd`
// trigger.
var CICDTriggerActionsAttrTypes = map[string]attr.Type{
	"report_issue": types.BoolType,
	"block_cicd":   types.BoolType,
	"report_cicd":  types.BoolType,
}

// CIImageTriggerActionsAttrTypes describes the action sub-block for the
// `ciImage` trigger.
var CIImageTriggerActionsAttrTypes = map[string]attr.Type{
	"report_issue": types.BoolType,
	"report_cicd":  types.BoolType,
	"block_cicd":   types.BoolType,
}

// ImageRegistryTriggerActionsAttrTypes describes the action sub-block for the
// `imageRegistry` trigger.
var ImageRegistryTriggerActionsAttrTypes = map[string]attr.Type{
	"report_issue": types.BoolType,
}

// triggerObjectAttrTypes returns the full Object type for one trigger block,
// embedding the per-trigger actions schema.
func triggerObjectAttrTypes(actionsTypes map[string]attr.Type) map[string]attr.Type {
	return map[string]attr.Type{
		"enabled":                 types.BoolType,
		"override_issue_severity": types.StringType,
		"actions":                 types.ObjectType{AttrTypes: actionsTypes},
	}
}

// PeriodicTriggerAttrTypes is the full type map for periodic_trigger.
var PeriodicTriggerAttrTypes = triggerObjectAttrTypes(PeriodicTriggerActionsAttrTypes)

// PRTriggerAttrTypes is the full type map for pr_trigger.
var PRTriggerAttrTypes = triggerObjectAttrTypes(PRTriggerActionsAttrTypes)

// CICDTriggerAttrTypes is the full type map for cicd_trigger.
var CICDTriggerAttrTypes = triggerObjectAttrTypes(CICDTriggerActionsAttrTypes)

// CIImageTriggerAttrTypes is the full type map for ci_image_trigger.
var CIImageTriggerAttrTypes = triggerObjectAttrTypes(CIImageTriggerActionsAttrTypes)

// ImageRegistryTriggerAttrTypes is the full type map for image_registry_trigger.
var ImageRegistryTriggerAttrTypes = triggerObjectAttrTypes(ImageRegistryTriggerActionsAttrTypes)

// ---------------------------
// PolicyModel
// ---------------------------

// PolicyModel is the Terraform model for an AppSec policy.
// Note: conditions and scope are stored as JSON strings due to deep nesting
// complexity (up to 10 levels). Triggers are exposed as five strongly-typed
// nested objects (one per trigger type) since each has a fixed shape.
type PolicyModel struct {
	ID                          types.String  `tfsdk:"id"`
	Name                        types.String  `tfsdk:"name"`
	Description                 types.String  `tfsdk:"description"`
	Status                      types.String  `tfsdk:"status"`
	IsCustom                    types.Bool    `tfsdk:"is_custom"`
	Conditions                  types.String  `tfsdk:"conditions"` // JSON string
	Scope                       types.String  `tfsdk:"scope"`      // JSON string
	AssetGroupIds               types.List    `tfsdk:"asset_group_ids"`
	PeriodicTrigger             types.Object  `tfsdk:"periodic_trigger"`
	PRTrigger                   types.Object  `tfsdk:"pr_trigger"`
	CICDTrigger                 types.Object  `tfsdk:"cicd_trigger"`
	CIImageTrigger              types.Object  `tfsdk:"ci_image_trigger"`
	ImageRegistryTrigger        types.Object  `tfsdk:"image_registry_trigger"`
	DeveloperSuppressionAffects types.Bool    `tfsdk:"developer_suppression_affects"`
	OverrideIssueSeverity       types.String  `tfsdk:"override_issue_severity"`
	CreatedBy                   types.String  `tfsdk:"created_by"`
	DateCreated                 types.String  `tfsdk:"date_created"`
	ModifiedBy                  types.String  `tfsdk:"modified_by"`
	DateModified                types.String  `tfsdk:"date_modified"`
	Version                     types.Float64 `tfsdk:"version"`
}

// RefreshFromRemote updates the Terraform model from the SDK response.
func (m *PolicyModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *appsecTypes.Policy) {
	tflog.Debug(ctx, "Refreshing appsec policy model from remote")

	if remote == nil {
		diags.AddError("AppSec Policy Not Found", "The requested AppSec policy does not exist.")
		return
	}

	m.ID = types.StringValue(remote.ID)
	m.Name = types.StringValue(remote.Name)
	m.Description = types.StringValue(remote.Description)
	m.Status = types.StringValue(remote.Status)
	m.IsCustom = types.BoolValue(remote.IsCustom)
	m.DeveloperSuppressionAffects = types.BoolValue(remote.DeveloperSuppressionAffects)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.DateCreated = types.StringValue(remote.DateCreated)
	m.ModifiedBy = types.StringValue(remote.ModifiedBy)
	m.DateModified = types.StringValue(remote.DateModified)
	m.Version = types.Float64Value(remote.Version)

	// Handle optional override severity
	if remote.OverrideIssueSeverity != nil {
		m.OverrideIssueSeverity = types.StringValue(*remote.OverrideIssueSeverity)
	} else {
		m.OverrideIssueSeverity = types.StringNull()
	}

	// Convert conditions to JSON, preserving user's string when semantically equal
	conditionsJSON, err := json.Marshal(remote.Conditions)
	if err != nil {
		diags.AddError("Error Marshaling Conditions", err.Error())
		return
	}
	m.Conditions = preserveJSONIfEqual(m.Conditions, string(conditionsJSON))

	// Convert scope to JSON (optional), preserving user's string when semantically equal
	if remote.Scope != nil {
		scopeJSON, err := json.Marshal(remote.Scope)
		if err != nil {
			diags.AddError("Error Marshaling Scope", err.Error())
			return
		}
		m.Scope = preserveJSONIfEqual(m.Scope, string(scopeJSON))
	} else {
		m.Scope = types.StringNull()
	}

	// Build the five trigger objects from the SDK response.
	m.PeriodicTrigger = triggerToObject(diags, remote.Triggers.Periodic, PeriodicTriggerAttrTypes,
		buildPeriodicActionsObject)
	m.PRTrigger = triggerToObject(diags, remote.Triggers.PR, PRTriggerAttrTypes,
		buildPRActionsObject)
	m.CICDTrigger = triggerToObject(diags, remote.Triggers.CICD, CICDTriggerAttrTypes,
		buildCICDActionsObject)
	m.CIImageTrigger = triggerToObject(diags, remote.Triggers.CIImage, CIImageTriggerAttrTypes,
		buildCIImageActionsObject)
	m.ImageRegistryTrigger = triggerToObject(diags, remote.Triggers.ImageRegistry, ImageRegistryTriggerAttrTypes,
		buildImageRegistryActionsObject)
	if diags.HasError() {
		return
	}

	// Convert asset_group_ids
	if len(remote.AssetGroupIds) == 0 {
		m.AssetGroupIds = types.ListValueMust(types.Int64Type, []attr.Value{})
	} else {
		elements := make([]attr.Value, len(remote.AssetGroupIds))
		for i, id := range remote.AssetGroupIds {
			elements[i] = types.Int64Value(int64(id))
		}
		listValue, listDiags := types.ListValue(types.Int64Type, elements)
		diags.Append(listDiags...)
		if diags.HasError() {
			return
		}
		m.AssetGroupIds = listValue
	}
}

// ToCreateRequest converts the Terraform model to an SDK create request.
func (m *PolicyModel) ToCreateRequest(ctx context.Context, diags *diag.Diagnostics) appsecTypes.CreatePolicyRequest {
	tflog.Debug(ctx, "Converting policy model to create request")

	req := appsecTypes.CreatePolicyRequest{
		Name:        m.Name.ValueString(),
		Description: m.Description.ValueString(),
	}

	// Parse conditions JSON
	if !m.Conditions.IsNull() && !m.Conditions.IsUnknown() {
		var conditions appsecTypes.PolicyCondition
		if err := json.Unmarshal([]byte(m.Conditions.ValueString()), &conditions); err != nil {
			diags.AddError("Error Parsing Conditions", err.Error())
			return req
		}
		req.Conditions = conditions
	}

	// Parse scope JSON (optional in Terraform, but required by the API).
	// If the user doesn't provide scope, send an empty scope object.
	if !m.Scope.IsNull() && !m.Scope.IsUnknown() {
		var scope appsecTypes.PolicyScope
		if err := json.Unmarshal([]byte(m.Scope.ValueString()), &scope); err != nil {
			diags.AddError("Error Parsing Scope", err.Error())
			return req
		}
		req.Scope = &scope
	} else {
		// API requires scope even when empty — send an empty scope object.
		req.Scope = &appsecTypes.PolicyScope{}
	}

	// Build all five triggers. Omitted triggers fall back to canonical defaults
	// (isEnabled=false, all actions=false). The API requires every trigger key
	// to be present on CREATE/UPDATE.
	req.Triggers = m.buildSDKTriggers(ctx, diags)
	if diags.HasError() {
		return req
	}

	// Convert asset_group_ids
	if !m.AssetGroupIds.IsNull() && !m.AssetGroupIds.IsUnknown() {
		var ids []int64
		diags.Append(m.AssetGroupIds.ElementsAs(ctx, &ids, false)...)
		if diags.HasError() {
			return req
		}
		req.AssetGroupIds = make([]int, len(ids))
		for i, id := range ids {
			req.AssetGroupIds[i] = int(id)
		}
	}

	// NOTE: developerSuppressionAffects is NOT sent on CREATE.
	// The POST endpoint rejects it as an excess property. It can only be
	// set via the UPDATE (PUT) endpoint after the policy is created.

	return req
}

// ToUpdateRequest converts the Terraform model to an SDK update request.
func (m *PolicyModel) ToUpdateRequest(ctx context.Context, diags *diag.Diagnostics) appsecTypes.UpdatePolicyRequest {
	tflog.Debug(ctx, "Converting policy model to update request")

	req := appsecTypes.UpdatePolicyRequest{}

	// Set name
	name := m.Name.ValueString()
	req.Name = &name

	// Set description
	desc := m.Description.ValueString()
	req.Description = &desc

	// Set enabled status
	enabled := m.Status.ValueString() == "enabled"
	req.Enabled = &enabled

	// Parse conditions JSON
	if !m.Conditions.IsNull() && !m.Conditions.IsUnknown() {
		var conditions appsecTypes.PolicyCondition
		if err := json.Unmarshal([]byte(m.Conditions.ValueString()), &conditions); err != nil {
			diags.AddError("Error Parsing Conditions", err.Error())
			return req
		}
		req.Conditions = &conditions
	}

	// Parse scope JSON (optional)
	if !m.Scope.IsNull() && !m.Scope.IsUnknown() {
		var scope appsecTypes.PolicyScope
		if err := json.Unmarshal([]byte(m.Scope.ValueString()), &scope); err != nil {
			diags.AddError("Error Parsing Scope", err.Error())
			return req
		}
		req.Scope = &scope
	}

	// Build all five triggers.
	triggers := m.buildSDKTriggers(ctx, diags)
	if diags.HasError() {
		return req
	}
	req.Triggers = &triggers

	// Convert asset_group_ids
	if !m.AssetGroupIds.IsNull() && !m.AssetGroupIds.IsUnknown() {
		var ids []int64
		diags.Append(m.AssetGroupIds.ElementsAs(ctx, &ids, false)...)
		if diags.HasError() {
			return req
		}
		req.AssetGroupIds = make([]int, len(ids))
		for i, id := range ids {
			req.AssetGroupIds[i] = int(id)
		}
	}

	// NOTE: Do NOT send developerSuppressionAffects on PUT. The API rejects it
	// as an excess property (same as POST). This is a server-computed field.

	return req
}

// ---------------------------
// Trigger conversion helpers (model <-> SDK)
// ---------------------------

// buildSDKTriggers assembles the five-trigger PolicyTriggers SDK struct from
// the model. Any null/unknown trigger is emitted with canonical defaults
// (isEnabled=false, all actions=false) so the API never rejects the request
// for missing keys.
func (m *PolicyModel) buildSDKTriggers(ctx context.Context, diags *diag.Diagnostics) appsecTypes.PolicyTriggers {
	return appsecTypes.PolicyTriggers{
		Periodic:      objectToTriggerConfig(ctx, diags, m.PeriodicTrigger, parsePeriodicActions),
		PR:            objectToTriggerConfig(ctx, diags, m.PRTrigger, parsePRActions),
		CICD:          objectToTriggerConfig(ctx, diags, m.CICDTrigger, parseCICDActions),
		CIImage:       objectToTriggerConfig(ctx, diags, m.CIImageTrigger, parseCIImageActions),
		ImageRegistry: objectToTriggerConfig(ctx, diags, m.ImageRegistryTrigger, parseImageRegistryActions),
	}
}

// objectToTriggerConfig converts a single trigger types.Object to the SDK's
// PolicyTriggerConfig. Null/unknown objects produce zero-valued configs.
func objectToTriggerConfig(
	ctx context.Context,
	diags *diag.Diagnostics,
	obj types.Object,
	parseActions func(context.Context, *diag.Diagnostics, types.Object) appsecTypes.TriggerActions,
) appsecTypes.PolicyTriggerConfig {
	if obj.IsNull() || obj.IsUnknown() {
		return appsecTypes.PolicyTriggerConfig{}
	}

	attrs := obj.Attributes()

	cfg := appsecTypes.PolicyTriggerConfig{}

	if v, ok := attrs["enabled"].(types.Bool); ok && !v.IsNull() && !v.IsUnknown() {
		cfg.IsEnabled = v.ValueBool()
	}

	if v, ok := attrs["override_issue_severity"].(types.String); ok && !v.IsNull() && !v.IsUnknown() {
		s := v.ValueString()
		if s != "" {
			cfg.OverrideIssueSeverity = &s
		}
	}

	if actionsObj, ok := attrs["actions"].(types.Object); ok {
		cfg.Actions = parseActions(ctx, diags, actionsObj)
	}

	return cfg
}

func parsePeriodicActions(_ context.Context, _ *diag.Diagnostics, obj types.Object) appsecTypes.TriggerActions {
	if obj.IsNull() || obj.IsUnknown() {
		return appsecTypes.TriggerActions{}
	}
	a := obj.Attributes()
	return appsecTypes.TriggerActions{
		ReportIssue: boolFromAttrs(a, "report_issue"),
	}
}

func parsePRActions(_ context.Context, _ *diag.Diagnostics, obj types.Object) appsecTypes.TriggerActions {
	if obj.IsNull() || obj.IsUnknown() {
		return appsecTypes.TriggerActions{}
	}
	a := obj.Attributes()
	return appsecTypes.TriggerActions{
		ReportIssue:     boolFromAttrs(a, "report_issue"),
		BlockPR:         boolFromAttrs(a, "block_pr"),
		ReportPRComment: boolFromAttrs(a, "report_pr_comment"),
	}
}

func parseCICDActions(_ context.Context, _ *diag.Diagnostics, obj types.Object) appsecTypes.TriggerActions {
	if obj.IsNull() || obj.IsUnknown() {
		return appsecTypes.TriggerActions{}
	}
	a := obj.Attributes()
	return appsecTypes.TriggerActions{
		ReportIssue: boolFromAttrs(a, "report_issue"),
		BlockCICD:   boolFromAttrs(a, "block_cicd"),
		ReportCICD:  boolFromAttrs(a, "report_cicd"),
	}
}

func parseCIImageActions(_ context.Context, _ *diag.Diagnostics, obj types.Object) appsecTypes.TriggerActions {
	if obj.IsNull() || obj.IsUnknown() {
		return appsecTypes.TriggerActions{}
	}
	a := obj.Attributes()
	return appsecTypes.TriggerActions{
		ReportIssue: boolFromAttrs(a, "report_issue"),
		ReportCICD:  boolFromAttrs(a, "report_cicd"),
		BlockCICD:   boolFromAttrs(a, "block_cicd"),
	}
}

func parseImageRegistryActions(_ context.Context, _ *diag.Diagnostics, obj types.Object) appsecTypes.TriggerActions {
	if obj.IsNull() || obj.IsUnknown() {
		return appsecTypes.TriggerActions{}
	}
	a := obj.Attributes()
	return appsecTypes.TriggerActions{
		ReportIssue: boolFromAttrs(a, "report_issue"),
	}
}

func boolFromAttrs(attrs map[string]attr.Value, key string) bool {
	if v, ok := attrs[key].(types.Bool); ok && !v.IsNull() && !v.IsUnknown() {
		return v.ValueBool()
	}
	return false
}

// triggerToObject builds a types.Object representation of a single trigger
// (Terraform-side) from the SDK's PolicyTriggerConfig.
func triggerToObject(
	diags *diag.Diagnostics,
	cfg appsecTypes.PolicyTriggerConfig,
	objAttrTypes map[string]attr.Type,
	buildActionsObj func(*diag.Diagnostics, appsecTypes.TriggerActions) types.Object,
) types.Object {
	actionsObj := buildActionsObj(diags, cfg.Actions)
	if diags.HasError() {
		return types.ObjectNull(objAttrTypes)
	}

	severity := types.StringNull()
	if cfg.OverrideIssueSeverity != nil {
		severity = types.StringValue(*cfg.OverrideIssueSeverity)
	}

	obj, d := types.ObjectValue(objAttrTypes, map[string]attr.Value{
		"enabled":                 types.BoolValue(cfg.IsEnabled),
		"override_issue_severity": severity,
		"actions":                 actionsObj,
	})
	diags.Append(d...)
	if diags.HasError() {
		return types.ObjectNull(objAttrTypes)
	}
	return obj
}

func buildPeriodicActionsObject(diags *diag.Diagnostics, a appsecTypes.TriggerActions) types.Object {
	obj, d := types.ObjectValue(PeriodicTriggerActionsAttrTypes, map[string]attr.Value{
		"report_issue": types.BoolValue(a.ReportIssue),
	})
	diags.Append(d...)
	return obj
}

func buildPRActionsObject(diags *diag.Diagnostics, a appsecTypes.TriggerActions) types.Object {
	obj, d := types.ObjectValue(PRTriggerActionsAttrTypes, map[string]attr.Value{
		"report_issue":      types.BoolValue(a.ReportIssue),
		"block_pr":          types.BoolValue(a.BlockPR),
		"report_pr_comment": types.BoolValue(a.ReportPRComment),
	})
	diags.Append(d...)
	return obj
}

func buildCICDActionsObject(diags *diag.Diagnostics, a appsecTypes.TriggerActions) types.Object {
	obj, d := types.ObjectValue(CICDTriggerActionsAttrTypes, map[string]attr.Value{
		"report_issue": types.BoolValue(a.ReportIssue),
		"block_cicd":   types.BoolValue(a.BlockCICD),
		"report_cicd":  types.BoolValue(a.ReportCICD),
	})
	diags.Append(d...)
	return obj
}

func buildCIImageActionsObject(diags *diag.Diagnostics, a appsecTypes.TriggerActions) types.Object {
	obj, d := types.ObjectValue(CIImageTriggerActionsAttrTypes, map[string]attr.Value{
		"report_issue": types.BoolValue(a.ReportIssue),
		"report_cicd":  types.BoolValue(a.ReportCICD),
		"block_cicd":   types.BoolValue(a.BlockCICD),
	})
	diags.Append(d...)
	return obj
}

func buildImageRegistryActionsObject(diags *diag.Diagnostics, a appsecTypes.TriggerActions) types.Object {
	obj, d := types.ObjectValue(ImageRegistryTriggerActionsAttrTypes, map[string]attr.Value{
		"report_issue": types.BoolValue(a.ReportIssue),
	})
	diags.Append(d...)
	return obj
}

// preserveJSONIfEqual compares two JSON strings semantically (ignoring key
// order) and returns the current state value if they are equal, avoiding
// spurious diffs. This handles the case where the API returns JSON with
// different key ordering than the user's Terraform configuration.
func preserveJSONIfEqual(current types.String, remoteJSON string) types.String {
	if current.IsNull() || current.IsUnknown() {
		return types.StringValue(remoteJSON)
	}

	var currentParsed, remoteParsed map[string]interface{}
	if err := json.Unmarshal([]byte(current.ValueString()), &currentParsed); err != nil {
		return types.StringValue(remoteJSON)
	}
	if err := json.Unmarshal([]byte(remoteJSON), &remoteParsed); err != nil {
		return types.StringValue(remoteJSON)
	}

	if reflect.DeepEqual(currentParsed, remoteParsed) {
		return current
	}
	return types.StringValue(remoteJSON)
}
