// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"reflect"
	"regexp"
	"strings"

	appsecTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/appsec"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"gopkg.in/yaml.v3"
)

// metadataKeyRe matches a top-level "metadata:" YAML key at column 0 (not indented).
// Compiled once at package level to avoid per-call overhead.
var metadataKeyRe = regexp.MustCompile(`(\r?\n)metadata:[ \t]*(\r?\n)`)

// RuleModel is the Terraform model for an AppSec rule.
type RuleModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Severity         types.String `tfsdk:"severity"`
	Scanner          types.String `tfsdk:"scanner"`
	Category         types.String `tfsdk:"category"`
	SubCategory      types.String `tfsdk:"sub_category"`
	Description      types.String `tfsdk:"description"`
	Frameworks       types.List   `tfsdk:"frameworks"`
	Labels           types.List   `tfsdk:"labels"`
	IsCustom         types.Bool   `tfsdk:"is_custom"`
	IsEnabled        types.Bool   `tfsdk:"is_enabled"`
	CloudProvider    types.String `tfsdk:"cloud_provider"`
	Domain           types.String `tfsdk:"domain"`
	FindingCategory  types.String `tfsdk:"finding_category"`
	CreatedAt        types.String `tfsdk:"created_at"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
	ShortDescription types.String `tfsdk:"short_description"`
	// The following are read-only fields populated by the API on read.
	DocLink         types.String `tfsdk:"doc_link"`
	DetectionMethod types.String `tfsdk:"detection_method"`
	FindingDocs     types.String `tfsdk:"finding_docs"`
	FindingTypeID   types.Int64  `tfsdk:"finding_type_id"`
	Owner           types.String `tfsdk:"owner"`
	MitreTactics    types.List   `tfsdk:"mitre_tactics"`
	MitreTechniques types.List   `tfsdk:"mitre_techniques"`
	// Write-only: API accepts it on create/update but never returns it; value is
	// preserved from config/state.
	CspmRuleId types.String `tfsdk:"cspm_rule_id"`
}

// FrameworkModel represents a framework definition.
type FrameworkModel struct {
	Name                   types.String `tfsdk:"name"`
	Definition             types.String `tfsdk:"definition"`
	DefinitionLink         types.String `tfsdk:"definition_link"`
	RemediationDescription types.String `tfsdk:"remediation_description"`
	RemediationIds         types.List   `tfsdk:"remediation_ids"`
	ResourceTypes          types.List   `tfsdk:"resource_types"`
}

// frameworkAttrTypes returns the attribute types for a framework object,
// used when building framework list values from the SDK response.
func frameworkAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"name":                    types.StringType,
		"definition":              types.StringType,
		"definition_link":         types.StringType,
		"remediation_description": types.StringType,
		"remediation_ids":         types.ListType{ElemType: types.StringType},
		"resource_types":          types.ListType{ElemType: types.StringType},
	}
}

// RefreshFromRemote updates the Terraform model from the SDK response.
func (m *RuleModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *appsecTypes.Rule) {
	tflog.Debug(ctx, "Refreshing appsec rule model from remote")

	if remote == nil {
		diags.AddError("AppSec Rule Not Found", "The requested AppSec rule does not exist.")
		return
	}

	m.ID = types.StringValue(remote.Id)

	// API lowercases name/description; preserve the user's casing to avoid drift.
	m.Name = preserveCaseIfEqual(m.Name, remote.Name)
	m.Description = preserveCaseIfEqual(m.Description, remote.Description)

	m.Severity = types.StringValue(remote.Severity)
	m.Scanner = types.StringValue(remote.Scanner)
	m.Category = types.StringValue(remote.Category)
	m.SubCategory = types.StringValue(remote.SubCategory)
	m.IsCustom = types.BoolValue(remote.IsCustom)
	m.IsEnabled = types.BoolValue(remote.IsEnabled)
	m.CloudProvider = types.StringValue(remote.CloudProvider)
	m.Domain = types.StringValue(remote.Domain)
	m.FindingCategory = types.StringValue(remote.FindingCategory)
	m.CreatedAt = types.StringValue(remote.CreatedAt.Value)
	m.UpdatedAt = types.StringValue(remote.UpdatedAt.Value)
	m.ShortDescription = stringValueOrNull(remote.ShortDescription)

	// Read-only fields populated by the API on read.
	m.DocLink = stringValueOrNull(remote.DocLink)
	if remote.DetectionMethod != nil {
		m.DetectionMethod = stringValueOrNull(*remote.DetectionMethod)
	} else {
		m.DetectionMethod = types.StringNull()
	}
	m.FindingDocs = stringValueOrNull(remote.FindingDocs)
	m.FindingTypeID = types.Int64Value(int64(remote.FindingTypeId))
	m.Owner = stringValueOrNull(remote.Owner)

	mitreTactics, mtDiags := stringSliceToListOrNull(ctx, remote.MitreTactics)
	diags.Append(mtDiags...)
	mitreTechniques, mtechDiags := stringSliceToListOrNull(ctx, remote.MitreTechniques)
	diags.Append(mtechDiags...)
	if diags.HasError() {
		return
	}
	m.MitreTactics = mitreTactics
	m.MitreTechniques = mitreTechniques

	// API may auto-add companion frameworks (e.g. TERRAFORMPLAN for TERRAFORM);
	// filter to configured ones to avoid a "block count changed" error.
	configuredNames := m.configuredFrameworkNames(ctx, diags)
	if diags.HasError() {
		return
	}
	remoteFrameworks := filterFrameworks(remote.Frameworks, configuredNames)

	if filtered := len(remote.Frameworks) - len(remoteFrameworks); filtered > 0 {
		tflog.Debug(ctx, "Filtered auto-added frameworks from API response",
			map[string]interface{}{"filtered_count": filtered, "kept_count": len(remoteFrameworks)})
	}

	if len(remoteFrameworks) == 0 {
		m.Frameworks = types.ListNull(types.ObjectType{AttrTypes: frameworkAttrTypes()})
	} else {
		// Preserve the user's definition when normalized forms match.
		configuredDefs := m.configuredFrameworkDefinitions(ctx, diags)

		frameworkElements := make([]attr.Value, len(remoteFrameworks))
		for i, fw := range remoteFrameworks {
			normalizedRemoteDef := stripDefinitionMetadata(fw.Definition)
			defValue := preserveDefinitionIfEqual(configuredDefs[fw.Name], normalizedRemoteDef)

			remediationIds, riDiags := stringSliceToListOrNull(ctx, fw.RemediationIds)
			diags.Append(riDiags...)
			resourceTypes, rtDiags := stringSliceToListOrNull(ctx, fw.ResourceTypes)
			diags.Append(rtDiags...)
			if diags.HasError() {
				return
			}

			fwObj, fwDiags := types.ObjectValue(
				frameworkAttrTypes(),
				map[string]attr.Value{
					"name":                    types.StringValue(fw.Name),
					"definition":              defValue,
					"definition_link":         stringValueOrNull(fw.DefinitionLink),
					"remediation_description": stringValueOrNull(fw.RemediationDescription),
					"remediation_ids":         remediationIds,
					"resource_types":          resourceTypes,
				},
			)
			diags.Append(fwDiags...)
			if diags.HasError() {
				return
			}
			frameworkElements[i] = fwObj
		}
		fwList, fwListDiags := types.ListValue(
			types.ObjectType{AttrTypes: frameworkAttrTypes()},
			frameworkElements,
		)
		diags.Append(fwListDiags...)
		if diags.HasError() {
			return
		}
		m.Frameworks = fwList
	}

	// Convert labels
	if remote.Labels == nil || len(*remote.Labels) == 0 {
		m.Labels = types.ListNull(types.StringType)
	} else {
		elements := make([]attr.Value, len(*remote.Labels))
		for i, label := range *remote.Labels {
			elements[i] = types.StringValue(label)
		}
		labelList, labelDiags := types.ListValue(types.StringType, elements)
		diags.Append(labelDiags...)
		if diags.HasError() {
			return
		}
		m.Labels = labelList
	}
}

// ToCreateRequest converts the Terraform model to an SDK create request.
func (m *RuleModel) ToCreateRequest(ctx context.Context, diags *diag.Diagnostics) appsecTypes.CreateOrCloneRequest {
	tflog.Debug(ctx, "Converting rule model to create request")

	req := appsecTypes.CreateOrCloneRequest{
		Name:        m.Name.ValueString(),
		Severity:    m.Severity.ValueString(),
		Scanner:     m.Scanner.ValueString(),
		Category:    m.Category.ValueString(),
		SubCategory: m.SubCategory.ValueString(),
		Description: m.Description.ValueString(),
		CspmRuleId:  cspmRuleIdPointerOrNil(m.CspmRuleId),
	}

	// Outbound uses ValueString() (null→""); inbound uses stringValueOrNull (""→null).
	if !m.Frameworks.IsNull() && !m.Frameworks.IsUnknown() {
		var frameworks []FrameworkModel
		diags.Append(m.Frameworks.ElementsAs(ctx, &frameworks, false)...)
		if diags.HasError() {
			return req
		}

		req.Frameworks = make([]appsecTypes.FrameworkData, len(frameworks))
		for i, fw := range frameworks {
			req.Frameworks[i] = appsecTypes.FrameworkData{
				Name:                   fw.Name.ValueString(),
				Definition:             strings.TrimRight(fw.Definition.ValueString(), " \t\r\n"),
				DefinitionLink:         fw.DefinitionLink.ValueString(),
				RemediationDescription: fw.RemediationDescription.ValueString(),
			}
		}
	}

	// Convert labels
	if !m.Labels.IsNull() && !m.Labels.IsUnknown() {
		var labels []string
		diags.Append(m.Labels.ElementsAs(ctx, &labels, false)...)
		if diags.HasError() {
			return req
		}
		req.Labels = labels
	} else {
		req.Labels = []string{}
	}

	return req
}

// cspmRuleIdPointerOrNil returns nil for unset/empty values so the optional
// field is omitted from the request.
func cspmRuleIdPointerOrNil(v types.String) *string {
	if v.IsNull() || v.IsUnknown() || v.ValueString() == "" {
		return nil
	}
	s := v.ValueString()
	return &s
}

// ToUpdateRequest converts the Terraform model to an SDK update request.
func (m *RuleModel) ToUpdateRequest(ctx context.Context, diags *diag.Diagnostics) appsecTypes.UpdateRequest {
	tflog.Debug(ctx, "Converting rule model to update request")

	req := appsecTypes.UpdateRequest{
		Name:        m.Name.ValueString(),
		Severity:    m.Severity.ValueString(),
		Scanner:     m.Scanner.ValueString(),
		Category:    m.Category.ValueString(),
		SubCategory: m.SubCategory.ValueString(),
		Description: m.Description.ValueString(),
		CspmRuleId:  cspmRuleIdPointerOrNil(m.CspmRuleId),
	}

	// Convert frameworks
	if !m.Frameworks.IsNull() && !m.Frameworks.IsUnknown() {
		var frameworks []FrameworkModel
		diags.Append(m.Frameworks.ElementsAs(ctx, &frameworks, false)...)
		if diags.HasError() {
			return req
		}

		req.Frameworks = make([]appsecTypes.FrameworkData, len(frameworks))
		for i, fw := range frameworks {
			req.Frameworks[i] = appsecTypes.FrameworkData{
				Name:                   fw.Name.ValueString(),
				Definition:             strings.TrimRight(fw.Definition.ValueString(), " \t\r\n"),
				DefinitionLink:         fw.DefinitionLink.ValueString(),
				RemediationDescription: fw.RemediationDescription.ValueString(),
			}
		}
	}

	// Convert labels (required field)
	if !m.Labels.IsNull() && !m.Labels.IsUnknown() {
		var labels []string
		diags.Append(m.Labels.ElementsAs(ctx, &labels, false)...)
		if diags.HasError() {
			return req
		}
		req.Labels = labels
	} else {
		req.Labels = []string{}
	}

	return req
}

// configuredFrameworkNames returns the configured framework names, or nil (no
// filtering) when the list is null/unknown.
func (m *RuleModel) configuredFrameworkNames(ctx context.Context, diags *diag.Diagnostics) map[string]struct{} {
	if m.Frameworks.IsNull() || m.Frameworks.IsUnknown() {
		return nil
	}

	var frameworks []FrameworkModel
	diags.Append(m.Frameworks.ElementsAs(ctx, &frameworks, false)...)
	if diags.HasError() {
		return nil
	}

	names := make(map[string]struct{}, len(frameworks))
	for _, fw := range frameworks {
		if !fw.Name.IsNull() && !fw.Name.IsUnknown() {
			names[fw.Name.ValueString()] = struct{}{}
		}
	}
	return names
}

// filterFrameworks keeps only frameworks in configuredNames; nil means no filtering.
func filterFrameworks(frameworks []appsecTypes.FrameworkData, configuredNames map[string]struct{}) []appsecTypes.FrameworkData {
	if configuredNames == nil {
		return frameworks
	}

	filtered := make([]appsecTypes.FrameworkData, 0, len(frameworks))
	for _, fw := range frameworks {
		if _, ok := configuredNames[fw.Name]; ok {
			filtered = append(filtered, fw)
		}
	}
	return filtered
}

// stringValueOrNull returns null for empty strings to avoid drift on unset Optional attrs.
func stringValueOrNull(v string) types.String {
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(v)
}

// stringSliceToListOrNull returns a typed null list for empty slices to avoid drift.
func stringSliceToListOrNull(ctx context.Context, values []string) (types.List, diag.Diagnostics) {
	if len(values) == 0 {
		return types.ListNull(types.StringType), nil
	}
	return types.ListValueFrom(ctx, types.StringType, values)
}

// stripDefinitionMetadata normalizes an API-returned definition: it drops the
// API-appended top-level "metadata:" YAML section (which causes spurious drift)
// and trims trailing whitespace (heredocs add a newline the API strips).
func stripDefinitionMetadata(definition string) string {
	if definition == "" {
		return definition
	}

	// Top-level "metadata:" key at column 0 (not nested): truncate from there.
	loc := metadataKeyRe.FindStringIndex(definition)
	if loc != nil {
		return strings.TrimRight(definition[:loc[0]], " \t\r\n")
	}

	if strings.HasPrefix(definition, "metadata:") {
		return ""
	}

	return strings.TrimRight(definition, " \t\r\n")
}

// configuredFrameworkDefinitions returns a map of framework name → definition
// from the current model's Frameworks list. Used to preserve the user's original
// definition value when the normalized forms match (preventing heredoc trailing
// newline drift).
func (m *RuleModel) configuredFrameworkDefinitions(ctx context.Context, diags *diag.Diagnostics) map[string]types.String {
	if m.Frameworks.IsNull() || m.Frameworks.IsUnknown() {
		return nil
	}

	var frameworks []FrameworkModel
	diags.Append(m.Frameworks.ElementsAs(ctx, &frameworks, false)...)
	if diags.HasError() {
		return nil
	}

	defs := make(map[string]types.String, len(frameworks))
	for _, fw := range frameworks {
		if !fw.Name.IsNull() && !fw.Name.IsUnknown() {
			defs[fw.Name.ValueString()] = fw.Definition
		}
	}
	return defs
}

// preserveDefinitionIfEqual preserves the user's original definition value
// if the normalized forms match. This prevents Terraform state drift caused by:
//   - Trailing newlines from heredoc (<<-EOT) that the API strips
//   - API-appended metadata sections that stripDefinitionMetadata removes
//   - YAML quote differences (e.g., "0.0.0.0/0" vs 0.0.0.0/0)
func preserveDefinitionIfEqual(configured types.String, normalizedRemote string) types.String {
	if configured.IsNull() || configured.IsUnknown() {
		return types.StringValue(normalizedRemote)
	}
	configNormalized := stripDefinitionMetadata(configured.ValueString())

	// Try YAML-aware comparison first (handles quote differences and trailing whitespace)
	var configParsed, remoteParsed interface{}
	if yaml.Unmarshal([]byte(configNormalized), &configParsed) == nil &&
		yaml.Unmarshal([]byte(normalizedRemote), &remoteParsed) == nil {
		if reflect.DeepEqual(configParsed, remoteParsed) {
			return configured
		}
	}

	// Fall back to string comparison (trimmed)
	if strings.TrimSpace(configNormalized) == strings.TrimSpace(normalizedRemote) {
		return configured
	}
	return types.StringValue(normalizedRemote)
}

// preserveCaseIfEqual preserves the current model value if the remote value
// is case-insensitively equal. This prevents Terraform state drift when the
// AppSec API lowercases user input on create/update.
func preserveCaseIfEqual(current types.String, remoteValue string) types.String {
	if !current.IsNull() && !current.IsUnknown() {
		if strings.EqualFold(current.ValueString(), remoteValue) {
			return current
		}
	}
	return types.StringValue(remoteValue)
}
