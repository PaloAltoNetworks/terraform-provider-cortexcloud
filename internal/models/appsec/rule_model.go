// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"reflect"
	"regexp"
	"strings"

	appsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/appsec"
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
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Severity        types.String `tfsdk:"severity"`
	Scanner         types.String `tfsdk:"scanner"`
	Category        types.String `tfsdk:"category"`
	SubCategory     types.String `tfsdk:"sub_category"`
	Description     types.String `tfsdk:"description"`
	Frameworks      types.List   `tfsdk:"frameworks"`
	Labels          types.List   `tfsdk:"labels"`
	IsCustom        types.Bool   `tfsdk:"is_custom"`
	IsEnabled       types.Bool   `tfsdk:"is_enabled"`
	CloudProvider   types.String `tfsdk:"cloud_provider"`
	Domain          types.String `tfsdk:"domain"`
	FindingCategory types.String `tfsdk:"finding_category"`
	CreatedAt       types.String `tfsdk:"created_at"`
	UpdatedAt       types.String `tfsdk:"updated_at"`
}

// FrameworkModel represents a framework definition.
type FrameworkModel struct {
	Name                   types.String `tfsdk:"name"`
	Definition             types.String `tfsdk:"definition"`
	DefinitionLink         types.String `tfsdk:"definition_link"`
	RemediationDescription types.String `tfsdk:"remediation_description"`
}

// RefreshFromRemote updates the Terraform model from the SDK response.
func (m *RuleModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *appsecTypes.Rule) {
	tflog.Debug(ctx, "Refreshing appsec rule model from remote")

	if remote == nil {
		diags.AddError("AppSec Rule Not Found", "The requested AppSec rule does not exist.")
		return
	}

	m.ID = types.StringValue(remote.Id)

	// The AppSec API lowercases the name and description fields on create/update.
	// Use case-insensitive comparison to preserve the user's original casing
	// and prevent spurious Terraform state drift.
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

	// Convert frameworks.
	// The AppSec API may auto-add companion frameworks (e.g., TERRAFORMPLAN
	// when TERRAFORM is sent). Filter the API response to only include
	// frameworks the user configured, preventing Terraform's "block count
	// changed" error.
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
		m.Frameworks = types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"name":                    types.StringType,
				"definition":              types.StringType,
				"definition_link":         types.StringType,
				"remediation_description": types.StringType,
			},
		})
	} else {
		// Build a map of configured definitions (from current model) so we can
		// preserve the user's original value when the normalized forms match.
		configuredDefs := m.configuredFrameworkDefinitions(ctx, diags)

		frameworkElements := make([]attr.Value, len(remoteFrameworks))
		for i, fw := range remoteFrameworks {
			normalizedRemoteDef := stripDefinitionMetadata(fw.Definition)
			defValue := preserveDefinitionIfEqual(configuredDefs[fw.Name], normalizedRemoteDef)

			fwObj, fwDiags := types.ObjectValue(
				map[string]attr.Type{
					"name":                    types.StringType,
					"definition":              types.StringType,
					"definition_link":         types.StringType,
					"remediation_description": types.StringType,
				},
				map[string]attr.Value{
					"name":                    types.StringValue(fw.Name),
					"definition":              defValue,
					"definition_link":         stringValueOrNull(fw.DefinitionLink),
					"remediation_description": stringValueOrNull(fw.RemediationDescription),
				},
			)
			diags.Append(fwDiags...)
			if diags.HasError() {
				return
			}
			frameworkElements[i] = fwObj
		}
		fwList, fwListDiags := types.ListValue(
			types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"name":                    types.StringType,
					"definition":              types.StringType,
					"definition_link":         types.StringType,
					"remediation_description": types.StringType,
				},
			},
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
	}

	// Convert frameworks.
	// Note: outbound uses ValueString() (null→"") which the API accepts.
	// Inbound (RefreshFromRemote) uses stringValueOrNull (""→null) to match
	// Terraform's expectation for unset Optional attributes.
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

// configuredFrameworkNames returns the set of framework names currently in the
// model's Frameworks list. If the list is null or unknown (e.g., during import),
// it returns nil to indicate that no filtering should be applied.
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

// filterFrameworks returns only the frameworks whose names are in the
// configuredNames set. If configuredNames is nil (e.g., during import or when
// no frameworks are configured), all frameworks are returned unfiltered.
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

// stringValueOrNull returns types.StringNull() for empty strings and
// types.StringValue(v) otherwise. This prevents Terraform state drift for
// Optional schema attributes that the user did not set — Terraform expects
// null, not an empty string.
func stringValueOrNull(v string) types.String {
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(v)
}

// stripDefinitionMetadata normalizes a framework definition string returned
// by the AppSec API. It performs two normalizations:
//
//  1. Strips the API-appended "metadata:" YAML section. The API appends rule
//     metadata (name, category, severity, guidelines) to the definition field
//     in GET responses, causing Terraform to detect spurious drift on updates.
//
//  2. Trims trailing whitespace/newlines. Terraform heredocs (<<-EOT) always
//     add a trailing newline, but the API strips it, causing a mismatch.
//
// The function looks for "\nmetadata:\n" as a top-level YAML key (at column 0)
// and truncates everything from that point onward.
func stripDefinitionMetadata(definition string) string {
	if definition == "" {
		return definition
	}

	// Use the package-level compiled regex to find a top-level "metadata:" key
	// at column 0, not indented (which would be a nested value).
	loc := metadataKeyRe.FindStringIndex(definition)
	if loc != nil {
		return strings.TrimRight(definition[:loc[0]], " \t\r\n")
	}

	// Also handle the edge case where "metadata:" is at the very start.
	if strings.HasPrefix(definition, "metadata:") {
		return ""
	}

	// Trim trailing whitespace/newlines to match API behavior.
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
