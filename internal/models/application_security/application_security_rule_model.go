// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	//"github.com/hashicorp/terraform-plugin-log/tflog"
)

// *********************************************************
// Structs
// *********************************************************

type ApplicationSecurityRuleModel struct {
	Category        types.String     `tfsdk:"category"`
	CloudProvider   types.String     `tfsdk:"cloud_provider"`
	CreatedAt       types.String     `tfsdk:"created_at"`
	Description     types.String     `tfsdk:"description"`
	DetectionMethod types.String     `tfsdk:"detection_method"`
	DocLink         types.String     `tfsdk:"doc_link"`
	Domain          types.String     `tfsdk:"domain"`
	FindingCategory types.String     `tfsdk:"finding_category"`
	FindingDocs     types.String     `tfsdk:"finding_docs"`
	FindingTypeId   types.Int32      `tfsdk:"finding_type_id"`
	FindingTypeName types.String     `tfsdk:"finding_type_name"`
	Frameworks      []FrameworkModel `tfsdk:"frameworks"`
	Id              types.String     `tfsdk:"id"`
	IsCustom        types.Bool       `tfsdk:"is_custom"`
	IsEnabled       types.Bool       `tfsdk:"is_enabled"`
	Labels          types.Set        `tfsdk:"labels"`
	MitreTactics    types.Set        `tfsdk:"mitre_tactics"`
	MitreTechniques types.Set        `tfsdk:"mitre_techniques"`
	Name            types.String     `tfsdk:"name"`
	Owner           types.String     `tfsdk:"owner"`
	Scanner         types.String     `tfsdk:"scanner"`
	Severity        types.String     `tfsdk:"severity"`
	Source          types.String     `tfsdk:"source"`
	SubCategory     types.String     `tfsdk:"sub_category"`
	UpdatedAt       types.String     `tfsdk:"updated_at"`
}

type FrameworkModel struct {
	Name                   types.String `tfsdk:"name"`
	Definition             types.String `tfsdk:"definition"`
	DefinitionLink         types.String `tfsdk:"definition_link"`
	RemediationDescription types.String `tfsdk:"remediation_description"`
}

// *********************************************************
// Request conversion functions
// *********************************************************

func (m *ApplicationSecurityRuleModel) ToCreateOrCloneRequest(ctx context.Context, diagnostics *diag.Diagnostics) appsec.CreateOrCloneRequest {
	labels := util.StringSetToStringArray(ctx, diagnostics, m.Labels)
	if diagnostics.HasError() {
		return appsec.CreateOrCloneRequest{}
	}

	var frameworks []appsec.FrameworkData
	for _, f := range m.Frameworks {
		frameworks = append(frameworks, appsec.FrameworkData{
			Name:                   f.Name.ValueString(),
			Definition:             f.Definition.ValueString(),
			RemediationDescription: f.RemediationDescription.ValueString(),
			DefinitionLink:         f.DefinitionLink.ValueString(),
		})
	}

	return appsec.CreateOrCloneRequest{
		Name:        m.Name.ValueString(),
		Severity:    m.Severity.ValueString(),
		Scanner:     m.Scanner.ValueString(),
		Frameworks:  frameworks,
		Category:    m.Category.ValueString(),
		SubCategory: m.SubCategory.ValueString(),
		Description: m.Description.ValueString(),
		Labels:      labels,
	}
}

func (m *ApplicationSecurityRuleModel) ToUpdateRequest(ctx context.Context, diagnostics *diag.Diagnostics) appsec.UpdateRequest {
	labels := util.StringSetToStringArray(ctx, diagnostics, m.Labels)
	if diagnostics.HasError() {
		return appsec.UpdateRequest{}
	}

	// If the target rule is a default rule, only the labels field may be updated
	if !m.IsCustom.ValueBool() {
		return appsec.UpdateRequest{
			Labels: labels,
		}
	}

	var frameworks []appsec.FrameworkData
	for _, f := range m.Frameworks {
		frameworks = append(frameworks, appsec.FrameworkData{
			Name:                   f.Name.ValueString(),
			Definition:             f.Definition.ValueString(),
			RemediationDescription: f.RemediationDescription.ValueString(),
			DefinitionLink:         f.DefinitionLink.ValueString(),
		})
	}

	name := m.Name.ValueString()
	severity := m.Severity.ValueString()
	scanner := m.Scanner.ValueString()
	category := m.Category.ValueString()
	subCategory := m.SubCategory.ValueString()
	description := m.Description.ValueString()

	return appsec.UpdateRequest{
		Name:        name,
		Severity:    severity,
		Scanner:     scanner,
		Frameworks:  frameworks,
		Category:    category,
		SubCategory: subCategory,
		Description: description,
		Labels:      labels,
	}
}

// *********************************************************
// Helper functions
// *********************************************************

var frameworkMetadataRegex = regexp.MustCompile(`(?m)^\s*metadata:\s*\n(?:^\s+.*\n){4}`)

//func (m *ApplicationSecurityRuleModel) NormalizeFrameworks(ctx context.Context, diagnostics *diag.Diagnostics) {
//	if len(m.Frameworks) == 0 {
//		return
//	}
//
//	tfPlanIdx := -1
//	for idx, framework := range m.Frameworks {
//		// Remove the `TERRAFORMPLAN` framework generated by the platform
//		// when a `TERRAFORM` framework definition is configured for the rule.
//		if framework.Name.ValueString() == "TERRAFORMPLAN" && slices.ContainsFunc(m.Frameworks, func(f FrameworkModel) bool { return strings.ToUpper(f.Name.ValueString()) == "TERRAFORM" }) {
//			tfPlanIdx = idx
//			continue
//		}
//
//		// Remove `metadata` block from framework definition to prevent
//		// Terraform erroring on inconsistant post-apply results
//		cleanedDefinition := frameworkMetadataRegex.ReplaceAllString(framework.Definition.ValueString(), "")
//		framework.Definition = types.StringValue(cleanedDefinition)
//	}
//
//	if tfPlanIdx != -1 {
//		m.Frameworks = append(m.Frameworks[:tfPlanIdx], m.Frameworks[tfPlanIdx+1:]...)
//	}
//
//}

func (m *ApplicationSecurityRuleModel) RefreshPropertyValues(ctx context.Context, diagnostics *diag.Diagnostics, response appsec.Rule) {
	// TODO: create member functions for conversion to schema

	var frameworkValues []FrameworkModel
	for _, framework := range response.Frameworks {
		// Remove the `TERRAFORMPLAN` framework generated by the platform
		// when a `TERRAFORM` framework definition is configured for the rule.
		if framework.Name == "TERRAFORMPLAN" && slices.ContainsFunc(m.Frameworks, func(f FrameworkModel) bool { return strings.ToUpper(f.Name.ValueString()) == "TERRAFORM" }) {
			continue
		}

		// Remove `metadata` block from framework definition to prevent
		// Terraform erroring on inconsistant post-apply results
		cleanedDefinition := frameworkMetadataRegex.ReplaceAllString(framework.Definition, "")

		frameworkValues = append(frameworkValues, FrameworkModel{
			Name:                   types.StringValue(framework.Name),
			Definition:             types.StringValue(cleanedDefinition),
			RemediationDescription: types.StringValue(framework.RemediationDescription),
			DefinitionLink:         types.StringValue(framework.DefinitionLink),
		})
	}

	labels, diags := types.SetValueFrom(ctx, types.StringType, response.Labels)
	diagnostics.Append(diags...)

	mitreTactics, diags := types.SetValueFrom(ctx, types.StringType, response.MitreTactics)
	diagnostics.Append(diags...)

	mitreTechniques, diags := types.SetValueFrom(ctx, types.StringType, response.MitreTechniques)
	diagnostics.Append(diags...)

	if diagnostics.HasError() {
		return
	}

	m.Category = types.StringValue(response.Category)
	m.CloudProvider = types.StringValue(response.CloudProvider)
	m.CreatedAt = types.StringValue(response.CreatedAt.Value)
	m.Description = types.StringValue(response.Description)
	m.DetectionMethod = types.StringPointerValue(response.DetectionMethod)
	m.DocLink = types.StringValue(response.DocLink)
	m.Domain = types.StringValue(response.Domain)
	m.FindingCategory = types.StringValue(response.FindingCategory)
	m.FindingDocs = types.StringValue(response.FindingDocs)
	m.FindingTypeId = types.Int32Value(int32(response.FindingTypeId))
	m.FindingTypeName = types.StringValue(response.FindingTypeName)
	m.Frameworks = frameworkValues
	m.Id = types.StringValue(response.Id)
	m.IsCustom = types.BoolValue(response.IsCustom)
	m.IsEnabled = types.BoolValue(response.IsEnabled)
	m.Labels = labels
	m.MitreTactics = mitreTactics
	m.MitreTechniques = mitreTechniques
	m.Name = types.StringValue(response.Name)
	m.Owner = types.StringValue(response.Owner)
	m.Scanner = types.StringValue(response.Scanner)
	m.Severity = types.StringValue(response.Severity)
	m.Source = types.StringValue(response.Source)
	m.SubCategory = types.StringValue(response.SubCategory)
	m.UpdatedAt = types.StringValue(response.UpdatedAt.Value)
}
