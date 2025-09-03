// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	//appSecApi "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/api/application_security"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/application_security"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	//"github.com/hashicorp/terraform-plugin-framework/path"
)

type addFrameworkDefinitionMetadata struct{}

func AddFrameworkDefinitionMetadata() planmodifier.String {
	return &addFrameworkDefinitionMetadata{}
}

func (m *addFrameworkDefinitionMetadata) Description(ctx context.Context) string {
	return m.MarkdownDescription(ctx)
}

func (m *addFrameworkDefinitionMetadata) MarkdownDescription(context.Context) string {
	return ""
}

func (m *addFrameworkDefinitionMetadata) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}

	tflog.Debug(ctx, "\n\n\nStarting metadata\n\n\n")

	definitionYAML := req.PlanValue.ValueString()

	// Use yaml.Node to preserve the order of keys.
	var rootNode yaml.Node
	err := yaml.Unmarshal([]byte(definitionYAML), &rootNode)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to parse YAML content for modification",
			fmt.Sprintf("The 'yaml_content' attribute contains invalid YAML: %s", err.Error()),
		)
		return
	}

	// Ensure the root node is a mapping (object).
	if rootNode.Kind != yaml.DocumentNode || len(rootNode.Content) == 0 || rootNode.Content[0].Kind != yaml.MappingNode {
		resp.Diagnostics.AddError(
			"Unexpected YAML structure",
			"The root of the YAML content must be a mapping (object).",
		)
		return
	}

	// The actual mapping node is usually the first content of the DocumentNode.
	mappingNode := rootNode.Content[0]

	var plan models.ApplicationSecurityRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Define the 'metadata' block that the API populates.
	// These values are hardcoded to match your example's 'config value'.
	injectedMetadataMap := map[string]string{
		"name":       plan.Name.ValueString(),
		"guidelines": "...",
		"category":   strings.ToLower(plan.Category.ValueString()),
		"severity":   strings.ToLower(plan.Severity.ValueString()),
	}

	// Create a new yaml.Node for the 'metadata' key and its value.
	metadataKeyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: "metadata",
	}

	metadataValueNode := &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
	}

	// Populate the metadataValueNode with its key-value pairs.
	for k, v := range injectedMetadataMap {
		metadataValueNode.Content = append(metadataValueNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v},
		)
	}

	// Check if 'metadata' already exists and remove it to re-insert in the correct position.
	newContent := []*yaml.Node{}
	//metadataFound := false
	for i := 0; i < len(mappingNode.Content); i += 2 {
		keyNode := mappingNode.Content[i]
		if keyNode.Value == "metadata" {
			//metadataFound = true
			// Skip this key-value pair as we will re-add it.
			continue
		}
		newContent = append(newContent, keyNode, mappingNode.Content[i+1])
	}

	// Prepend the new metadata key-value pair to the content.
	// This ensures 'metadata' is the first top-level key.
	mappingNode.Content = append([]*yaml.Node{metadataKeyNode, metadataValueNode}, newContent...)

	// Marshal the modified yaml.Node back into a YAML string.
	var buf strings.Builder
	yamlEncoder := yaml.NewEncoder(&buf)
	yamlEncoder.SetIndent(2) // Use 2 spaces for indentation, common for YAML
	err = yamlEncoder.Encode(&rootNode)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to serialize modified YAML content",
			fmt.Sprintf("Could not re-serialize the modified YAML: %s", err.Error()),
		)
		return
	}

	if !req.ConfigValue.IsNull() || !req.ConfigValue.IsUnknown() {
		plannedUpdatedYAML := buf.String()
		if plannedUpdatedYAML != req.ConfigValue.ValueString() {
			tflog.Debug(ctx, "\n\n\nsetting unknown\n\n\n")
			resp.PlanValue = types.StringUnknown()
			return
		}
	}

	// Set the modified YAML string as the new planned value.
	resp.PlanValue = types.StringValue(buf.String())

	//var yamlMap map[string]any
	//err := yaml.Unmarshal([]byte(definitionYaml), &yamlMap)
	//if err != nil {
	//	resp.Diagnostics.AddAttributeError(
	//		req.Path,
	//		"Failed to parse YAML content",
	//		fmt.Sprintf("Provided value contains invalid YAML: %s", err.Error()),
	//	)
	//	return
	//}

	//var plan models.ApplicationSecurityRuleModel
	//resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//metadata := map[string]any{
	//	"name": plan.Name.ValueString(),
	//	"guidelines": "...",
	//	"category": strings.ToLower(plan.Category.ValueString()),
	//	"severity": strings.ToLower(plan.Severity.ValueString()),
	//}

	//yamlMap["metadata"] = metadata

	//modifiedYAMLBytes, err := yaml.Marshal(yamlMap)
	//if err != nil {
	//	resp.Diagnostics.AddAttributeError(
	//		req.Path,
	//		"Failed to serialize YAML content",
	//		fmt.Sprintf("Could not re-serialize the modified YAML: %s", err.Error()),
	//	)
	//	return
	//}

	//resp.PlanValue = types.StringValue(string(modifiedYAMLBytes))

	//var definition customTypes.YamlString
	//resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, req.Path, &definition)...)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//definitionYaml := appSecApi.ApplicationSecurityRuleYaml{}
	//err := yaml.Unmarshal([]byte(definition.ValueString()), &definitionYaml)
	//if err != nil {
	//	resp.Diagnostics.AddAttributeError(
	//		req.Path,
	//		"Value Conversion Error",
	//		fmt.Sprintf("Failed to convert rule definition \"%s\": %s", definition.ValueString(), err.Error()),
	//	)
	//	return
	//}

	//if definitionYaml.Metadata == nil {
	//	var plan models.ApplicationSecurityRuleModel
	//	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	//	if resp.Diagnostics.HasError() {
	//		return
	//	}

	//	var guidelines *string
	//	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, req.Path.ParentPath().AtName("remediation_description"), &guidelines)...)

	//	definitionYaml.Metadata = &appSecApi.ApplicationSecurityRuleYamlMetadata{
	//		Name:       strings.ToLower(plan.Name.ValueString()),
	//		Guidelines: guidelines,
	//		Category:   strings.ToLower(plan.Category.ValueString()),
	//		Severity:   strings.ToLower(plan.Severity.ValueString()),
	//	}

	//	var updatedDefinitionYaml strings.Builder
	//	encoder := yaml.NewEncoder(&updatedDefinitionYaml)
	//	encoder.SetIndent(2)
	//	err := encoder.Encode(definitionYaml)
	//	if err != nil {
	//		resp.Diagnostics.AddAttributeError(
	//			req.Path,
	//			"Value Conversion Error",
	//			fmt.Sprintf("Failed to convert modified rule definition back into YAML string: %s", err.Error()),
	//		)
	//	}
	//	updateDefinitionString := updatedDefinitionYaml.String()
	//	resp.PlanValue = types.StringValue(updateDefinitionString)
	//}
}
