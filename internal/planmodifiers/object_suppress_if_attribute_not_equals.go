package planmodifiers

import (
	"context"
	"fmt"
	"reflect"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ObjectSuppressIfAttributeNotEquals returns a planmodifier.Object that suppresses
// the attribute if another attribute does NOT have a specific value.
func ObjectSuppressIfAttributeNotEquals(attributePath path.Path, attributeValue attr.Value) planmodifier.Object {
	return &objectSuppressIfAttributeNotEquals{
		attributePath:  attributePath,
		attributeValue: attributeValue,
	}
}

type objectSuppressIfAttributeNotEquals struct {
	attributePath  path.Path
	attributeValue attr.Value
}

// Description returns a human-readable description of the plan modifier.
func (m *objectSuppressIfAttributeNotEquals) Description(ctx context.Context) string {
	return fmt.Sprintf("Suppresses the attribute if `%s` is NOT set to `%s`.", m.attributePath.String(), m.attributeValue.String())
}

// MarkdownDescription returns a markdown-formatted description of the plan
// modifier.
func (m *objectSuppressIfAttributeNotEquals) MarkdownDescription(ctx context.Context) string {
	return fmt.Sprintf("Suppresses the attribute if `%s` is NOT set to `%s`.", m.attributePath.String(), m.attributeValue.String())
}

// PlanModifyObject implements the planmodifier.Object interface.
func (m *objectSuppressIfAttributeNotEquals) PlanModifyObject(ctx context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	// Do nothing if the planned value is already null or unknown.
	//if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
	if req.PlanValue.IsNull() {
		return
	}

	// Create a new instance of the concrete type of m.attributeValue
	attributeValueFromPlan := reflect.New(reflect.TypeOf(m.attributeValue)).Interface().(attr.Value)

	diags := req.Plan.GetAttribute(ctx, m.attributePath, attributeValueFromPlan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if attributeValueFromPlan.IsUnknown() || attributeValueFromPlan.IsNull() {
		return
	}

	// Compare attributeValueFromPlan with m.attributeValue
	if !attributeValueFromPlan.Equal(m.attributeValue) {
		resp.PlanValue = types.ObjectNull(req.PlanValue.AttributeTypes(ctx))
	}
}
