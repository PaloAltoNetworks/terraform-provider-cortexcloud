// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

import (
	"context"
	//"fmt"
	"slices"
	////"strconv"
	//"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

//var (
//	_ validator.String = NullIfAlsoSetPlanModifier{}
//	_ validator.Bool   = NullIfAlsoSetPlanModifier{}
//)

func NullIfAlsoSetInt32(onValues []string) planmodifier.Int32 {
	return &nullIfAlsoSetInt32{
		OnValues: onValues,
	}
}

type nullIfAlsoSetInt32 struct {
	OnValues []string
}

func (m *nullIfAlsoSetInt32) Description(ctx context.Context) string {
	return m.MarkdownDescription(ctx)
}

func (m *nullIfAlsoSetInt32) MarkdownDescription(context.Context) string {
	return ""
}

func (m *nullIfAlsoSetInt32) PlanModifyInt32(ctx context.Context, req planmodifier.Int32Request, resp *planmodifier.Int32Response) {
	var attrValue basetypes.StringValue
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("additional_capabilities").AtName("registry_scanning_options").AtName("type"), &attrValue)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if slices.Contains(m.OnValues, attrValue.ValueString()) {
		resp.PlanValue = types.Int32Null()
	}
}
