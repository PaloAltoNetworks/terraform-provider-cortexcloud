// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

//var (
//	_ validator.String = NullIfAlsoSetPlanModifier{}
//	_ validator.Bool   = NullIfAlsoSetPlanModifier{}
//)

func ToLowercase() planmodifier.String {
	return &toLowercase{}
}

type toLowercase struct{}

func (m *toLowercase) Description(ctx context.Context) string {
	return m.MarkdownDescription(ctx)
}

func (m *toLowercase) MarkdownDescription(context.Context) string {
	return ""
}

func (m *toLowercase) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if !req.ConfigValue.IsNull() && !req.ConfigValue.IsUnknown() {
		req.ConfigValue = types.StringValue(strings.ToLower(req.ConfigValue.ValueString()))
		resp.PlanValue = req.ConfigValue
	}
}
