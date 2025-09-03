// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

//var (
//	_ validator.String = NullIfAlsoSetPlanModifier{}
//	_ validator.Bool   = NullIfAlsoSetPlanModifier{}
//)

func ToEmptyStringIfNullOrUnknown() planmodifier.String {
	return &toEmptyStringIfNullOrUnknown{}
}

type toEmptyStringIfNullOrUnknown struct{}

func (m *toEmptyStringIfNullOrUnknown) Description(ctx context.Context) string {
	return m.MarkdownDescription(ctx)
}

func (m *toEmptyStringIfNullOrUnknown) MarkdownDescription(context.Context) string {
	return ""
}

func (m *toEmptyStringIfNullOrUnknown) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		resp.PlanValue = types.StringValue("")
	}
}
