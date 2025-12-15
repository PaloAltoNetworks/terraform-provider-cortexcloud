// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func ToNullStringIfUnknown() planmodifier.String {
	return &toNullStringIfUnknown{}
}

type toNullStringIfUnknown struct{}

func (m *toNullStringIfUnknown) Description(ctx context.Context) string {
	return m.MarkdownDescription(ctx)
}

func (m *toNullStringIfUnknown) MarkdownDescription(context.Context) string {
	return ""
}

func (m *toNullStringIfUnknown) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsUnknown() {
		resp.PlanValue = types.StringNull()
	}
}
