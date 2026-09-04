// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ListEmptyIfOtherConfigured plans an empty list when the attribute is absent
// from configuration and a mutually exclusive attribute is configured.
//
// It exists for Optional+Computed list attributes that pair with a conflicting
// attribute. Removing such a list from configuration does not plan a null:
// Terraform marks it unknown, the provider skips unknown values when building
// the request, and any server-side merge step is then free to restore the
// previous value. The net effect is that the removed value survives and both
// mutually exclusive settings end up applied.
//
// Planning a known empty list instead makes the intent explicit: the request
// carries a non-nil empty slice, encoding/json omits it via omitempty, and a
// full-replacement API call clears the association.
//
// An empty list is used rather than null deliberately. Refresh logic that
// normalises an absent server value to an empty list would disagree with a
// planned null, and Terraform would reject the apply with "Provider produced
// inconsistent result after apply".
//
// Configuration is the only reliable signal here, so this reads req.Config
// rather than req.Plan; by the time the plan is built it may already carry the
// prior value that this modifier exists to discard.
func ListEmptyIfOtherConfigured(other path.Path, elementType attr.Type) planmodifier.List {
	return &listEmptyIfOtherConfigured{
		other:       other,
		elementType: elementType,
	}
}

type listEmptyIfOtherConfigured struct {
	other       path.Path
	elementType attr.Type
}

func (m *listEmptyIfOtherConfigured) Description(ctx context.Context) string {
	return m.MarkdownDescription(ctx)
}

func (m *listEmptyIfOtherConfigured) MarkdownDescription(context.Context) string {
	return fmt.Sprintf("Plans an empty list when this attribute is omitted from configuration and `%s` is configured.", m.other)
}

func (m *listEmptyIfOtherConfigured) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	// An explicit configuration value — including an empty list — is the user's
	// decision. Only step in when the attribute is absent altogether.
	if !req.ConfigValue.IsNull() {
		return
	}

	var other attr.Value
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, m.other, &other)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// No conflicting attribute in configuration means no conflict to resolve;
	// leave the normal Optional+Computed behaviour intact so a server-managed
	// value still flows through.
	//
	// Unknown is treated the same way. When the conflicting attribute is
	// interpolated from another resource its value is not available at plan
	// time, so there is no way to tell whether it is set. Acting on a guess
	// could clear a list the user still wants. The consequence is that a
	// transition performed in the same apply as an unknown conflicting value
	// is not corrected on that run; it resolves on the next apply, once the
	// value is known.
	if other.IsNull() || other.IsUnknown() {
		return
	}

	resp.PlanValue = types.ListValueMust(m.elementType, []attr.Value{})
}
