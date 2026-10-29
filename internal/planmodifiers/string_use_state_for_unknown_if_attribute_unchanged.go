// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// StringUseStateForUnknownIfAttributeUnchanged behaves like
// stringplanmodifier.UseStateForUnknown, but only copies the prior state value
// into the plan while the attribute at `other` keeps its prior value.
//
// It exists for Optional+Computed attributes whose meaning depends on another
// attribute. Plain UseStateForUnknown would carry the old value forward even
// after the controlling attribute changes. A full-replacement update then sends
// a value that no longer fits the new configuration. For example, an old
// outpost ID could be sent with a new scanning mode.
//
// When `other` changes, the plan value stays unknown. The provider then omits
// it from the request, and whatever the API reports after apply (a new value
// or nothing) is stored in state.
//
// If `other` is unknown at plan time, the modifier cannot tell whether it
// changed, so it leaves the value unknown. That is the safe choice: no stale
// value can be sent.
func StringUseStateForUnknownIfAttributeUnchanged(other path.Path) planmodifier.String {
	return &stringUseStateForUnknownIfAttributeUnchanged{other: other}
}

type stringUseStateForUnknownIfAttributeUnchanged struct {
	other path.Path
}

func (m *stringUseStateForUnknownIfAttributeUnchanged) Description(ctx context.Context) string {
	return m.MarkdownDescription(ctx)
}

func (m *stringUseStateForUnknownIfAttributeUnchanged) MarkdownDescription(context.Context) string {
	return fmt.Sprintf("Once set, the value of this attribute in state will not change while `%s` is unchanged.", m.other)
}

func (m *stringUseStateForUnknownIfAttributeUnchanged) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Creating the resource: there is no prior value to keep.
	if req.State.Raw.IsNull() {
		return
	}
	// Destroying the resource.
	if req.Plan.Raw.IsNull() {
		return
	}
	// Nothing to keep.
	if req.StateValue.IsNull() {
		return
	}
	// Only fill in values the framework marked unknown, i.e. computed and not
	// set in configuration. A configured value always wins.
	if !req.PlanValue.IsUnknown() {
		return
	}
	// Interpolated configuration values are unknown too; leave them alone.
	if req.ConfigValue.IsUnknown() {
		return
	}

	var planOther, stateOther types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, m.other, &planOther)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, m.other, &stateOther)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if planOther.IsUnknown() || !planOther.Equal(stateOther) {
		return
	}

	resp.PlanValue = req.StateValue
}
