package planmodifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// StringUseStateIfConfigUnchanged returns a planmodifier.String that uses the state
// value if no configurable attributes have changed.
func StringUseStateIfConfigUnchanged(paths []path.Path) planmodifier.String {
	return &stringUseStateIfConfigUnchanged{
		paths: paths,
	}
}

type stringUseStateIfConfigUnchanged struct {
	paths []path.Path
}

// Description returns a human-readable description of the plan modifier.
func (m *stringUseStateIfConfigUnchanged) Description(ctx context.Context) string {
	return "Uses the state value if no configurable attributes have changed."
}

// MarkdownDescription returns a markdown-formatted description of the plan
// modifier.
func (m *stringUseStateIfConfigUnchanged) MarkdownDescription(ctx context.Context) string {
	return "Uses the state value if no configurable attributes have changed."
}

// PlanModifyString implements the planmodifier.String interface.
func (m *stringUseStateIfConfigUnchanged) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Do nothing if the plan value is already known or the resource is being created.
	if !resp.PlanValue.IsUnknown() || req.State.Raw.IsNull() {
		return
	}

	// Do nothing if there is no state value.
	if req.StateValue.IsNull() {
		return
	}

	for _, p := range m.paths {
		var stateValue basetypes.StringValue
		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, p, &stateValue)...)
		if resp.Diagnostics.HasError() {
			return
		}

		var planValue basetypes.StringValue
		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, p, &planValue)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if !stateValue.Equal(planValue) {
			// A configurable attribute has changed, so don't use state.
			return
		}
	}

	// No configurable attributes have changed, so use the state value.
	resp.PlanValue = req.StateValue
}
