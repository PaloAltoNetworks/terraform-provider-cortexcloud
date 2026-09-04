// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// testSchema mirrors the shape the modifier is used with: a list attribute
// guarded by a conflicting string attribute.
func testSchema() schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"other": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"target": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.Int64Type,
			},
		},
	}
}

// testConfig builds a tfsdk.Config with the two attributes set to the supplied
// raw values.
func testConfig(t *testing.T, other, target tftypes.Value) tfsdk.Config {
	t.Helper()

	objType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"other":  tftypes.String,
			"target": tftypes.List{ElementType: tftypes.Number},
		},
	}

	return tfsdk.Config{
		Schema: testSchema(),
		Raw: tftypes.NewValue(objType, map[string]tftypes.Value{
			"other":  other,
			"target": target,
		}),
	}
}

func listOfInts(vals ...int64) tftypes.Value {
	elems := make([]tftypes.Value, 0, len(vals))
	for _, v := range vals {
		elems = append(elems, tftypes.NewValue(tftypes.Number, v))
	}
	return tftypes.NewValue(tftypes.List{ElementType: tftypes.Number}, elems)
}

func nullList() tftypes.Value {
	return tftypes.NewValue(tftypes.List{ElementType: tftypes.Number}, nil)
}

func TestListEmptyIfOtherConfigured(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		// raw config values for the whole object
		other  tftypes.Value
		target tftypes.Value
		// configValue is what the framework hands the modifier for the
		// attribute under modification. Stated explicitly rather than derived
		// from target, so a bug in the harness cannot masquerade as a bug in
		// the modifier.
		configValue types.List
		// the plan value the framework hands us before modification
		planValue types.List
		// expectations
		wantEmptyList bool
		wantUnchanged bool
	}{
		{
			// The reported bug: user removed the list and set the conflicting
			// attribute. Plan arrives unknown; we must pin it to an empty list
			// so the value is cleared on the wire.
			name:          "target absent from config and other configured plans empty list",
			other:         tftypes.NewValue(tftypes.String, `{"AND":[]}`),
			target:        nullList(),
			configValue:   types.ListNull(types.Int64Type),
			planValue:     types.ListUnknown(types.Int64Type),
			wantEmptyList: true,
		},
		{
			// Negative control. Without this, an implementation that always
			// returned an empty list would pass the suite while silently
			// discarding the user's configured values.
			name:          "target configured is left untouched even when other is configured",
			other:         tftypes.NewValue(tftypes.String, `{"AND":[]}`),
			target:        listOfInts(56),
			configValue:   types.ListValueMust(types.Int64Type, []attr.Value{types.Int64Value(56)}),
			planValue:     types.ListValueMust(types.Int64Type, []attr.Value{types.Int64Value(56)}),
			wantUnchanged: true,
		},
		{
			// Negative control. No conflict, so today's Computed behaviour
			// (server value flows through) must be preserved.
			name:          "neither configured is left untouched",
			other:         tftypes.NewValue(tftypes.String, nil),
			target:        nullList(),
			configValue:   types.ListNull(types.Int64Type),
			planValue:     types.ListUnknown(types.Int64Type),
			wantUnchanged: true,
		},
		{
			// An explicit empty list is a user decision; leave it alone.
			name:          "target explicitly empty is left untouched",
			other:         tftypes.NewValue(tftypes.String, `{"AND":[]}`),
			target:        listOfInts(),
			configValue:   types.ListValueMust(types.Int64Type, []attr.Value{}),
			planValue:     types.ListValueMust(types.Int64Type, []attr.Value{}),
			wantUnchanged: true,
		},
		{
			// other unknown at plan time (interpolated from another resource):
			// we cannot tell whether it is set, so we must not act.
			name:          "other unknown is left untouched",
			other:         tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
			target:        nullList(),
			configValue:   types.ListNull(types.Int64Type),
			planValue:     types.ListUnknown(types.Int64Type),
			wantUnchanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := ListEmptyIfOtherConfigured(path.Root("other"), types.Int64Type)

			req := planmodifier.ListRequest{
				Path:        path.Root("target"),
				Config:      testConfig(t, tt.other, tt.target),
				PlanValue:   tt.planValue,
				ConfigValue: tt.configValue,
			}
			resp := &planmodifier.ListResponse{PlanValue: tt.planValue}

			m.PlanModifyList(ctx, req, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics.Errors())
			}

			if tt.wantUnchanged {
				if !resp.PlanValue.Equal(tt.planValue) {
					t.Errorf("PlanValue = %v, want it left as %v", resp.PlanValue, tt.planValue)
				}
				return
			}

			if tt.wantEmptyList {
				if resp.PlanValue.IsUnknown() || resp.PlanValue.IsNull() {
					t.Fatalf("PlanValue = %v, want a known empty list", resp.PlanValue)
				}
				if got := len(resp.PlanValue.Elements()); got != 0 {
					t.Errorf("PlanValue has %d elements, want 0", got)
				}
			}
		})
	}
}
