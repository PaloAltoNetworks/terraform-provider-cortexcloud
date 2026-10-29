// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestStringUseStateForUnknownIfAttributeUnchanged(t *testing.T) {
	ctx := context.Background()

	sch := schema.Schema{
		Attributes: map[string]schema.Attribute{
			"mode":   schema.StringAttribute{Required: true},
			"target": schema.StringAttribute{Optional: true, Computed: true},
		},
	}
	objType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"mode":   tftypes.String,
		"target": tftypes.String,
	}}
	str := func(v any) tftypes.Value { return tftypes.NewValue(tftypes.String, v) }
	obj := func(mode, target tftypes.Value) tftypes.Value {
		return tftypes.NewValue(objType, map[string]tftypes.Value{"mode": mode, "target": target})
	}
	nullObj := tftypes.NewValue(objType, nil)

	tests := []struct {
		name        string
		stateMode   tftypes.Value // ignored when noState
		planMode    tftypes.Value
		noState     bool
		stateValue  types.String
		configValue types.String
		planValue   types.String
		want        types.String
	}{
		{
			name:        "mode unchanged keeps prior value",
			stateMode:   str("CLOUD"),
			planMode:    str("CLOUD"),
			stateValue:  types.StringValue("op-1"),
			configValue: types.StringNull(),
			planValue:   types.StringUnknown(),
			want:        types.StringValue("op-1"),
		},
		{
			name:        "mode changed leaves value unknown",
			stateMode:   str("OUTPOST"),
			planMode:    str("BROKER"),
			stateValue:  types.StringValue("op-1"),
			configValue: types.StringNull(),
			planValue:   types.StringUnknown(),
			want:        types.StringUnknown(),
		},
		{
			name:        "mode unknown leaves value unknown",
			stateMode:   str("OUTPOST"),
			planMode:    str(tftypes.UnknownValue),
			stateValue:  types.StringValue("op-1"),
			configValue: types.StringNull(),
			planValue:   types.StringUnknown(),
			want:        types.StringUnknown(),
		},
		{
			name:        "configured value is never overridden",
			stateMode:   str("OUTPOST"),
			planMode:    str("OUTPOST"),
			stateValue:  types.StringValue("op-1"),
			configValue: types.StringValue("op-2"),
			planValue:   types.StringValue("op-2"),
			want:        types.StringValue("op-2"),
		},
		{
			name:        "interpolated config value stays unknown",
			stateMode:   str("OUTPOST"),
			planMode:    str("OUTPOST"),
			stateValue:  types.StringValue("op-1"),
			configValue: types.StringUnknown(),
			planValue:   types.StringUnknown(),
			want:        types.StringUnknown(),
		},
		{
			name:        "null prior value stays unknown",
			stateMode:   str("CLOUD"),
			planMode:    str("CLOUD"),
			stateValue:  types.StringNull(),
			configValue: types.StringNull(),
			planValue:   types.StringUnknown(),
			want:        types.StringUnknown(),
		},
		{
			name:        "create leaves value unknown",
			noState:     true,
			planMode:    str("CLOUD"),
			stateValue:  types.StringNull(),
			configValue: types.StringNull(),
			planValue:   types.StringUnknown(),
			want:        types.StringUnknown(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateRaw := nullObj
			if !tt.noState {
				stateRaw = obj(tt.stateMode, str(tt.stateValue.ValueString()))
				if tt.stateValue.IsNull() {
					stateRaw = obj(tt.stateMode, str(nil))
				}
			}
			planTarget := str(tftypes.UnknownValue)
			if !tt.planValue.IsUnknown() {
				planTarget = str(tt.planValue.ValueString())
			}

			req := planmodifier.StringRequest{
				Path:        path.Root("target"),
				State:       tfsdk.State{Schema: sch, Raw: stateRaw},
				Plan:        tfsdk.Plan{Schema: sch, Raw: obj(tt.planMode, planTarget)},
				StateValue:  tt.stateValue,
				ConfigValue: tt.configValue,
				PlanValue:   tt.planValue,
			}
			resp := &planmodifier.StringResponse{PlanValue: req.PlanValue}

			StringUseStateForUnknownIfAttributeUnchanged(path.Root("mode")).PlanModifyString(ctx, req, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
			}
			if !resp.PlanValue.Equal(tt.want) {
				t.Errorf("PlanValue = %v, want %v", resp.PlanValue, tt.want)
			}
		})
	}
}
