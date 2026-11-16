// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestControlLabelTitleCase(t *testing.T) {
	tests := []struct {
		name        string
		value       types.String
		wantWarning bool
	}{
		{name: "null", value: types.StringNull()},
		{name: "unknown", value: types.StringUnknown()},
		{name: "empty", value: types.StringValue("")},
		{name: "already normalized", value: types.StringValue("My Custom Category")},
		{name: "numeric", value: types.StringValue("5.1")},
		{name: "lower case", value: types.StringValue("my custom category"), wantWarning: true},
		{name: "upper case", value: types.StringValue("ACCESS CONTROL"), wantWarning: true},
		{name: "padded", value: types.StringValue(" Access Control "), wantWarning: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validator.StringRequest{
				Path:        path.Root("category"),
				ConfigValue: tt.value,
			}
			resp := &validator.StringResponse{}

			ControlLabelTitleCase().ValidateString(context.Background(), req, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("validator must never return an error, got: %v", resp.Diagnostics)
			}
			if got := resp.Diagnostics.WarningsCount() > 0; got != tt.wantWarning {
				t.Errorf("warning = %v, want %v (diags: %v)", got, tt.wantWarning, resp.Diagnostics)
			}
		})
	}
}
