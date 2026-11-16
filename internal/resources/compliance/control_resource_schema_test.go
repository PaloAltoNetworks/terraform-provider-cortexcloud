// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func controlResourceSchema(t *testing.T) schema.Schema {
	t.Helper()

	resp := &resource.SchemaResponse{}
	NewControlResource().Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema returned diagnostics: %v", resp.Diagnostics)
	}
	return resp.Schema
}

// TestControlResourceSchema_OmittedAttributesAreCleared guards the contract
// that description and subcategory are Optional only (not Computed).
//
// Removing either attribute from the configuration must plan it as null, so
// the update request sends "" and the backend value is cleared. Computed or
// UseStateForUnknown would instead carry the old value forward and leave the
// backend unchanged.
func TestControlResourceSchema_OmittedAttributesAreCleared(t *testing.T) {
	s := controlResourceSchema(t)

	for _, name := range []string{"description", "subcategory"} {
		t.Run(name, func(t *testing.T) {
			attr, ok := s.Attributes[name].(schema.StringAttribute)
			if !ok {
				t.Fatalf("%s is %T, want schema.StringAttribute", name, s.Attributes[name])
			}

			if !attr.Optional {
				t.Errorf("%s: Optional=false, want true", name)
			}
			if attr.Computed {
				t.Errorf("%s: Computed=true, want false; an omitted value must clear the backend", name)
			}
			if attr.Required {
				t.Errorf("%s: Required=true, want false", name)
			}
			if attr.Default != nil {
				t.Errorf("%s has a Default; want none", name)
			}
			if len(attr.PlanModifiers) != 0 {
				t.Errorf("%s has %d plan modifiers, want none", name, len(attr.PlanModifiers))
			}
		})
	}
}

// TestControlResourceSchema_LabelsWarnWhenNotNormalized guards that category
// and subcategory carry the validator warning about the API's Title Case
// normalization, and that it stays a warning (never an error) so existing
// configurations keep working.
func TestControlResourceSchema_LabelsWarnWhenNotNormalized(t *testing.T) {
	s := controlResourceSchema(t)

	for _, name := range []string{"category", "subcategory"} {
		t.Run(name, func(t *testing.T) {
			attr, ok := s.Attributes[name].(schema.StringAttribute)
			if !ok {
				t.Fatalf("%s is %T, want schema.StringAttribute", name, s.Attributes[name])
			}
			if len(attr.Validators) != 1 {
				t.Fatalf("%s has %d validators, want 1", name, len(attr.Validators))
			}

			req := validator.StringRequest{
				Path:        path.Root(name),
				ConfigValue: types.StringValue("my custom value"),
			}
			resp := &validator.StringResponse{}
			attr.Validators[0].ValidateString(context.Background(), req, resp)

			if resp.Diagnostics.HasError() {
				t.Errorf("%s: validator returned an error: %v", name, resp.Diagnostics)
			}
			if resp.Diagnostics.WarningsCount() != 1 {
				t.Errorf("%s: got %d warnings, want 1", name, resp.Diagnostics.WarningsCount())
			}

			req.ConfigValue = types.StringValue("My Custom Value")
			resp = &validator.StringResponse{}
			attr.Validators[0].ValidateString(context.Background(), req, resp)
			if len(resp.Diagnostics) != 0 {
				t.Errorf("%s: normalized value produced diagnostics: %v", name, resp.Diagnostics)
			}
		})
	}
}
