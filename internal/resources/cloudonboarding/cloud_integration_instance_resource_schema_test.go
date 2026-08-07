// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// customResourcesTagsAttribute returns the custom_resources_tags attribute from
// the resource schema, failing the test if the schema no longer declares it.
func customResourcesTagsAttribute(t *testing.T) fwresource.SchemaResponse {
	t.Helper()

	resp := fwresource.SchemaResponse{}
	NewCloudIntegrationInstanceResource().Schema(context.Background(), fwresource.SchemaRequest{}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("building the schema produced errors: %v", resp.Diagnostics.Errors())
	}

	return resp
}

// tagObjectType mirrors the nested object declared by custom_resources_tags.
var tagObjectType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"key":   types.StringType,
		"value": types.StringType,
	},
}

// TestCloudIntegrationInstanceResourceRejectsEmptyCustomResourcesTags proves the
// practitioner is told at plan time that an empty tag list is not usable, rather
// than discovering it when the platform rejects the edit mid-apply.
func TestCloudIntegrationInstanceResourceRejectsEmptyCustomResourcesTags(t *testing.T) {
	t.Parallel()

	schemaResp := customResourcesTagsAttribute(t)

	attribute, ok := schemaResp.Schema.Attributes["custom_resources_tags"]
	if !ok {
		t.Fatal("schema does not declare custom_resources_tags")
	}

	setAttribute, ok := attribute.(interface {
		SetValidators() []validator.Set
	})
	if !ok {
		t.Fatalf("custom_resources_tags does not expose set validators (type %T)", attribute)
	}

	validators := setAttribute.SetValidators()
	if len(validators) == 0 {
		t.Fatal("custom_resources_tags declares no validators, so an empty list reaches the platform")
	}

	emptyTags, diags := types.SetValue(tagObjectType, []attr.Value{})
	if diags.HasError() {
		t.Fatalf("constructing the empty set failed: %v", diags.Errors())
	}

	req := validator.SetRequest{
		ConfigValue: emptyTags,
	}

	var rejected bool
	for _, v := range validators {
		resp := &validator.SetResponse{}
		v.ValidateSet(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			rejected = true
			t.Logf("empty list rejected with: %s", resp.Diagnostics.Errors()[0].Detail())
		}
	}

	if !rejected {
		t.Error("an empty custom_resources_tags list was accepted at plan time; the platform rejects it mid-apply")
	}
}

// TestCloudIntegrationInstanceResourceAcceptsPopulatedCustomResourcesTags guards
// the other side of the boundary: the validator must not reject a usable
// configuration. Without this, a validator that rejected everything would still
// satisfy the test above.
func TestCloudIntegrationInstanceResourceAcceptsPopulatedCustomResourcesTags(t *testing.T) {
	t.Parallel()

	schemaResp := customResourcesTagsAttribute(t)

	attribute, ok := schemaResp.Schema.Attributes["custom_resources_tags"]
	if !ok {
		t.Fatal("schema does not declare custom_resources_tags")
	}

	setAttribute, ok := attribute.(interface {
		SetValidators() []validator.Set
	})
	if !ok {
		t.Fatalf("custom_resources_tags does not expose set validators (type %T)", attribute)
	}

	tag, diags := types.ObjectValue(tagObjectType.AttrTypes, map[string]attr.Value{
		"key":   types.StringValue("cost_center"),
		"value": types.StringValue("engineering"),
	})
	if diags.HasError() {
		t.Fatalf("constructing the tag object failed: %v", diags.Errors())
	}

	populatedTags, diags := types.SetValue(tagObjectType, []attr.Value{tag})
	if diags.HasError() {
		t.Fatalf("constructing the populated set failed: %v", diags.Errors())
	}

	req := validator.SetRequest{
		ConfigValue: populatedTags,
	}

	for _, v := range setAttribute.SetValidators() {
		resp := &validator.SetResponse{}
		v.ValidateSet(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("a populated tag list was rejected: %v", resp.Diagnostics.Errors())
		}
	}
}

// TestCloudIntegrationInstanceResourceAllowsUnconfiguredCustomResourcesTags
// pins the attribute as optional and computed. Making it required would oblige
// the practitioner to transcribe the instance's existing tags into the
// configuration immediately after importing it, and every tag missed from that
// transcription is deleted on the next apply.
func TestCloudIntegrationInstanceResourceAllowsUnconfiguredCustomResourcesTags(t *testing.T) {
	t.Parallel()

	schemaResp := customResourcesTagsAttribute(t)

	attribute, ok := schemaResp.Schema.Attributes["custom_resources_tags"]
	if !ok {
		t.Fatal("schema does not declare custom_resources_tags")
	}

	if attribute.IsRequired() {
		t.Error("custom_resources_tags is required; an imported instance cannot be planned until its tags are transcribed by hand")
	}

	if !attribute.IsOptional() {
		t.Error("custom_resources_tags is not optional")
	}

	if !attribute.IsComputed() {
		t.Error("custom_resources_tags is not computed; the tags the platform holds cannot be reported in state")
	}

	// A null configuration must survive validation: it is the path that leaves
	// the instance's existing tags untouched.
	req := validator.SetRequest{
		ConfigValue: types.SetNull(tagObjectType),
	}

	setAttribute, ok := attribute.(interface {
		SetValidators() []validator.Set
	})
	if !ok {
		t.Fatalf("custom_resources_tags does not expose set validators (type %T)", attribute)
	}

	for _, v := range setAttribute.SetValidators() {
		resp := &validator.SetResponse{}
		v.ValidateSet(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("an unconfigured custom_resources_tags was rejected: %v", resp.Diagnostics.Errors())
		}
	}
}
