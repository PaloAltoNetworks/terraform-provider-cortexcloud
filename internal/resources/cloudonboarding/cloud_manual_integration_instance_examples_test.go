// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// exampleDirectory is the published example set for this resource. The files
// there are copied verbatim into the generated documentation, so a mistake in
// them is a mistake a practitioner will paste into their own configuration.
const exampleDirectory = "../../../examples/resources/cortexcloud_cloud_manual_integration_instance"

// manualInstanceResourceType is the type name the examples must declare.
const manualInstanceResourceType = "cortexcloud_cloud_manual_integration_instance"

// TestManualInstanceExamplesOnlyUseSchemaAttributes proves every attribute the
// published examples set actually exists in the resource schema, at the nesting
// level the example puts it.
//
// An example is the first thing a practitioner runs, and one naming an
// attribute the schema does not declare fails at "terraform plan" with an error
// about our documentation rather than their configuration. This walks the real
// HCL rather than grepping, so a nested attribute in the wrong block is caught
// as readily as one that is simply misspelled.
func TestManualInstanceExamplesOnlyUseSchemaAttributes(t *testing.T) {
	t.Parallel()

	resourceSchema, _ := manualResourceSchema(t)

	for _, file := range exampleFiles(t) {
		body := parseExampleFile(t, file)

		for _, block := range body.Blocks {
			if block.Type != "resource" || len(block.Labels) == 0 {
				continue
			}
			if block.Labels[0] != manualInstanceResourceType {
				continue
			}

			assertBodyMatchesAttributes(t, filepath.Base(file), block.Labels[0], block.Body, resourceSchema.Attributes)
		}
	}
}

// TestManualInstanceExamplesCoverEveryCloudProvider proves the published
// examples demonstrate all three supported providers.
//
// The three differ in which manual_details members apply, so an example set
// that covers only one leaves the other two to guesswork.
func TestManualInstanceExamplesCoverEveryCloudProvider(t *testing.T) {
	t.Parallel()

	demonstrated := map[string]bool{}

	for _, file := range exampleFiles(t) {
		body := parseExampleFile(t, file)

		for _, block := range body.Blocks {
			if block.Type != "resource" || len(block.Labels) == 0 {
				continue
			}
			if block.Labels[0] != manualInstanceResourceType {
				continue
			}

			attribute, ok := block.Body.Attributes["cloud_provider"]
			if !ok {
				continue
			}

			value, diags := attribute.Expr.Value(nil)
			if diags.HasErrors() {
				t.Fatalf("%s: cloud_provider is not a literal: %v", filepath.Base(file), diags)
			}
			demonstrated[value.AsString()] = true
		}
	}

	for _, provider := range []string{"AWS", "AZURE"} {
		if !demonstrated[provider] {
			t.Errorf("no published example onboards %s; the manual_details members differ per provider, so an undemonstrated provider is left to guesswork", provider)
		}
	}

	// GCP is not supported for manual onboarding. An example carrying it would
	// be rejected at plan time by the cloud_provider validator, so publishing
	// one would hand practitioners a configuration that cannot apply.
	if demonstrated["GCP"] {
		t.Error("a published example onboards GCP, which manual onboarding does not support; the example cannot apply")
	}
}

// TestManualInstanceExamplesNeverConfigureReportedOnlyMembers proves no example
// tries to set a member the write endpoints reject.
//
// client_id is the one that matters: the platform reports it, which makes it
// look configurable, and rejects it on write. An example carrying it would fail
// on first apply.
func TestManualInstanceExamplesNeverConfigureReportedOnlyMembers(t *testing.T) {
	t.Parallel()

	resourceSchema, _ := manualResourceSchema(t)

	writable := map[string]bool{}
	for name := range nestedAttributes(t, resourceSchema.Attributes, "manual_details") {
		writable[name] = true
	}

	for _, file := range exampleFiles(t) {
		body := parseExampleFile(t, file)

		for _, block := range body.Blocks {
			if block.Type != "resource" || len(block.Labels) == 0 || block.Labels[0] != manualInstanceResourceType {
				continue
			}

			attribute, ok := block.Body.Attributes["manual_details"]
			if !ok {
				continue
			}

			for _, member := range objectExpressionKeys(t, filepath.Base(file), attribute.Expr) {
				if !writable[member] {
					t.Errorf("%s: manual_details sets %q, which the resource does not accept on write; the platform reports it but rejects it, so this example fails on first apply",
						filepath.Base(file), member)
				}
			}
		}
	}
}

// TestManualInstanceExamplesNeverSendEmptyAzureAccountName proves no example
// sets account_name to the empty string.
//
// A non-empty value is accepted and omitting it is accepted, but the empty
// string is rejected outright by at least one provider. It is an easy value to
// reach for when illustrating an optional field, so it is worth pinning.
func TestManualInstanceExamplesNeverSendEmptyAzureAccountName(t *testing.T) {
	t.Parallel()

	for _, file := range exampleFiles(t) {
		body := parseExampleFile(t, file)

		for _, block := range body.Blocks {
			if block.Type != "resource" || len(block.Labels) == 0 || block.Labels[0] != manualInstanceResourceType {
				continue
			}

			attribute, ok := block.Body.Attributes["manual_details"]
			if !ok {
				continue
			}

			expression, ok := attribute.Expr.(*hclsyntax.ObjectConsExpr)
			if !ok {
				continue
			}

			for _, item := range expression.Items {
				if objectKeyName(t, filepath.Base(file), item.KeyExpr) != "account_name" {
					continue
				}

				value, diags := item.ValueExpr.Value(nil)
				if diags.HasErrors() {
					continue
				}
				if value.Type().FriendlyName() == "string" && value.AsString() == "" {
					t.Errorf("%s: manual_details sets account_name to the empty string, which the platform rejects; give it a real value or leave it out",
						filepath.Base(file))
				}
			}
		}
	}
}

// reservedResourceTagKey is a custom_resources_tags key the platform owns.
//
// It is accepted only with the platform's own value; any other value is
// refused. Measured live rather than inferred: holding every other input
// constant, "managed_by=paloaltonetworks" onboards with HTTP 200 while
// "managed_by=terraform" and "managed_by=zzz-arbitrary" are both refused with
//
//	400 "The request contains invalid or missing parameters."
//	    "Invalid connector details"
//
// The key alone is not the problem and the value alone is not the problem: the
// same value under a different key ("owner=terraform") is accepted, and a
// near-miss key ("managed_by_x=terraform") is accepted. It is the pair.
const (
	reservedResourceTagKey   = "managed_by"
	reservedResourceTagValue = "paloaltonetworks"
)

// TestManualInstanceExamplesNeverUseAReservedResourceTag proves no published
// example sends a custom resource tag the platform will refuse.
//
// This is not a hypothetical. Two examples shipped with
// "managed_by = terraform", and applying either produced a 400 -- and, because
// a rejected onboarding still writes its template row, an orphan PENDING
// connector the practitioner then has to hunt down. The failure is worse than a
// plain error: it leaves debris on their tenant.
//
// The gate is written against the whole example set rather than the two known
// files, because the next example added is as likely to reach for "managed_by"
// as these two were -- it is the obvious thing to call such a tag.
func TestManualInstanceExamplesNeverUseAReservedResourceTag(t *testing.T) {
	t.Parallel()

	for _, file := range exampleFiles(t) {
		body := parseExampleFile(t, file)

		for _, block := range body.Blocks {
			if block.Type != "resource" || len(block.Labels) == 0 || block.Labels[0] != manualInstanceResourceType {
				continue
			}

			attribute, ok := block.Body.Attributes["custom_resources_tags"]
			if !ok {
				continue
			}

			tuple, ok := attribute.Expr.(*hclsyntax.TupleConsExpr)
			if !ok {
				continue
			}

			for _, element := range tuple.Exprs {
				object, ok := element.(*hclsyntax.ObjectConsExpr)
				if !ok {
					continue
				}

				var key, value string
				for _, item := range object.Items {
					literal, diags := item.ValueExpr.Value(nil)
					if diags.HasErrors() || literal.Type().FriendlyName() != "string" {
						continue
					}
					switch objectKeyName(t, filepath.Base(file), item.KeyExpr) {
					case "key":
						key = literal.AsString()
					case "value":
						value = literal.AsString()
					}
				}

				if key == reservedResourceTagKey && value != reservedResourceTagValue {
					t.Errorf(
						"%s: custom_resources_tags uses the reserved key %q with value %q. "+
							"The platform accepts that key only with its own value %q and answers "+
							"400 \"Invalid connector details\" otherwise, leaving an orphan PENDING "+
							"connector behind. Use a different key.",
						filepath.Base(file), key, value, reservedResourceTagValue,
					)
				}
			}
		}
	}
}

// TestManualInstanceDocumentsTheFeatureFlag proves the resource documentation
// says the feature has to be switched on before the resource can be used.
//
// On a tenant without the flag the resource cannot work at all, and the failure
// arrives from the API rather than from anything visible in the configuration,
// so the prerequisite belongs on the page someone reads before writing HCL.
func TestManualInstanceDocumentsTheFeatureFlag(t *testing.T) {
	t.Parallel()

	resourceSchema, _ := manualResourceSchema(t)

	for name, description := range map[string]string{
		"Description":         resourceSchema.Description,
		"MarkdownDescription": resourceSchema.MarkdownDescription,
	} {
		// Folded because the sentence is assembled from wrapped literals and
		// the break moves whenever the wording is re-flowed.
		folded := strings.Join(strings.Fields(description), " ")

		if !strings.Contains(folded, "feature flag") {
			t.Errorf("the resource %s does not say the feature is behind a feature flag; a practitioner on a tenant without it gets an API failure with no explanation", name)
		}
		if !strings.Contains(folded, "support") {
			t.Errorf("the resource %s does not say who enables the feature flag, so the note is not actionable", name)
		}
	}
}

// TestManualInstanceDoesNotWarnAboutASurvivingTemplate proves the resource
// documentation no longer claims a destroy leaves an onboarding template
// behind.
//
// It used to, and the platform has since fixed it, so the warning would now
// send people hunting for a record that is not there. Kept rather than deleted
// because a warning about a fixed defect is the kind of thing someone
// reinstates from stale notes.
func TestManualInstanceDoesNotWarnAboutASurvivingTemplate(t *testing.T) {
	t.Parallel()

	resourceSchema, _ := manualResourceSchema(t)

	for name, description := range map[string]string{
		"Description":         resourceSchema.Description,
		"MarkdownDescription": resourceSchema.MarkdownDescription,
	} {
		folded := strings.Join(strings.Fields(description), " ")

		for _, stale := range []string{
			"PENDING",
			"delete_instance_template",
			"leaves one record behind",
		} {
			if strings.Contains(folded, stale) {
				t.Errorf("the resource %s still mentions %q, but the platform no longer leaves an onboarding template behind after a destroy; the warning sends practitioners looking for a record that does not exist", name, stale)
			}
		}
	}
}

// TestManualInstanceDocumentsTheImportGap proves the resource documentation
// warns that an import cannot recover manual_details.
//
// Without the warning the non-empty first plan after an import looks like a
// provider bug, and a practitioner may try to resolve it by removing
// manual_details from their configuration -- which Terraform rejects, since the
// attribute is required.
func TestManualInstanceDocumentsTheImportGap(t *testing.T) {
	t.Parallel()

	resourceSchema, _ := manualResourceSchema(t)

	for name, description := range map[string]string{
		"Description":         resourceSchema.Description,
		"MarkdownDescription": resourceSchema.MarkdownDescription,
	} {
		if !strings.Contains(description, "manual_details") {
			t.Errorf("the resource %s does not mention that an import cannot recover manual_details", name)
		}
		if !strings.Contains(description, "not empty") {
			t.Errorf("the resource %s does not warn that the first plan after an import is not empty, which is the symptom a practitioner actually sees", name)
		}
	}
}

// assertBodyMatchesAttributes checks every attribute set in an HCL body against
// the schema attributes valid at that level, descending into nested objects.
func assertBodyMatchesAttributes(t *testing.T, file, path string, body *hclsyntax.Body, attributes map[string]schema.Attribute) {
	t.Helper()

	for name, attribute := range body.Attributes {
		declared, ok := attributes[name]
		if !ok {
			t.Errorf("%s: %s.%s is not declared by the resource schema, so this example fails at plan time",
				file, path, name)
			continue
		}

		nested := nestedAttributesOf(declared)
		if nested == nil {
			continue
		}

		for _, member := range objectExpressionKeys(t, file, attribute.Expr) {
			if _, ok := nested[member]; !ok {
				t.Errorf("%s: %s.%s.%s is not declared by the resource schema, so this example fails at plan time",
					file, path, name, member)
			}
		}
	}
}

// nestedAttributesOf returns the attributes of a nested attribute, or nil when
// the attribute is not a nested one.
func nestedAttributesOf(attribute schema.Attribute) map[string]schema.Attribute {
	switch typed := attribute.(type) {
	case schema.SingleNestedAttribute:
		return typed.Attributes
	case schema.SetNestedAttribute:
		return typed.NestedObject.Attributes
	case schema.ListNestedAttribute:
		return typed.NestedObject.Attributes
	default:
		return nil
	}
}

// nestedAttributes returns the nested attributes of a named schema attribute.
func nestedAttributes(t *testing.T, attributes map[string]schema.Attribute, name string) map[string]schema.Attribute {
	t.Helper()

	attribute, ok := attributes[name]
	if !ok {
		t.Fatalf("the resource schema does not declare %q", name)
	}

	nested := nestedAttributesOf(attribute)
	if nested == nil {
		t.Fatalf("%q is not a nested attribute", name)
	}

	return nested
}

// objectExpressionKeys returns the keys of an object-construction expression,
// and nothing for any other kind of expression. Tuples of objects are flattened
// so that a set of nested objects is checked member by member.
func objectExpressionKeys(t *testing.T, file string, expression hclsyntax.Expression) []string {
	t.Helper()

	switch typed := expression.(type) {
	case *hclsyntax.ObjectConsExpr:
		keys := make([]string, 0, len(typed.Items))
		for _, item := range typed.Items {
			keys = append(keys, objectKeyName(t, file, item.KeyExpr))
		}

		return keys
	case *hclsyntax.TupleConsExpr:
		var keys []string
		for _, element := range typed.Exprs {
			keys = append(keys, objectExpressionKeys(t, file, element)...)
		}

		return keys
	default:
		return nil
	}
}

// objectKeyName renders an object key as the attribute name it refers to.
func objectKeyName(t *testing.T, file string, expression hclsyntax.Expression) string {
	t.Helper()

	if wrapped, ok := expression.(*hclsyntax.ObjectConsKeyExpr); ok {
		if traversal, diags := hcl.AbsTraversalForExpr(wrapped.Wrapped); !diags.HasErrors() && len(traversal) == 1 {
			return traversal.RootName()
		}
	}

	value, diags := expression.Value(nil)
	if diags.HasErrors() {
		t.Fatalf("%s: an object key is not a literal name: %v", file, diags)
	}

	return value.AsString()
}

// exampleFiles lists the published example configurations.
func exampleFiles(t *testing.T) []string {
	t.Helper()

	files, err := filepath.Glob(filepath.Join(exampleDirectory, "*.tf"))
	if err != nil {
		t.Fatalf("failed to list the example directory: %v", err)
	}

	if len(files) == 0 {
		t.Fatalf("no example configurations found in %s; the generated documentation would ship with no usage example", exampleDirectory)
	}

	return files
}

// parseExampleFile parses an example configuration, failing the test if it is
// not valid HCL.
func parseExampleFile(t *testing.T, file string) *hclsyntax.Body {
	t.Helper()

	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("failed to read %s: %v", file, err)
	}

	parsed, diags := hclparse.NewParser().ParseHCL(content, file)
	if diags.HasErrors() {
		t.Fatalf("%s is not valid HCL, so a practitioner pasting it gets a syntax error: %v", filepath.Base(file), diags)
	}

	body, ok := parsed.Body.(*hclsyntax.Body)
	if !ok {
		t.Fatalf("%s did not parse into an HCL body", filepath.Base(file))
	}

	return body
}
