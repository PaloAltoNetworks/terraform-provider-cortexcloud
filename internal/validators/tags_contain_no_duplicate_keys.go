// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"

	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

func TagsContainNoDuplicateKeys() tagsContainNoDuplicateKeys {
	return tagsContainNoDuplicateKeys{}
}

type tagsContainNoDuplicateKeys struct {}

// Description returns a plain text description of the validator's behavior.
func (v tagsContainNoDuplicateKeys) Description(ctx context.Context) string {
	return "ensure that no two tags in the collection have the same key value"
}

// MarkdownDescription returns a markdown formatted description of the validator's behavior.
func (v tagsContainNoDuplicateKeys) MarkdownDescription(ctx context.Context) string {
	return "ensure that no two tags in the collection have the same key value"
}

// ValidateSet performs the validation logic for the validator.
func (v tagsContainNoDuplicateKeys) ValidateSet(ctx context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	var tags []cloudOnboardingTypes.Tag
	resp.Diagnostics.Append(req.ConfigValue.ElementsAs(ctx, &tags, false)...)
	if resp.Diagnostics.HasError() {
		 return
	}

	knownValues := make(map[string]struct{})

	for i, tag := range tags {
		if _, exists := knownValues[tag.Key]; !exists {
			knownValues[tag.Key] = struct{}{}	
		} else {
			resp.Diagnostics.AddAttributeError(
				req.Path.AtSetValue(req.ConfigValue.Elements()[i]),
				"Duplicate Tag Value",
				fmt.Sprintf("The key attribute must be unique for each tag, but the value %q is repeated.", tag.Key),
			)
		}
	}
}
