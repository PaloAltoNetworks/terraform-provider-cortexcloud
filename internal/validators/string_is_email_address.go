// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

const regexpEmailAddress string = `(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`

func StringIsValidEmailAddress() validator.String {
	return stringvalidator.RegexMatches(
		regexp.MustCompile(regexpEmailAddress),
		"must be a valid email address",
	)
}
