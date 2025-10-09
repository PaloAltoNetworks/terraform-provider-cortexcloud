package models

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type FilterRangeInt64Model struct {
	From types.Int64 `tfsdk:"from"`
	To types.Int64 `tfsdk:"to"`
}

type FilterGreaterOrLessThanInt64Model struct {
	Condition types.String `tfsdk:"condition"`
	Value types.Int64 `tfsdk:"value"`
}
