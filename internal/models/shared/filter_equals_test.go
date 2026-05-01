package models

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// FilterRangeInt64Model.Equals
// ---------------------------------------------------------------------------

func TestFilterRangeInt64Model_Equals_Identical(t *testing.T) {
	a := FilterRangeInt64Model{From: types.Int64Value(1), To: types.Int64Value(10)}
	b := FilterRangeInt64Model{From: types.Int64Value(1), To: types.Int64Value(10)}
	if !a.Equals(b) {
		t.Error("expected equal FilterRangeInt64Model to return true")
	}
}

func TestFilterRangeInt64Model_Equals_DifferentFrom(t *testing.T) {
	a := FilterRangeInt64Model{From: types.Int64Value(1), To: types.Int64Value(10)}
	b := FilterRangeInt64Model{From: types.Int64Value(2), To: types.Int64Value(10)}
	if a.Equals(b) {
		t.Error("expected different From to return false")
	}
}

func TestFilterRangeInt64Model_Equals_DifferentTo(t *testing.T) {
	a := FilterRangeInt64Model{From: types.Int64Value(1), To: types.Int64Value(10)}
	b := FilterRangeInt64Model{From: types.Int64Value(1), To: types.Int64Value(20)}
	if a.Equals(b) {
		t.Error("expected different To to return false")
	}
}

func TestFilterRangeInt64Model_Equals_NullVsValue(t *testing.T) {
	a := FilterRangeInt64Model{From: types.Int64Null(), To: types.Int64Value(10)}
	b := FilterRangeInt64Model{From: types.Int64Value(1), To: types.Int64Value(10)}
	if a.Equals(b) {
		t.Error("expected null vs value From to return false")
	}
}

func TestFilterRangeInt64Model_Equals_BothNull(t *testing.T) {
	a := FilterRangeInt64Model{From: types.Int64Null(), To: types.Int64Null()}
	b := FilterRangeInt64Model{From: types.Int64Null(), To: types.Int64Null()}
	if !a.Equals(b) {
		t.Error("expected both null to return true")
	}
}

// ---------------------------------------------------------------------------
// FilterGreaterOrLessThanInt64Model.Equals
// ---------------------------------------------------------------------------

func TestFilterGreaterOrLessThanInt64Model_Equals_Identical(t *testing.T) {
	a := FilterGreaterOrLessThanInt64Model{Condition: types.StringValue("gt"), Value: types.Int64Value(5)}
	b := FilterGreaterOrLessThanInt64Model{Condition: types.StringValue("gt"), Value: types.Int64Value(5)}
	if !a.Equals(b) {
		t.Error("expected equal FilterGreaterOrLessThanInt64Model to return true")
	}
}

func TestFilterGreaterOrLessThanInt64Model_Equals_CaseInsensitive(t *testing.T) {
	a := FilterGreaterOrLessThanInt64Model{Condition: types.StringValue("GT"), Value: types.Int64Value(5)}
	b := FilterGreaterOrLessThanInt64Model{Condition: types.StringValue("gt"), Value: types.Int64Value(5)}
	if !a.Equals(b) {
		t.Error("expected case-insensitive Condition comparison to return true")
	}
}

func TestFilterGreaterOrLessThanInt64Model_Equals_DifferentCondition(t *testing.T) {
	a := FilterGreaterOrLessThanInt64Model{Condition: types.StringValue("gt"), Value: types.Int64Value(5)}
	b := FilterGreaterOrLessThanInt64Model{Condition: types.StringValue("lt"), Value: types.Int64Value(5)}
	if a.Equals(b) {
		t.Error("expected different Condition to return false")
	}
}

func TestFilterGreaterOrLessThanInt64Model_Equals_DifferentValue(t *testing.T) {
	a := FilterGreaterOrLessThanInt64Model{Condition: types.StringValue("gt"), Value: types.Int64Value(5)}
	b := FilterGreaterOrLessThanInt64Model{Condition: types.StringValue("gt"), Value: types.Int64Value(10)}
	if a.Equals(b) {
		t.Error("expected different Value to return false")
	}
}

func TestFilterGreaterOrLessThanInt64Model_Equals_NullCondition(t *testing.T) {
	a := FilterGreaterOrLessThanInt64Model{Condition: types.StringNull(), Value: types.Int64Value(5)}
	b := FilterGreaterOrLessThanInt64Model{Condition: types.StringValue("gt"), Value: types.Int64Value(5)}
	if a.Equals(b) {
		t.Error("expected null vs value Condition to return false")
	}
}

// ---------------------------------------------------------------------------
// NestedFilterModel.Equals
// ---------------------------------------------------------------------------

func TestNestedFilterModel_Equals_Identical(t *testing.T) {
	a := NestedFilterModel{
		SearchField: types.StringValue("host"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("foo"),
	}
	b := NestedFilterModel{
		SearchField: types.StringValue("host"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("foo"),
	}
	if !a.Equals(b) {
		t.Error("expected equal NestedFilterModel to return true")
	}
}

func TestNestedFilterModel_Equals_CaseInsensitive(t *testing.T) {
	a := NestedFilterModel{
		SearchField: types.StringValue("HOST"),
		SearchType:  types.StringValue("EXACT"),
		SearchValue: types.StringValue("FOO"),
	}
	b := NestedFilterModel{
		SearchField: types.StringValue("host"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("foo"),
	}
	if !a.Equals(b) {
		t.Error("expected case-insensitive comparison to return true")
	}
}

func TestNestedFilterModel_Equals_DifferentSearchField(t *testing.T) {
	a := NestedFilterModel{
		SearchField: types.StringValue("host"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("foo"),
	}
	b := NestedFilterModel{
		SearchField: types.StringValue("name"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("foo"),
	}
	if a.Equals(b) {
		t.Error("expected different SearchField to return false")
	}
}

func TestNestedFilterModel_Equals_DifferentSearchType(t *testing.T) {
	a := NestedFilterModel{
		SearchField: types.StringValue("host"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("foo"),
	}
	b := NestedFilterModel{
		SearchField: types.StringValue("host"),
		SearchType:  types.StringValue("partial"),
		SearchValue: types.StringValue("foo"),
	}
	if a.Equals(b) {
		t.Error("expected different SearchType to return false")
	}
}

func TestNestedFilterModel_Equals_DifferentSearchValue(t *testing.T) {
	a := NestedFilterModel{
		SearchField: types.StringValue("host"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("foo"),
	}
	b := NestedFilterModel{
		SearchField: types.StringValue("host"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("bar"),
	}
	if a.Equals(b) {
		t.Error("expected different SearchValue to return false")
	}
}

func TestNestedFilterModel_Equals_NullVsValueSearchField(t *testing.T) {
	a := NestedFilterModel{
		SearchField: types.StringNull(),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("foo"),
	}
	b := NestedFilterModel{
		SearchField: types.StringValue("host"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("foo"),
	}
	if a.Equals(b) {
		t.Error("expected null vs value SearchField to return false")
	}
}

func TestNestedFilterModel_Equals_BothNullSearchField(t *testing.T) {
	a := NestedFilterModel{
		SearchField: types.StringNull(),
		SearchType:  types.StringNull(),
		SearchValue: types.StringNull(),
	}
	b := NestedFilterModel{
		SearchField: types.StringNull(),
		SearchType:  types.StringNull(),
		SearchValue: types.StringNull(),
	}
	if !a.Equals(b) {
		t.Error("expected both null fields to return true")
	}
}

func TestNestedFilterModel_Equals_WithAndChildren(t *testing.T) {
	child := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	a := NestedFilterModel{And: []NestedFilterModel{child}}
	b := NestedFilterModel{And: []NestedFilterModel{child}}
	if !a.Equals(b) {
		t.Error("expected equal AND children to return true")
	}
}

func TestNestedFilterModel_Equals_DifferentAndLength(t *testing.T) {
	child := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	a := NestedFilterModel{And: []NestedFilterModel{child}}
	b := NestedFilterModel{And: []NestedFilterModel{child, child}}
	if a.Equals(b) {
		t.Error("expected different AND lengths to return false")
	}
}

func TestNestedFilterModel_Equals_DifferentAndChildren(t *testing.T) {
	child1 := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	child2 := NestedFilterModel{
		SearchField: types.StringValue("f2"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v2"),
	}
	a := NestedFilterModel{And: []NestedFilterModel{child1}}
	b := NestedFilterModel{And: []NestedFilterModel{child2}}
	if a.Equals(b) {
		t.Error("expected different AND children to return false")
	}
}

func TestNestedFilterModel_Equals_WithOrChildren(t *testing.T) {
	child := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	a := NestedFilterModel{Or: []NestedFilterModel{child}}
	b := NestedFilterModel{Or: []NestedFilterModel{child}}
	if !a.Equals(b) {
		t.Error("expected equal OR children to return true")
	}
}

func TestNestedFilterModel_Equals_NilVsNonNilAnd(t *testing.T) {
	child := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	a := NestedFilterModel{And: nil}
	b := NestedFilterModel{And: []NestedFilterModel{child}}
	if a.Equals(b) {
		t.Error("expected nil vs non-nil AND to return false")
	}
}

func TestNestedFilterModel_Equals_DeepRecursive(t *testing.T) {
	leaf := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	inner := NestedFilterModel{And: []NestedFilterModel{leaf}}
	a := NestedFilterModel{Or: []NestedFilterModel{inner}}
	b := NestedFilterModel{Or: []NestedFilterModel{inner}}
	if !a.Equals(b) {
		t.Error("expected deeply nested equal filters to return true")
	}
}

func TestNestedFilterModel_Equals_DeepRecursive_Different(t *testing.T) {
	leaf1 := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	leaf2 := NestedFilterModel{
		SearchField: types.StringValue("f2"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v2"),
	}
	innerA := NestedFilterModel{And: []NestedFilterModel{leaf1}}
	innerB := NestedFilterModel{And: []NestedFilterModel{leaf2}}
	a := NestedFilterModel{Or: []NestedFilterModel{innerA}}
	b := NestedFilterModel{Or: []NestedFilterModel{innerB}}
	if a.Equals(b) {
		t.Error("expected deeply nested different filters to return false")
	}
}

// ---------------------------------------------------------------------------
// RootFilterModel.Equals
// ---------------------------------------------------------------------------

func TestRootFilterModel_Equals_Identical(t *testing.T) {
	child := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	a := RootFilterModel{And: []NestedFilterModel{child}}
	b := RootFilterModel{And: []NestedFilterModel{child}}
	if !a.Equals(&b) {
		t.Error("expected equal RootFilterModel to return true")
	}
}

func TestRootFilterModel_Equals_BothEmpty(t *testing.T) {
	a := RootFilterModel{}
	b := RootFilterModel{}
	if !a.Equals(&b) {
		t.Error("expected both empty RootFilterModel to return true")
	}
}

func TestRootFilterModel_Equals_DifferentAndChildren(t *testing.T) {
	child1 := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	child2 := NestedFilterModel{
		SearchField: types.StringValue("f2"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v2"),
	}
	a := RootFilterModel{And: []NestedFilterModel{child1}}
	b := RootFilterModel{And: []NestedFilterModel{child2}}
	if a.Equals(&b) {
		t.Error("expected different AND children to return false")
	}
}

func TestRootFilterModel_Equals_DifferentOrChildren(t *testing.T) {
	child1 := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	child2 := NestedFilterModel{
		SearchField: types.StringValue("f2"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v2"),
	}
	a := RootFilterModel{Or: []NestedFilterModel{child1}}
	b := RootFilterModel{Or: []NestedFilterModel{child2}}
	if a.Equals(&b) {
		t.Error("expected different OR children to return false")
	}
}

func TestRootFilterModel_Equals_NilVsNonNilAnd(t *testing.T) {
	child := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	a := RootFilterModel{And: nil}
	b := RootFilterModel{And: []NestedFilterModel{child}}
	if a.Equals(&b) {
		t.Error("expected nil vs non-nil AND to return false")
	}
}

func TestRootFilterModel_Equals_NilVsNonNilOr(t *testing.T) {
	child := NestedFilterModel{
		SearchField: types.StringValue("f1"),
		SearchType:  types.StringValue("exact"),
		SearchValue: types.StringValue("v1"),
	}
	a := RootFilterModel{Or: nil}
	b := RootFilterModel{Or: []NestedFilterModel{child}}
	if a.Equals(&b) {
		t.Error("expected nil vs non-nil OR to return false")
	}
}
