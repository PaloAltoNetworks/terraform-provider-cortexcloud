// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// BIOCModel is the Terraform model for the cortexcloud_bioc resource and
// data sources. `rule_id` is the resource identity (server-assigned numeric
// ID, mirrored into ID as a string for plugin-framework compatibility) —
// BIOC names are NOT unique per tenant, so `name` is just a mutable
// attribute.
//
// XQLQuery and Definition are mutually exclusive surface-level
// representations of the polymorphic SDK `indicator` field:
//
//   - Set XQLQuery to a raw XQL string; the resource derives `is_xql=true`
//     and sends Indicator as a JSON-encoded string.
//   - Set Definition to a JSON-encoded filter-AST object (typically
//     `jsonencode(...)`); the resource derives `is_xql=false` and sends
//     Indicator as the raw JSON object.
//
// IsXQL is computed and reflects which of the two was used.
//
// The last four fields are populated only by the server (creation time,
// modification time, source, number of issues). They are read-only and
// never carried into the SDK insert payload.
type BIOCModel struct {
	ID                      types.String `tfsdk:"id"`
	RuleID                  types.Int64  `tfsdk:"rule_id"`
	Name                    types.String `tfsdk:"name"`
	Type                    types.String `tfsdk:"type"`
	Severity                types.String `tfsdk:"severity"`
	Status                  types.String `tfsdk:"status"`
	Comment                 types.String `tfsdk:"comment"`
	IsXQL                   types.Bool   `tfsdk:"is_xql"`
	XQLQuery                types.String `tfsdk:"xql_query"`
	Definition              types.String `tfsdk:"definition"`
	MitreTacticIDAndName    types.List   `tfsdk:"mitre_tactic_id_and_name"`
	MitreTechniqueIDAndName types.List   `tfsdk:"mitre_technique_id_and_name"`

	CreationTime     types.Int64  `tfsdk:"creation_time"`
	ModificationTime types.Int64  `tfsdk:"modification_time"`
	Source           types.String `tfsdk:"source"`
	NumberOfIssues   types.Int64  `tfsdk:"number_of_issues"`
}

// canonicalizeJSON re-serializes a JSON document with sorted object keys
// and no extra whitespace, so harmless cosmetic differences between the
// caller's `jsonencode(...)` output and what the server returns don't show
// up as planned diffs. Returns the input untouched if it does not parse as
// JSON — for malformed input the schema validator catches the error
// earlier.
func canonicalizeJSON(raw string) string {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return raw
	}
	// Encoder appends a trailing newline; strip it for state cleanliness.
	return strings.TrimRight(buf.String(), "\n")
}

// normalizeStatus lowercases status so plans don't drift when records
// inserted via the UI (which writes uppercase) are managed alongside
// records inserted via this provider (which writes lowercase per the
// OpenAPI enum). The live API preserves whatever casing was last written.
func normalizeStatus(s string) string {
	return strings.ToLower(s)
}

// normalizeMitre collapses the server's `[""]` placeholder back to an
// empty list. The API rewrites an empty `mitre_*` array on insert as a
// single-element array containing the empty string; without this
// normalization every plan after Create would show a phantom diff.
func normalizeMitre(in []string) []string {
	if len(in) == 1 && in[0] == "" {
		return []string{}
	}
	return in
}

// RefreshFromRemote updates the model in place with the latest fields from
// the API response.
func (m *BIOCModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *platformTypes.BIOC) {
	tflog.Debug(ctx, "Refreshing BIOC model from remote")

	m.ID = types.StringValue(strconv.Itoa(remote.RuleID))
	m.RuleID = types.Int64Value(int64(remote.RuleID))
	m.Name = types.StringValue(remote.Name)
	m.Type = types.StringValue(string(remote.Type))
	m.Severity = types.StringValue(string(remote.Severity))
	m.Status = types.StringValue(normalizeStatus(string(remote.Status)))
	m.Comment = types.StringValue(remote.Comment)
	m.IsXQL = types.BoolValue(remote.IsXQL)

	if remote.IsXQL {
		// Indicator round-trips as a JSON string; pull the unquoted value.
		var xql string
		if err := json.Unmarshal(remote.Indicator, &xql); err == nil {
			m.XQLQuery = types.StringValue(xql)
		} else {
			m.XQLQuery = types.StringValue(string(remote.Indicator))
		}
		m.Definition = types.StringNull()
	} else {
		m.Definition = types.StringValue(canonicalizeJSON(string(remote.Indicator)))
		m.XQLQuery = types.StringNull()
	}

	tactic, tacticDiags := types.ListValueFrom(ctx, types.StringType, normalizeMitre(remote.MitreTacticIDAndName))
	diags.Append(tacticDiags...)
	m.MitreTacticIDAndName = tactic

	technique, techniqueDiags := types.ListValueFrom(ctx, types.StringType, normalizeMitre(remote.MitreTechniqueIDAndName))
	diags.Append(techniqueDiags...)
	m.MitreTechniqueIDAndName = technique

	m.CreationTime = types.Int64Value(remote.CreationTime)
	m.ModificationTime = types.Int64Value(remote.ModificationTime)
	m.Source = types.StringValue(remote.Source)
	m.NumberOfIssues = types.Int64Value(int64(remote.NumberOfIssues))
}

// ToSDKBIOC converts the Terraform model into the SDK BIOC type used as
// the insert payload. The XQLQuery / Definition split is collapsed back
// into the polymorphic `indicator` field; `is_xql` is derived from which
// of the two was set. Read-only fields are not threaded into the payload.
// Returns an error if neither or both representations are populated — the
// schema-level ExactlyOneOf validator should prevent this, but we re-check
// here for defense in depth.
func (m *BIOCModel) ToSDKBIOC(ctx context.Context) (platformTypes.BIOC, diag.Diagnostics) {
	var diags diag.Diagnostics

	out := platformTypes.BIOC{
		RuleID:   int(m.RuleID.ValueInt64()),
		Name:     m.Name.ValueString(),
		Type:     enums.BIOCType(m.Type.ValueString()),
		Severity: enums.BIOCSeverity(m.Severity.ValueString()),
		Status:   enums.BIOCStatus(normalizeStatus(m.Status.ValueString())),
		Comment:  m.Comment.ValueString(),
	}

	xqlSet := !m.XQLQuery.IsNull() && !m.XQLQuery.IsUnknown()
	defSet := !m.Definition.IsNull() && !m.Definition.IsUnknown()
	switch {
	case xqlSet && defSet:
		diags.AddError(
			"Conflicting Indicator Representations",
			"Exactly one of `xql_query` or `definition` must be set, not both.",
		)
		return out, diags
	case xqlSet:
		out.IsXQL = true
		b, err := json.Marshal(m.XQLQuery.ValueString())
		if err != nil {
			diags.AddError("Failed to encode xql_query", err.Error())
			return out, diags
		}
		out.Indicator = json.RawMessage(b)
	case defSet:
		out.IsXQL = false
		raw := []byte(m.Definition.ValueString())
		if !json.Valid(raw) {
			diags.AddError(
				"Invalid Definition",
				fmt.Sprintf("`definition` must be valid JSON; got: %s", m.Definition.ValueString()),
			)
			return out, diags
		}
		out.Indicator = json.RawMessage(raw)
	default:
		diags.AddError(
			"Missing Indicator Representation",
			"Exactly one of `xql_query` or `definition` must be set.",
		)
		return out, diags
	}

	if !m.MitreTacticIDAndName.IsNull() && !m.MitreTacticIDAndName.IsUnknown() {
		var tactics []string
		diags.Append(m.MitreTacticIDAndName.ElementsAs(ctx, &tactics, false)...)
		out.MitreTacticIDAndName = tactics
	} else {
		out.MitreTacticIDAndName = []string{}
	}

	if !m.MitreTechniqueIDAndName.IsNull() && !m.MitreTechniqueIDAndName.IsUnknown() {
		var techniques []string
		diags.Append(m.MitreTechniqueIDAndName.ElementsAs(ctx, &techniques, false)...)
		out.MitreTechniqueIDAndName = techniques
	} else {
		out.MitreTechniqueIDAndName = []string{}
	}

	return out, diags
}
