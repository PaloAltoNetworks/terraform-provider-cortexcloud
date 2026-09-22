// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	platformModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// BIOCResource manages a single Cortex BIOC (Behavioral Indicator of
// Compromise) via the upsert `/public_api/v1/bioc/insert` endpoint. The
// server-assigned `rule_id` is the resource identity — BIOC names are not
// unique per tenant, so every CRUD path keys on `rule_id`. A name change
// is just another field edit on the same `rule_id`, so it is applied in
// place by a single API call.
var (
	_ resource.Resource                     = &BIOCResource{}
	_ resource.ResourceWithImportState      = &BIOCResource{}
	_ resource.ResourceWithConfigValidators = &BIOCResource{}
)

// NewBIOCResource is a helper function to simplify the provider implementation.
func NewBIOCResource() resource.Resource {
	return &BIOCResource{}
}

// biocTypeValues, biocSeverityValues, biocStatusValues return the
// documented enum values as []string for use with stringvalidator.OneOf,
// so the TF schema validators stay in sync with the SDK constants without
// duplicating the literal sets.
func biocTypeValues() []string {
	all := enums.BIOCTypes()
	out := make([]string, len(all))
	for i, v := range all {
		out[i] = string(v)
	}
	return out
}

func biocSeverityValues() []string {
	all := enums.BIOCSeverities()
	out := make([]string, len(all))
	for i, v := range all {
		out[i] = string(v)
	}
	return out
}

// biocStatusValues returns the canonical lowercase status set plus the
// uppercase equivalents — the live API preserves whatever casing was last
// written, and records inserted via the Cortex UI come back uppercase, so
// the schema must accept both. ToSDKBIOC re-canonicalizes to lowercase on
// write.
func biocStatusValues() []string {
	all := enums.BIOCStatuses()
	out := make([]string, 0, len(all)*2)
	for _, v := range all {
		out = append(out, string(v))
		out = append(out, strings.ToUpper(string(v)))
	}
	return out
}

// BIOCResource is the resource implementation.
type BIOCResource struct {
	client *platform.Client
}

func (r *BIOCResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_bioc"
}

func (r *BIOCResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a single Behavioral Indicator of Compromise (BIOC) in Cortex. " +
			"Backed by the upsert `/public_api/v1/bioc/insert` endpoint: every " +
			"edit submits the server-assigned `rule_id` carried in state so the " +
			"API overwrites the existing record in place. A change to `name` is " +
			"just another field update on that `rule_id`, so it preserves the " +
			"record's identity rather than recreating it. BIOC names are NOT " +
			"unique per tenant: two `cortexcloud_bioc` resources may share the " +
			"same `name` and will produce two distinct `rule_id`s.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Mirror of `rule_id` as a string; the resource identity used for " +
					"state addressing. Computed because the value is server-assigned.",
				Computed: true,
			},
			"rule_id": schema.Int64Attribute{
				Description: "Server-assigned numeric ID — the record's canonical identity. " +
					"The upsert path keys on this value, so it is stable across every " +
					"update, including a rename of `name`.",
				Computed: true,
			},
			"name": schema.StringAttribute{
				Description: "BIOC display name. Not unique per tenant — two BIOCs may " +
					"share the same name with different `rule_id`s. Changes are applied " +
					"in place via the `rule_id`-keyed upsert path.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"type": schema.StringAttribute{
				Description: "BIOC category. Documented values come from `enums.BIOCTypes()`.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(biocTypeValues()...),
				},
			},
			"severity": schema.StringAttribute{
				Description: "BIOC severity. Documented values come from " +
					"`enums.BIOCSeverities()` — the namespaced `SEV_NNN_X` form " +
					"the live API accepts on both reads and writes.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(biocSeverityValues()...),
				},
			},
			"status": schema.StringAttribute{
				Description: "BIOC status. Accepts both lowercase (`enabled`/`disabled` per " +
					"the OpenAPI enum) and uppercase (`ENABLED`/`DISABLED` as the Cortex " +
					"UI writes). The provider canonicalizes to lowercase on write so plans " +
					"stay quiet across a mixed UI-and-Terraform-managed tenant.",
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(string(enums.BIOCStatusEnabled)),
				Validators: []validator.String{
					stringvalidator.OneOf(biocStatusValues()...),
				},
			},
			"comment": schema.StringAttribute{
				Description: "Free-form comment.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"is_xql": schema.BoolAttribute{
				Description: "Computed: `true` when `xql_query` is set, `false` when " +
					"`definition` is set. Derived from which of the two indicator " +
					"representations was configured.",
				Computed: true,
			},
			"xql_query": schema.StringAttribute{
				Description: "Raw XQL query that defines the BIOC behavior. Exactly one " +
					"of `xql_query` or `definition` must be set.",
				Optional: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"definition": schema.StringAttribute{
				Description: "JSON-encoded filter-AST object that defines the BIOC behavior " +
					"(use `jsonencode(...)`). Exactly one of `xql_query` or `definition` " +
					"must be set. The provider re-canonicalizes the JSON on read so " +
					"cosmetic differences from server-side normalization don't surface " +
					"as plan diffs.",
				Optional: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"mitre_tactic_id_and_name": schema.ListAttribute{
				Description: "MITRE ATT&CK tactic identifiers (e.g. `TA0001 - Initial Access`).",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"mitre_technique_id_and_name": schema.ListAttribute{
				Description: "MITRE ATT&CK technique identifiers (e.g. `T1059 - Command and Scripting Interpreter`).",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"creation_time": schema.Int64Attribute{
				Description: "Unix epoch milliseconds when the BIOC was first created. " +
					"Stable across updates, including a rename, since the record is " +
					"upserted in place rather than recreated.",
				Computed: true,
			},
			"modification_time": schema.Int64Attribute{
				Description: "Unix epoch milliseconds of the most recent update.",
				Computed:    true,
			},
			"source": schema.StringAttribute{
				Description: "Human-readable origin of the most recent write — typically " +
					"`Public API user (key #<id>)` for API-key-authored records, or a user " +
					"email for UI/SSO-authored records. Useful for detecting out-of-band drift.",
				Computed: true,
			},
			"number_of_issues": schema.Int64Attribute{
				Description: "Count of issues this BIOC has fired on. Server-maintained.",
				Computed:    true,
			},
		},
	}
}

// ConfigValidators enforces ExactlyOneOf{xql_query, definition} at plan
// time. Both fields are model-level optional so the schema can carry
// either; this validator catches misconfiguration before any API call.
func (r *BIOCResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.ExactlyOneOf(
			path.MatchRoot("xql_query"),
			path.MatchRoot("definition"),
		),
	}
}

func (r *BIOCResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	clients, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedResourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}
	r.client = clients.Platform
}

// upsertSingle posts a single BIOC to /bioc/insert. The endpoint is
// natively upsert: when the payload carries `rule_id`, the matching record
// appears in updated_objects; when it does not, the new record appears in
// added_objects. The endpoint's `errors` array carries any per-record
// failures (and the SDK already recovers those from HTTP-400-with-success-
// body responses).
//
// We treat the call as successful when `errors` is empty AND at least one
// added/updated record is reported. The reported rule_id flows back to the
// caller via the returned int — needed by Create to learn the
// server-assigned ID for the new record.
func (r *BIOCResource) upsertSingle(ctx context.Context, bioc platformTypes.BIOC) (int, error) {
	resp, err := r.client.InsertBIOCs(ctx, []platformTypes.BIOC{bioc})
	if err != nil {
		return 0, err
	}
	if len(resp.Errors) > 0 {
		msgs := make([]string, 0, len(resp.Errors))
		for _, e := range resp.Errors {
			msgs = append(msgs, fmt.Sprintf("index %d: %s", e.Index, e.Status))
		}
		return 0, fmt.Errorf("bioc/insert errors: %s", strings.Join(msgs, "; "))
	}
	switch {
	case len(resp.AddedObjects) == 1:
		return resp.AddedObjects[0].ID, nil
	case len(resp.UpdatedObjects) == 1:
		return resp.UpdatedObjects[0].ID, nil
	default:
		return 0, fmt.Errorf("bioc/insert returned no added or updated objects and no errors")
	}
}

// deleteByRuleID removes the record with the given server-assigned
// rule_id via the filter-bodied /bioc/delete endpoint. Used by the Delete
// CRUD method (the API exposes no by-ID delete path).
//
// rule_id is undocumented in the OpenAPI filter enum for /bioc/delete but
// accepted by the live API on EQ — verified against a live tenant. It is
// the only safe identity-based delete: deleting by `name` would risk
// removing co-named BIOCs.
//
// A zero-length return slice means the filter matched nothing. We treat
// that as success (idempotent delete).
func (r *BIOCResource) deleteByRuleID(ctx context.Context, ruleID int) error {
	_, err := r.client.DeleteBIOCs(ctx, platformTypes.DeleteBIOCsRequest{
		Filters: []platformTypes.BIOCFilter{
			{Field: "rule_id", Operator: "EQ", Value: ruleID},
		},
	})
	return err
}

func (r *BIOCResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan platformModels.BIOCModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload, payloadDiags := plan.ToSDKBIOC(ctx)
	resp.Diagnostics.Append(payloadDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Names are not unique; do NOT pre-flight by name. A plain insert
	// always creates a new record with a fresh rule_id.
	ruleID, err := r.upsertSingle(ctx, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating BIOC", err.Error())
		return
	}

	remote, err := r.client.FindBIOCByID(ctx, ruleID)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading BIOC After Create", err.Error())
		return
	}
	if remote == nil {
		resp.Diagnostics.AddError(
			"BIOC Not Found After Create",
			fmt.Sprintf("bioc/get returned no match for rule_id=%d after insert", ruleID),
		)
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *BIOCResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state platformModels.BIOCModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	remote, err := r.client.FindBIOCByID(ctx, int(state.RuleID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Error Reading BIOC", err.Error())
		return
	}
	if remote == nil {
		resp.Diagnostics.AddWarning(
			"BIOC Not Found",
			fmt.Sprintf("No BIOC found with rule_id=%d, removing from state.", state.RuleID.ValueInt64()),
		)
		resp.State.RemoveResource(ctx)
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update applies content changes in place via the rule_id-keyed upsert.
// The SDK payload carries the server-assigned `rule_id` from prior state,
// so the API matches the existing record by its canonical identity and
// overwrites it in a single call — even when `name` changed. A rename is
// therefore just another field edit: `rule_id` and `creation_time` are
// preserved, and no record is orphaned.
func (r *BIOCResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state platformModels.BIOCModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var plan platformModels.BIOCModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload, payloadDiags := plan.ToSDKBIOC(ctx)
	resp.Diagnostics.Append(payloadDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// rule_id is the upsert key — pull it from prior state.
	ruleID := int(state.RuleID.ValueInt64())
	payload.RuleID = ruleID

	if _, err := r.upsertSingle(ctx, payload); err != nil {
		resp.Diagnostics.AddError("Error Updating BIOC", err.Error())
		return
	}

	remote, err := r.client.FindBIOCByID(ctx, ruleID)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading BIOC After Update", err.Error())
		return
	}
	if remote == nil {
		resp.Diagnostics.AddError(
			"BIOC Not Found After Update",
			fmt.Sprintf("bioc/get returned no match for rule_id=%d after upsert", ruleID),
		)
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *BIOCResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state platformModels.BIOCModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.deleteByRuleID(ctx, int(state.RuleID.ValueInt64())); err != nil {
		resp.Diagnostics.AddError("Error Deleting BIOC", err.Error())
		return
	}
}

// ImportState supports `terraform import cortexcloud_bioc.foo <rule_id>` —
// the numeric rule_id is the identity. Importing by `name` is not
// supported because BIOC names are not unique per tenant.
func (r *BIOCResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ruleID, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("BIOC import expects a numeric rule_id, got %q: %s", req.ID, err.Error()),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("rule_id"), ruleID)...)
}
