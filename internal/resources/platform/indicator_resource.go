// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	platformModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// IndicatorResource manages a single Cortex IOC via the upsert
// `/public_api/v1/indicators/insert` endpoint. Updates submit the
// server-assigned `rule_id` from state so the API overwrites the existing
// record in place. Indicator renames (changes to the `indicator` string
// itself) are applied as delete-old + insert-new to avoid leaving an
// orphan, since the OpenAPI spec does not promise that the `indicator`
// field is mutable within a rule_id-keyed upsert.
var (
	_ resource.Resource                = &IndicatorResource{}
	_ resource.ResourceWithImportState = &IndicatorResource{}
)

// NewIndicatorResource is a helper function to simplify the provider implementation.
func NewIndicatorResource() resource.Resource {
	return &IndicatorResource{}
}

// indicatorTypeValues, indicatorSeverityValues, indicatorReputationValues
// return the documented enum values as []string for use with
// stringvalidator.OneOf, so the TF schema validators stay in sync with the
// SDK constants without duplicating the literal sets.
func indicatorTypeValues() []string {
	all := enums.IndicatorTypes()
	out := make([]string, len(all))
	for i, v := range all {
		out[i] = string(v)
	}
	return out
}

func indicatorSeverityValues() []string {
	all := enums.IndicatorSeverities()
	out := make([]string, len(all))
	for i, v := range all {
		out[i] = string(v)
	}
	return out
}

func indicatorReputationValues() []string {
	all := enums.IndicatorReputations()
	out := make([]string, len(all))
	for i, v := range all {
		out[i] = string(v)
	}
	return out
}

func indicatorReliabilityValues() []string {
	all := enums.IndicatorReliabilities()
	out := make([]string, len(all))
	for i, v := range all {
		out[i] = string(v)
	}
	return out
}

// IndicatorResource is the resource implementation.
type IndicatorResource struct {
	client *platform.Client
}

func (r *IndicatorResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_indicator"
}

func (r *IndicatorResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a single Indicator of Compromise (IOC) in Cortex. " +
			"Backed by the upsert `/public_api/v1/indicators/insert` endpoint: " +
			"in-place edits submit the server-assigned `rule_id` carried in " +
			"state so the API overwrites the existing record. Renames " +
			"(changes to the `indicator` value itself) are applied as " +
			"delete-old + insert-new — same Terraform-level `~ in-place` " +
			"plan, two API calls under the hood.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Mirror of `indicator`; the resource identity used for state " +
					"addressing. Computed so a rename of `indicator` legitimately updates " +
					"this value rather than violating the plan-vs-apply invariant.",
				Computed: true,
			},
			"indicator": schema.StringAttribute{
				Description: "The IOC value (hash, IP, domain, filename, or path). " +
					"Changes are applied in place via delete-then-insert (the rule_id " +
					"is regenerated server-side); other fields update via the documented " +
					"upsert path keyed on `rule_id`.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"type": schema.StringAttribute{
				Description: "Indicator type. Documented values come from `enums.IndicatorTypes()`.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(indicatorTypeValues()...),
				},
			},
			"severity": schema.StringAttribute{
				Description: "Indicator severity. Documented values come from " +
					"`enums.IndicatorSeverities()` — the namespaced `SEV_NNN_X` form " +
					"the live API accepts on both reads and writes.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(indicatorSeverityValues()...),
				},
			},
			"expiration_date": schema.Int64Attribute{
				Description: "Unix epoch milliseconds at which the IOC expires. Use `-1` for `Never`. " +
					"Required by the API; defaults to `-1` when omitted.",
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(-1),
			},
			"default_expiration_enabled": schema.BoolAttribute{
				Description: "When true, the indicator uses the tenant default expiration policy " +
					"for its type instead of `expiration_date`.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"comment": schema.StringAttribute{
				Description: "Free-form comment.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"reputation": schema.StringAttribute{
				Description: "Indicator reputation. Documented values come from " +
					"`enums.IndicatorReputations()`.",
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(string(enums.IndicatorReputationUnknown)),
				Validators: []validator.String{
					stringvalidator.OneOf(indicatorReputationValues()...),
				},
			},
			"reliability": schema.StringAttribute{
				Description: "Reliability rating. Documented values come from " +
					"`enums.IndicatorReliabilities()` (A most reliable through G least); " +
					"the empty string means unset.",
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(""),
				Validators: []validator.String{
					stringvalidator.OneOf(append(indicatorReliabilityValues(), "")...),
				},
			},
			"rule_id": schema.Int64Attribute{
				Description: "Server-assigned numeric ID. Surfaced for cross-reference; not " +
					"used for identity by the resource (rename path keys on the indicator " +
					"string, not on rule_id). Stable across in-place updates; regenerated on rename.",
				Computed: true,
			},
			"creation_time": schema.Int64Attribute{
				Description: "Unix epoch milliseconds when the indicator was first created. " +
					"Regenerated when the `indicator` value changes (rename path is delete + insert).",
				Computed: true,
			},
			"modification_time": schema.Int64Attribute{
				Description: "Unix epoch milliseconds of the most recent update.",
				Computed:    true,
			},
			"status": schema.StringAttribute{
				Description: "Server-reported status (e.g. `ENABLED`).",
				Computed:    true,
			},
			"source": schema.StringAttribute{
				Description: "Human-readable origin of the most recent write — typically " +
					"`Public API user (key #<id>)` for API-key-authored records, or a user " +
					"email for UI/SSO-authored records. Useful for detecting out-of-band drift.",
				Computed: true,
			},
			"number_of_issues": schema.Int64Attribute{
				Description: "Count of issues this indicator has fired on. Server-maintained.",
				Computed:    true,
			},
		},
	}
}

func (r *IndicatorResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// upsertSingle posts a single indicator to /indicators/insert. The endpoint
// is natively upsert: when the payload carries `rule_id`, the matching
// record appears in updated_objects; when it does not, the new record
// appears in added_objects. The endpoint's `errors` array carries any
// batch-wide or per-record failures.
//
// We treat the call as successful when `errors` is empty AND at least one
// added/updated record is reported. An "empty success" (no errors but no
// added/updated rows either) is also reported as an error because it
// silently swallows the write — interpretation: defensive, since the spec
// example always shows at least one object on a successful call.
func (r *IndicatorResource) upsertSingle(ctx context.Context, ioc platformTypes.Indicator) error {
	resp, err := r.client.InsertIndicators(ctx, []platformTypes.Indicator{ioc})
	if err != nil {
		return err
	}
	if len(resp.Errors) > 0 {
		msgs := make([]string, 0, len(resp.Errors))
		for _, e := range resp.Errors {
			msgs = append(msgs, fmt.Sprintf("index %d: %s", e.Index, e.Status))
		}
		return fmt.Errorf("indicators/insert errors: %s", strings.Join(msgs, "; "))
	}
	if len(resp.AddedObjects)+len(resp.UpdatedObjects) == 0 {
		return fmt.Errorf("indicators/insert returned no added or updated objects and no errors")
	}
	return nil
}

// deleteByName removes the record whose `indicator` field equals the given
// value via the filter-bodied /indicators/delete endpoint. Used by the
// Delete CRUD method and by Update when the indicator string itself
// changes (rename path).
//
// A zero-length return slice means the filter matched nothing. We treat
// that as success (idempotent delete) — callers can pre-flight a find if
// they need stricter semantics.
func (r *IndicatorResource) deleteByName(ctx context.Context, indicator string) error {
	_, err := r.client.DeleteIndicators(ctx, platformTypes.DeleteIndicatorsRequest{
		Filters: []platformTypes.IndicatorFilter{
			{Field: "indicator", Operator: "EQ", Value: indicator},
		},
	})
	return err
}

func (r *IndicatorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan platformModels.IndicatorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := plan.ToSDKIndicator()

	// Adopt-on-collision: if the indicator already exists out-of-band, look
	// up its rule_id and submit as an upsert instead of erroring with
	// "IOC indicator exists". This makes `terraform apply` idempotent over
	// pre-existing records without requiring a prior `terraform import`.
	if existing, err := r.client.FindIndicatorByName(ctx, plan.Indicator.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error Checking Existing Indicator", err.Error())
		return
	} else if existing != nil {
		payload.RuleID = existing.RuleID
	}

	if err := r.upsertSingle(ctx, payload); err != nil {
		resp.Diagnostics.AddError("Error Creating Indicator", err.Error())
		return
	}

	remote, err := r.client.FindIndicatorByName(ctx, plan.Indicator.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Indicator After Create", err.Error())
		return
	}
	if remote == nil {
		resp.Diagnostics.AddError(
			"Indicator Not Found After Create",
			fmt.Sprintf("indicators/get returned no match for %q after insert", plan.Indicator.ValueString()),
		)
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *IndicatorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state platformModels.IndicatorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	remote, err := r.client.FindIndicatorByName(ctx, state.Indicator.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Indicator", err.Error())
		return
	}
	if remote == nil {
		resp.Diagnostics.AddWarning(
			"Indicator Not Found",
			fmt.Sprintf("No indicator found with value %q, removing from state.", state.Indicator.ValueString()),
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

// Update applies content changes in place. Two paths:
//
//   - When the `indicator` string is unchanged, the SDK payload carries the
//     server-assigned `rule_id` from state and the API overwrites the
//     existing record in a single call (documented upsert path).
//   - When the `indicator` string itself changed, the prior record is
//     deleted by its old value and a fresh record is inserted without a
//     `rule_id`. The new `rule_id` is then re-read from the API. This
//     branch exists because the OpenAPI spec does not promise that the
//     `indicator` field is mutable inside a rule_id-keyed upsert
//     (interpretation: safer to assume `indicator` is part of the natural
//     key on the backend than to risk leaving an orphaned record).
func (r *IndicatorResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state platformModels.IndicatorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var plan platformModels.IndicatorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := plan.ToSDKIndicator()

	oldName := state.Indicator.ValueString()
	newName := plan.Indicator.ValueString()
	if oldName != newName {
		// Rename path: drop the old record by its name, then insert fresh.
		// Leave payload.RuleID at zero so the SDK omits the field and the
		// API assigns a new one.
		if err := r.deleteByName(ctx, oldName); err != nil {
			resp.Diagnostics.AddError("Error Renaming Indicator (delete old)", err.Error())
			return
		}
	} else {
		// rule_id is the upsert key; pull it from the prior state so the
		// API matches the existing record and overwrites it in place.
		payload.RuleID = int(state.RuleID.ValueInt64())
	}

	if err := r.upsertSingle(ctx, payload); err != nil {
		resp.Diagnostics.AddError("Error Updating Indicator", err.Error())
		return
	}

	remote, err := r.client.FindIndicatorByName(ctx, plan.Indicator.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Indicator After Update", err.Error())
		return
	}
	if remote == nil {
		resp.Diagnostics.AddError(
			"Indicator Not Found After Update",
			fmt.Sprintf("indicators/get returned no match for %q after upsert", plan.Indicator.ValueString()),
		)
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *IndicatorResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state platformModels.IndicatorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.deleteByName(ctx, state.Indicator.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error Deleting Indicator", err.Error())
		return
	}
}

// ImportState supports `terraform import cortexcloud_indicator.foo <indicator>`
// — the indicator string is the identity. Both `id` and `indicator` are
// hydrated from the import value so the subsequent Read can locate the
// remote record via FindIndicatorByName.
func (r *IndicatorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("indicator"), req.ID)...)
}
