// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	platformModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource                     = &BIOCDataSource{}
	_ datasource.DataSourceWithConfigValidators = &BIOCDataSource{}
)

// NewBIOCDataSource is a helper function to simplify the provider implementation.
func NewBIOCDataSource() datasource.DataSource {
	return &BIOCDataSource{}
}

// BIOCDataSource looks up a single BIOC by either its `name` or its
// server-assigned `rule_id`. Exactly one of the two must be set. BIOC
// names are NOT unique per tenant — when looking up by `name`, the data
// source returns the first match the API returns; prefer `rule_id` when
// you need a deterministic lookup.
type BIOCDataSource struct {
	client *platform.Client
}

func (d *BIOCDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_bioc"
}

func (d *BIOCDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Looks up a single Behavioral Indicator of Compromise (BIOC) by " +
			"either its `name` or its server-assigned `rule_id`. Exactly one of " +
			"the two must be set. BIOC names are NOT unique per tenant — when " +
			"looking up by `name`, this data source returns the first match the " +
			"API returns. Prefer `rule_id` when uniqueness matters.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Mirror of the resolved `rule_id` as a string.",
			},
			"name": schema.StringAttribute{
				Description: "The BIOC name to look up. Mutually exclusive with `rule_id`.",
				Optional:    true,
				Computed:    true,
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"rule_id": schema.Int64Attribute{
				Description: "The server-assigned numeric ID to look up. Mutually exclusive with `name`.",
				Optional:    true,
				Computed:    true,
			},
			"type":              schema.StringAttribute{Computed: true},
			"severity":          schema.StringAttribute{Computed: true},
			"status":            schema.StringAttribute{Computed: true},
			"comment":           schema.StringAttribute{Computed: true},
			"is_xql":            schema.BoolAttribute{Computed: true},
			"xql_query":         schema.StringAttribute{Computed: true},
			"definition":        schema.StringAttribute{Computed: true},
			"mitre_tactic_id_and_name": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
			"mitre_technique_id_and_name": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
			"creation_time":     schema.Int64Attribute{Computed: true},
			"modification_time": schema.Int64Attribute{Computed: true},
			"source":            schema.StringAttribute{Computed: true},
			"number_of_issues":  schema.Int64Attribute{Computed: true},
		},
	}
}

func (d *BIOCDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("name"),
			path.MatchRoot("rule_id"),
		),
	}
}

func (d *BIOCDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	clients, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}
	d.client = clients.Platform
}

func (d *BIOCDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config platformModels.BIOCModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var (
		remote      *platformTypes.BIOC
		err         error
		lookupPath  path.Path
		notFoundMsg string
	)
	if !config.RuleID.IsNull() && !config.RuleID.IsUnknown() {
		remote, err = d.client.FindBIOCByID(ctx, int(config.RuleID.ValueInt64()))
		lookupPath = path.Root("rule_id")
		notFoundMsg = fmt.Sprintf("No BIOC found with rule_id %d", config.RuleID.ValueInt64())
	} else {
		remote, err = d.client.FindBIOCByName(ctx, config.Name.ValueString())
		lookupPath = path.Root("name")
		notFoundMsg = fmt.Sprintf("No BIOC found with name %q", config.Name.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Error Reading BIOC", err.Error())
		return
	}
	if remote == nil {
		resp.Diagnostics.AddAttributeError(lookupPath, "BIOC Not Found", notFoundMsg)
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
