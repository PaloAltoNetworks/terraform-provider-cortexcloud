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
)

var (
	_ datasource.DataSource                     = &IndicatorDataSource{}
	_ datasource.DataSourceWithConfigValidators = &IndicatorDataSource{}
)

// NewIndicatorDataSource is a helper function to simplify the provider implementation.
func NewIndicatorDataSource() datasource.DataSource {
	return &IndicatorDataSource{}
}

// IndicatorDataSource looks up a single IOC by either its `indicator`
// string or its server-assigned `rule_id`. Exactly one of the two must be
// set. The `rule_id` filter is undocumented in the OpenAPI field enum but
// works against the live API on EQ.
type IndicatorDataSource struct {
	client *platform.Client
}

func (d *IndicatorDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_indicator"
}

func (d *IndicatorDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Looks up a single Indicator of Compromise (IOC) by either its " +
			"`indicator` value or its server-assigned `rule_id`. Exactly one of " +
			"the two must be set.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Mirror of the resolved `indicator` value.",
			},
			"indicator": schema.StringAttribute{
				Description: "The IOC value to look up. Mutually exclusive with `rule_id`.",
				Optional:    true,
				Computed:    true,
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"rule_id": schema.Int64Attribute{
				Description: "The server-assigned numeric ID to look up. Mutually exclusive with `indicator`.",
				Optional:    true,
				Computed:    true,
			},
			"type":                       schema.StringAttribute{Computed: true},
			"severity":                   schema.StringAttribute{Computed: true},
			"expiration_date":            schema.Int64Attribute{Computed: true},
			"default_expiration_enabled": schema.BoolAttribute{Computed: true},
			"comment":                    schema.StringAttribute{Computed: true},
			"reputation":                 schema.StringAttribute{Computed: true},
			"reliability":                schema.StringAttribute{Computed: true},
			"creation_time":              schema.Int64Attribute{Computed: true},
			"modification_time":          schema.Int64Attribute{Computed: true},
			"status":                     schema.StringAttribute{Computed: true},
			"source":                     schema.StringAttribute{Computed: true},
			"number_of_issues":           schema.Int64Attribute{Computed: true},
		},
	}
}

func (d *IndicatorDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("indicator"),
			path.MatchRoot("rule_id"),
		),
	}
}

func (d *IndicatorDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *IndicatorDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config platformModels.IndicatorModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var (
		remote      *platformTypes.Indicator
		err         error
		lookupPath  path.Path
		notFoundMsg string
	)
	if !config.RuleID.IsNull() && !config.RuleID.IsUnknown() {
		remote, err = d.client.FindIndicatorByID(ctx, int(config.RuleID.ValueInt64()))
		lookupPath = path.Root("rule_id")
		notFoundMsg = fmt.Sprintf("No indicator found with rule_id %d", config.RuleID.ValueInt64())
	} else {
		remote, err = d.client.FindIndicatorByName(ctx, config.Indicator.ValueString())
		lookupPath = path.Root("indicator")
		notFoundMsg = fmt.Sprintf("No indicator found with value %q", config.Indicator.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Indicator", err.Error())
		return
	}
	if remote == nil {
		resp.Diagnostics.AddAttributeError(lookupPath, "Indicator Not Found", notFoundMsg)
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
