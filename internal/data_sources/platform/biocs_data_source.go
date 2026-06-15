// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"
	"strconv"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	platformModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource = &BIOCsDataSource{}
)

// NewBIOCsDataSource is a helper function to simplify the provider implementation.
func NewBIOCsDataSource() datasource.DataSource {
	return &BIOCsDataSource{}
}

// BIOCsDataSource returns a filtered list of BIOCs. Filters mirror the
// bioc/get filter shape; pass an empty filters list to return all BIOCs
// (subject to the server's response cap).
type BIOCsDataSource struct {
	client *platform.Client
}

// BIOCsDataSourceModel is the on-the-wire schema of the list data source:
// a flat input filter list plus a `biocs` output list.
type BIOCsDataSourceModel struct {
	ID      types.String                 `tfsdk:"id"`
	Filters []BIOCsDataSourceFilterModel `tfsdk:"filters"`
	BIOCs   []platformModels.BIOCModel   `tfsdk:"biocs"`
}

// BIOCsDataSourceFilterModel mirrors a single API filter clause. `value`
// is a string here for schema simplicity; the data source coerces it to
// the right JSON type per field at Read time.
type BIOCsDataSourceFilterModel struct {
	Field    types.String `tfsdk:"field"`
	Operator types.String `tfsdk:"operator"`
	Value    types.String `tfsdk:"value"`
}

func (d *BIOCsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_biocs"
}

func (d *BIOCsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	biocBlock := schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"id":        schema.StringAttribute{Computed: true},
			"rule_id":   schema.Int64Attribute{Computed: true},
			"name":      schema.StringAttribute{Computed: true},
			"type":      schema.StringAttribute{Computed: true},
			"severity":  schema.StringAttribute{Computed: true},
			"status":    schema.StringAttribute{Computed: true},
			"comment":   schema.StringAttribute{Computed: true},
			"is_xql":    schema.BoolAttribute{Computed: true},
			"xql_query": schema.StringAttribute{Computed: true},
			"definition": schema.StringAttribute{Computed: true},
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

	resp.Schema = schema.Schema{
		Description: "Lists Behavioral Indicators of Compromise (BIOCs) matching an " +
			"optional filter set.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Synthetic identifier (constant `biocs`).",
				Computed:    true,
			},
			"filters": schema.ListNestedAttribute{
				Description: "Optional filter clauses. Omit for an unfiltered listing.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"field": schema.StringAttribute{
							Required:    true,
							Description: "Filter field (e.g. `name`, `type`, `severity`, `is_xql`, `rule_id`).",
							Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
						},
						"operator": schema.StringAttribute{
							Required:    true,
							Description: "Filter operator (`EQ`, `NEQ`, `IN`, `GTE`, `LTE`).",
							Validators: []validator.String{
								stringvalidator.OneOf("EQ", "NEQ", "IN", "GTE", "LTE"),
							},
						},
						"value": schema.StringAttribute{
							Required:    true,
							Description: "Filter value, serialized as the API `value` field. " +
								"Numeric fields (`rule_id`) and the boolean `is_xql` field " +
								"are coerced from the string form before submission.",
						},
					},
				},
			},
			"biocs": schema.ListNestedAttribute{
				Description:  "The BIOCs returned by the API.",
				Computed:     true,
				NestedObject: biocBlock,
			},
		},
	}
}

func (d *BIOCsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *BIOCsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config BIOCsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := make([]platformTypes.BIOCFilter, 0, len(config.Filters))
	for i, f := range config.Filters {
		field := f.Field.ValueString()
		raw := f.Value.ValueString()
		// Coerce the Terraform string into the JSON type the API expects
		// per field. The IOC sibling endpoint returns HTTP 500 on
		// mistyped filter values; treat the BIOC endpoint as the same.
		var value any = raw
		switch field {
		case "rule_id":
			n, parseErr := strconv.ParseInt(raw, 10, 64)
			if parseErr != nil {
				resp.Diagnostics.AddAttributeError(
					path.Root("filters").AtListIndex(i).AtName("value"),
					"Invalid Numeric Filter Value",
					fmt.Sprintf("filter[%d].value=%q is not a valid integer; required for field %q", i, raw, field),
				)
				return
			}
			value = n
		case "is_xql":
			b, parseErr := strconv.ParseBool(raw)
			if parseErr != nil {
				resp.Diagnostics.AddAttributeError(
					path.Root("filters").AtListIndex(i).AtName("value"),
					"Invalid Boolean Filter Value",
					fmt.Sprintf("filter[%d].value=%q is not a valid boolean; required for field %q", i, raw, field),
				)
				return
			}
			value = b
		}
		filters = append(filters, platformTypes.BIOCFilter{
			Field:    field,
			Operator: f.Operator.ValueString(),
			Value:    value,
		})
	}

	listResp, err := d.client.ListBIOCs(ctx, platformTypes.ListBIOCsRequest{
		Filters:      filters,
		ExtendedView: true,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error Listing BIOCs", err.Error())
		return
	}

	result := make([]platformModels.BIOCModel, 0, len(listResp.Objects))
	for i := range listResp.Objects {
		var m platformModels.BIOCModel
		m.RefreshFromRemote(ctx, &resp.Diagnostics, &listResp.Objects[i])
		if resp.Diagnostics.HasError() {
			return
		}
		result = append(result, m)
	}

	config.ID = types.StringValue("biocs")
	config.BIOCs = result

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
