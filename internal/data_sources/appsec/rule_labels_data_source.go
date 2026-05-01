// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &ruleLabelsDataSource{}
	_ datasource.DataSourceWithConfigure = &ruleLabelsDataSource{}
)

func NewRuleLabelsDataSource() datasource.DataSource {
	return &ruleLabelsDataSource{}
}

type ruleLabelsDataSource struct {
	client *appsec.Client
}

func (d *ruleLabelsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_appsec_rule_labels"
}

func (d *ruleLabelsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a list of available rule labels.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Static identifier for the data source.",
				Computed:    true,
			},
			"labels": schema.ListAttribute{
				Description: "The list of available rule labels.",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (d *ruleLabelsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = client.AppSec
}

func (d *ruleLabelsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	result, err := d.client.GetLabels(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error Getting AppSec Rule Labels", err.Error())
		return
	}

	// Convert labels to Terraform list
	// Handle both empty array and null from API (API bug: should return [] not null)
	var labelsList types.List
	if result.Labels == nil || len(result.Labels) == 0 {
		// Return empty list instead of null for better UX
		labelsList, _ = types.ListValue(types.StringType, []attr.Value{})
	} else {
		elements := make([]attr.Value, len(result.Labels))
		for i, label := range result.Labels {
			elements[i] = types.StringValue(label)
		}
		var diags diag.Diagnostics
		labelsList, diags = types.ListValue(types.StringType, elements)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Set state
	state := struct {
		ID     types.String `tfsdk:"id"`
		Labels types.List   `tfsdk:"labels"`
	}{
		ID:     types.StringValue("appsec_rule_labels"),
		Labels: labelsList,
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
