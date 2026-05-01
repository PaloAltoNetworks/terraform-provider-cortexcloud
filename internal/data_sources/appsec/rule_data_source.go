// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	appsecModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/appsec"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &ruleDataSource{}
	_ datasource.DataSourceWithConfigure = &ruleDataSource{}
)

func NewRuleDataSource() datasource.DataSource {
	return &ruleDataSource{}
}

type ruleDataSource struct {
	client *appsec.Client
}

func (d *ruleDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_appsec_rule"
}

func (d *ruleDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides details about an Application Security rule.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for the rule.",
				Required:    true,
			},
			"name": schema.StringAttribute{
				Description: "Name of the rule.",
				Computed:    true,
			},
			"severity": schema.StringAttribute{
				Description: "The severity level of the rule (CRITICAL, HIGH, MEDIUM, LOW).",
				Computed:    true,
			},
			"scanner": schema.StringAttribute{
				Description: "The type of security scanner used to detect findings of this rule.",
				Computed:    true,
			},
			"category": schema.StringAttribute{
				Description: "Custom rule IaC category.",
				Computed:    true,
			},
			"sub_category": schema.StringAttribute{
				Description: "Custom rule subcategory.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "The rule description.",
				Computed:    true,
			},
			"frameworks": schema.ListNestedAttribute{
				Description: "The framework or language that the Application Security rule applies to.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "Name of the configured frameworks.",
							Computed:    true,
						},
						"definition": schema.StringAttribute{
							Description: "The rule definition.",
							Computed:    true,
						},
						"definition_link": schema.StringAttribute{
							Description: "HTTP link to the definition documentation.",
							Computed:    true,
						},
						"remediation_description": schema.StringAttribute{
							Description: "The remediation steps that will appear on the rule's findings.",
							Computed:    true,
						},
					},
				},
			},
			"labels": schema.ListAttribute{
				Description: "Labels assigned to the rule.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"is_custom": schema.BoolAttribute{
				Description: "Indicates whether the rule is custom.",
				Computed:    true,
			},
			"is_enabled": schema.BoolAttribute{
				Description: "Indicates whether the rule is enabled.",
				Computed:    true,
			},
			"cloud_provider": schema.StringAttribute{
				Description: "The cloud provider.",
				Computed:    true,
			},
			"domain": schema.StringAttribute{
				Description: "The domain associated with the rule.",
				Computed:    true,
			},
			"finding_category": schema.StringAttribute{
				Description: "The finding category.",
				Computed:    true,
			},
			"created_at": schema.StringAttribute{
				Description: "The timestamp when the rule was created.",
				Computed:    true,
			},
			"updated_at": schema.StringAttribute{
				Description: "The timestamp when the rule was updated.",
				Computed:    true,
			},
		},
	}
}

func (d *ruleDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *ruleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config appsecModels.RuleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	remote, err := d.client.Get(ctx, config.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Reading AppSec Rule", err.Error())
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, &remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
