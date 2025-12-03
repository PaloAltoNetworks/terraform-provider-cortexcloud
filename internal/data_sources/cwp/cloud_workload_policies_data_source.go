// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp

import (
	"context"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cwp"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	cwpSdk "github.com/PaloAltoNetworks/cortex-cloud-go/cwp"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &policiesDataSource{}
	_ datasource.DataSourceWithConfigure = &policiesDataSource{}
)

// NewPoliciesDataSource is a helper function to simplify the provider implementation.
func NewPoliciesDataSource() datasource.DataSource {
	return &policiesDataSource{}
}

// policiesDataSource is the data source implementation.
type policiesDataSource struct {
	client *cwpSdk.Client
}

// Metadata returns the data source type name.
func (d *policiesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cwp_policies"
}

// Schema defines the schema for the data source.
func (d *policiesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Gets a list of CWP policies, optionally filtered by policy types.",
		Attributes: map[string]schema.Attribute{
			"policy_types": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "List of policy types to filter by. If not provided, all policies are returned.",
				Optional:    true,
			},
			"policies": schema.ListNestedAttribute{
				Description: "List of policies matching the filter criteria.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The unique identifier of the policy.",
							Computed:    true,
						},
						"revision": schema.Int64Attribute{
							Description: "The revision number of the policy.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "The timestamp when the policy was created.",
							Computed:    true,
						},
						"modified_at": schema.StringAttribute{
							Description: "The timestamp when the policy was last modified.",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "The type of the policy.",
							Computed:    true,
						},
						"created_by": schema.StringAttribute{
							Description: "The user who created the policy.",
							Computed:    true,
						},
						"disabled": schema.BoolAttribute{
							Description: "Whether the policy is disabled.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The name of the policy.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "The description of the policy.",
							Computed:    true,
						},
						"evaluation_modes": schema.ListAttribute{
							ElementType: types.StringType,
							Description: "The evaluation modes for the policy.",
							Computed:    true,
						},
						"evaluation_stage": schema.StringAttribute{
							Description: "The evaluation stage for the policy.",
							Computed:    true,
						},
						"rules_ids": schema.ListAttribute{
							ElementType: types.StringType,
							Description: "The list of rule IDs associated with the policy.",
							Computed:    true,
						},
						"condition": schema.StringAttribute{
							Description: "The condition for the policy.",
							Computed:    true,
						},
						"exception": schema.StringAttribute{
							Description: "The exception for the policy.",
							Computed:    true,
						},
						"asset_scope": schema.StringAttribute{
							Description: "The asset scope for the policy.",
							Computed:    true,
						},
						"asset_group_ids": schema.ListAttribute{
							ElementType: types.Int64Type,
							Description: "The list of asset group IDs associated with the policy.",
							Computed:    true,
						},
						"asset_groups": schema.ListAttribute{
							ElementType: types.StringType,
							Description: "The list of asset groups associated with the policy.",
							Computed:    true,
						},
						"policy_action": schema.StringAttribute{
							Description: "The action to take when the policy is triggered.",
							Computed:    true,
						},
						"policy_severity": schema.StringAttribute{
							Description: "The severity level of the policy.",
							Computed:    true,
						},
						"remediation_guidance": schema.StringAttribute{
							Description: "The remediation guidance for the policy.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
func (d *policiesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedResourceConfigureTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = client.CWP
}

// Read refreshes the Terraform state with the latest data.
func (d *policiesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	// Fetch config
	var config models.CloudWorkloadPoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policyTypes []string
	resp.Diagnostics.Append(config.PolicyTypes.ElementsAs(ctx, &policyTypes, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Execute API request
	policies, err := d.client.ListCloudWorkloadPolicies(ctx, policyTypes)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policies", err.Error())
		return
	} else if policies == nil {
		resp.Diagnostics.AddError("Error reading policies", "API returned nil")
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, *policies)

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
