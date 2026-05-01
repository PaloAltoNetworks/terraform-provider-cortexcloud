// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cwp"
	cwpModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cwp"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
	client *cwp.Client
}

// Metadata returns the data source type name.
func (d *policiesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cwp_policies"
}

// Schema defines the schema for the data source.
func (d *policiesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a filtered list of Cloud Workload Protection (CWP) policies.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Static identifier for the data source.",
				Computed:    true,
			},
			"policy_types": schema.ListAttribute{
				Description: "Optional list of policy types to filter by (COMPLIANCE, MALWARE, SECRET). If not specified, returns all policies.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"policies": schema.ListNestedAttribute{
				Description: "The list of CWP policies.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The ID of the CWP policy.",
							Computed:    true,
						},
						"revision": schema.Int64Attribute{
							Description: "The revision number of the policy.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "The timestamp when the policy was created. Note: Due to an API limitation, this value may change when the policy is updated.",
							Computed:    true,
						},
						"modified_at": schema.StringAttribute{
							Description: "The timestamp when the policy was last modified.",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "The policy type.",
							Computed:    true,
						},
						"created_by": schema.StringAttribute{
							Description: "The user who created the policy. Note: Due to an API limitation, this field may be empty for policies created via the API.",
							Computed:    true,
						},
						"disabled": schema.BoolAttribute{
							Description: "Whether the policy is disabled. Note: This field is always false for user-created policies due to an API limitation.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The name of the CWP policy.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "The description of the CWP policy.",
							Computed:    true,
						},
						"evaluation_modes": schema.ListAttribute{
							Description: "The evaluation modes for the policy.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"evaluation_stage": schema.StringAttribute{
							Description: "The evaluation stage for the policy.",
							Computed:    true,
						},
						"policy_rules": schema.ListNestedAttribute{
							Description: "The CWP rules attached to the policy.",
							Computed:    true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"action": schema.StringAttribute{
										Description: "The CWP rule's action.",
										Computed:    true,
									},
									"id": schema.StringAttribute{
										Description: "The policy rule's ID.\n\nThis value differs from the rule_id value, which is the unique ID of the individual CWP rule.",
										Computed:    true,
									},
									"policy_id": schema.StringAttribute{
										Description: "The ID of the underlying policy.",
										Computed:    true,
									},
									"policy_revision": schema.Int32Attribute{
										Description: "The revision of the underlying policy.",
										Computed:    true,
									},
									"remediation_guidance": schema.StringAttribute{
										Description: "The remediation steps for the underlying policy.",
										Computed:    true,
									},
									"rule_id": schema.StringAttribute{
										Description: "The ID of the CWP rule.",
										Computed:    true,
									},
									"rule_name": schema.StringAttribute{
										Description: "The name of the CWP rule.",
										Computed:    true,
									},
									"severity": schema.StringAttribute{
										Description: "The severity of the CWP rule.",
										Computed:    true,
									},
									"user_remediation_guidance": schema.StringAttribute{
										Description: "The procedure to remediate the issue captured by the CWP rule.",
										Computed:    true,
									},
								},
							},
						},
						"condition": schema.StringAttribute{
							Description: "The condition in blob form.",
							Computed:    true,
						},
						"exception": schema.StringAttribute{
							Description: "The exception in blob form.",
							Computed:    true,
						},
						"asset_scope": schema.StringAttribute{
							Description: "The asset scope in blob form.",
							Computed:    true,
						},
						"asset_group_ids": schema.ListAttribute{
							Description: "The asset group IDs that this policy applies to.",
							Computed:    true,
							ElementType: types.Int64Type,
						},
						"asset_groups": schema.ListAttribute{
							Description: "The asset group names.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"action": schema.StringAttribute{
							Description: "The policy's action. \n\nThis will be set according to the actions configured for the attached rules. The \"Prevent\" action takes precedence over the \"Issue\" action.",
							Computed:    true,
						},
						"severity": schema.StringAttribute{
							Description: "The policy's severity level. \n\nThis will be set according to the highest severity level in the attached rules.",
							Computed:    true,
						},
						"remediation_guidance": schema.StringAttribute{
							Description: "Remediation guidance for the policy.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
func (d *policiesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	ctx = tflog.SetField(ctx, "data_source_type", "CWPPoliciesDataSource")
	tflog.Debug(ctx, "Configuring SDK client")

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = client.CWP
}

// Read refreshes the Terraform state with the latest data.
func (d *policiesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "data_source_type", "CWPPoliciesDataSource")

	var config cwpModels.PoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert policy_types to string slice
	var policyTypes []string
	if !config.PolicyTypes.IsNull() && !config.PolicyTypes.IsUnknown() {
		resp.Diagnostics.Append(config.PolicyTypes.ElementsAs(ctx, &policyTypes, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Get the policies from the API
	policies, err := d.client.ListPolicies(ctx, policyTypes)
	if err != nil {
		resp.Diagnostics.AddError("Error Listing CWP Policies", err.Error())
		return
	}

	// Update config with remote data
	config.RefreshFromRemote(ctx, &resp.Diagnostics, policies)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
