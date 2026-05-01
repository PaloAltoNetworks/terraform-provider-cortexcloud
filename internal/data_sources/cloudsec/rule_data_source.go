// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

import (
	"context"
	"fmt"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudsec"
	cloudsecModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloudsec"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &CloudSecRuleDataSource{}
	_ datasource.DataSourceWithConfigure = &CloudSecRuleDataSource{}
)

// NewCloudSecRuleDataSource is a helper function to simplify the provider implementation.
func NewCloudSecRuleDataSource() datasource.DataSource {
	return &CloudSecRuleDataSource{}
}

// CloudSecRuleDataSource is the data source implementation.
type CloudSecRuleDataSource struct {
	client *cloudsec.Client
}

// Metadata returns the data source type name.
func (d *CloudSecRuleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloudsec_rule"
}

// Schema defines the schema for the data source.
func (d *CloudSecRuleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides details about a Cloud Security detection rule for Cloud Security Posture Management (CSPM).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier of the rule (UUID format).",
				Required:    true,
			},
			"name": schema.StringAttribute{
				Description: "Unique rule name.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "Detailed rule description.",
				Computed:    true,
			},
			"class": schema.StringAttribute{
				Description: "Rule class (e.g., 'config' for CSPM rules).",
				Computed:    true,
			},
			"type": schema.StringAttribute{
				Description: "Rule type (e.g., 'DETECTION').",
				Computed:    true,
			},
			"asset_types": schema.ListAttribute{
				Description: "Array of asset type identifiers.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"severity": schema.StringAttribute{
				Description: "Rule severity level (low, medium, high, critical, informational).",
				Computed:    true,
			},
			"query": schema.SingleNestedAttribute{
				Description: "Query definition containing XQL.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"xql": schema.StringAttribute{
						Description: "XQL query string.",
						Computed:    true,
					},
				},
			},
			"metadata": schema.SingleNestedAttribute{
				Description: "Metadata containing issue information.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"issue": schema.SingleNestedAttribute{
						Description: "Issue information with remediation details.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"recommendation": schema.StringAttribute{
								Description: "Remediation steps.",
								Computed:    true,
							},
						},
					},
				},
			},
			"compliance_metadata": schema.ListNestedAttribute{
				Description: "List of compliance metadata with control IDs.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"control_id": schema.StringAttribute{
							Description: "Compliance control identifier.",
							Computed:    true,
						},
						"standard_id": schema.StringAttribute{
							Description: "Compliance standard identifier.",
							Computed:    true,
						},
						"standard_name": schema.StringAttribute{
							Description: "Full name of the compliance standard.",
							Computed:    true,
						},
						"control_name": schema.StringAttribute{
							Description: "Full name of the compliance control.",
							Computed:    true,
						},
					},
				},
			},
			"labels": schema.SetAttribute{
				Description: "Custom labels.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the rule is enabled.",
				Computed:    true,
			},
			"providers": schema.ListAttribute{
				Description: "Cloud providers derived from asset_types.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"system_default": schema.BoolAttribute{
				Description: "Indicates if this is a system default rule.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "User who created the rule.",
				Computed:    true,
			},
			"created_on": schema.Int64Attribute{
				Description: "Creation timestamp (epoch milliseconds).",
				Computed:    true,
			},
			"last_modified_by": schema.StringAttribute{
				Description: "User who last modified the rule.",
				Computed:    true,
			},
			"last_modified_on": schema.Int64Attribute{
				Description: "Last modification timestamp (epoch milliseconds).",
				Computed:    true,
			},
			"deleted": schema.BoolAttribute{
				Description: "Deletion status.",
				Computed:    true,
			},
			"deleted_at": schema.Int64Attribute{
				Description: "Deletion timestamp (epoch milliseconds).",
				Computed:    true,
			},
			"deleted_by": schema.StringAttribute{
				Description: "User who deleted the rule.",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
func (d *CloudSecRuleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	clients, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = clients.CloudSec
}

// Read refreshes the Terraform state with the latest data.
func (d *CloudSecRuleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config cloudsecModels.CloudSecRuleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the rule ID from config
	ruleID := config.ID.ValueString()
	if ruleID == "" {
		resp.Diagnostics.AddError(
			"Missing Rule ID",
			"The rule ID must be provided.",
		)
		return
	}

	// Call SDK Get method
	ruleResp, err := d.client.Get(ctx, ruleID)
	if err != nil {
		// Check if rule not found (404)
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "404") {
			resp.Diagnostics.AddError(
				"CloudSec Rule Not Found",
				fmt.Sprintf("Rule with ID %s was not found.", ruleID),
			)
			return
		}
		resp.Diagnostics.AddError(
			"Error Reading CloudSec Rule",
			fmt.Sprintf("Could not read rule %s: %s", ruleID, err.Error()),
		)
		return
	}

	// Populate the model from the API response
	config.FromSDKResponse(ctx, &resp.Diagnostics, &ruleResp)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set the state
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
