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
	_ datasource.DataSource              = &CloudSecPolicyDataSource{}
	_ datasource.DataSourceWithConfigure = &CloudSecPolicyDataSource{}
)

// NewCloudSecPolicyDataSource is a helper function to simplify the provider implementation.
func NewCloudSecPolicyDataSource() datasource.DataSource {
	return &CloudSecPolicyDataSource{}
}

// CloudSecPolicyDataSource is the data source implementation.
type CloudSecPolicyDataSource struct {
	client *cloudsec.Client
}

// Metadata returns the data source type name.
func (d *CloudSecPolicyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloudsec_policy"
}

// getFilterCriteriaSchemaComputed returns the recursive filter criteria schema for data sources.
// All fields are Computed (read-only) since this is a data source.
func getFilterCriteriaSchemaComputed(depth int, maxDepth int) map[string]schema.Attribute {
	attrs := map[string]schema.Attribute{
		"operator": schema.StringAttribute{
			Description: "Logical operator for combining criteria (AND or OR).",
			Computed:    true,
		},
		"field": schema.StringAttribute{
			Description: "Field name to filter on (e.g., 'severity', 'cloudType').",
			Computed:    true,
		},
		"type": schema.StringAttribute{
			Description: "Filter operation type (EQ, NEQ, CONTAINS, NCONTAINS, ARRAY_CONTAINS).",
			Computed:    true,
		},
		"value": schema.StringAttribute{
			Description: "Value to filter for.",
			Computed:    true,
		},
	}

	// Add recursive criteria list if we haven't reached max depth
	if depth < maxDepth {
		attrs["criteria"] = schema.ListNestedAttribute{
			Description: "List of nested filter criteria.",
			Computed:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: getFilterCriteriaSchemaComputed(depth+1, maxDepth),
			},
		}
	}

	return attrs
}

// Schema defines the schema for the data source.
func (d *CloudSecPolicyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides details about a Cloud Security policy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier of the policy (UUID format).",
				Required:    true,
			},
			"name": schema.StringAttribute{
				Description: "Unique policy name.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "Detailed policy description.",
				Computed:    true,
			},
			"labels": schema.SetAttribute{
				Description: "Custom labels.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"rule_matching": schema.SingleNestedAttribute{
				Description: "Rule matching configuration.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Description: "Rule matching type (ALL_RULES, RULES, RULE_FILTER).",
						Computed:    true,
					},
					"rules": schema.ListAttribute{
						Description: "List of rule IDs (when type is RULES).",
						Computed:    true,
						ElementType: types.StringType,
					},
					"filter_criteria": schema.SingleNestedAttribute{
						Description: "Filter criteria for rules (when type is RULE_FILTER).",
						Computed:    true,
						Attributes:  getFilterCriteriaSchemaComputed(0, 3),
					},
				},
			},
			"asset_matching": schema.SingleNestedAttribute{
				Description: "Asset matching configuration.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Description: "Asset matching type (ALL_ASSETS, ASSET_GROUPS, CLOUD_ACCOUNTS).",
						Computed:    true,
					},
					"asset_group_ids": schema.ListAttribute{
						Description: "List of asset group IDs (when type is ASSET_GROUPS).",
						Computed:    true,
						ElementType: types.Int64Type,
					},
					"cloud_account_ids": schema.ListAttribute{
						Description: "List of cloud account IDs (when type is CLOUD_ACCOUNTS).",
						Computed:    true,
						ElementType: types.StringType,
					},
				},
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the policy is enabled.",
				Computed:    true,
			},
			"mode": schema.StringAttribute{
				Description: "Policy mode.",
				Computed:    true,
			},
			"created_at": schema.Int64Attribute{
				Description: "Creation timestamp (epoch milliseconds).",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "User who created the policy.",
				Computed:    true,
			},
			"updated_at": schema.Int64Attribute{
				Description: "Last update timestamp (epoch milliseconds).",
				Computed:    true,
			},
			"updated_by": schema.StringAttribute{
				Description: "User who last updated the policy.",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
func (d *CloudSecPolicyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *CloudSecPolicyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config cloudsecModels.CloudSecPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the policy ID from config
	policyID := config.ID.ValueString()
	if policyID == "" {
		resp.Diagnostics.AddError(
			"Missing Policy ID",
			"The policy ID must be provided.",
		)
		return
	}

	// Call SDK GetPolicy method
	policyResp, err := d.client.GetPolicy(ctx, policyID)
	if err != nil {
		// Check if policy not found (404)
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "404") {
			resp.Diagnostics.AddError(
				"CloudSec Policy Not Found",
				fmt.Sprintf("Policy with ID %s was not found.", policyID),
			)
			return
		}
		resp.Diagnostics.AddError(
			"Error Reading CloudSec Policy",
			fmt.Sprintf("Could not read policy %s: %s", policyID, err.Error()),
		)
		return
	}

	// Populate the model from the API response
	config.FromSDKResponse(ctx, &resp.Diagnostics, &policyResp)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set the state
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
