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
	_ datasource.DataSource              = &policyDataSource{}
	_ datasource.DataSourceWithConfigure = &policyDataSource{}
)

func NewPolicyDataSource() datasource.DataSource {
	return &policyDataSource{}
}

type policyDataSource struct {
	client *appsec.Client
}

func (d *policyDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_appsec_policy"
}

func (d *policyDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides details about an Application Security policy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for the policy.",
				Required:    true,
			},
			"name": schema.StringAttribute{
				Description: "Name of the policy.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the policy.",
				Computed:    true,
			},
			"status": schema.StringAttribute{
				Description: "Indicates whether the policy is currently enabled or disabled.",
				Computed:    true,
			},
			"is_custom": schema.BoolAttribute{
				Description: "Indicates if the policy is a custom policy or a system-provided policy.",
				Computed:    true,
			},
			"conditions": schema.StringAttribute{
				Description: "Policy conditions as a JSON-encoded string with nested AND/OR logic.",
				Computed:    true,
			},
			"scope": schema.StringAttribute{
				Description: "Asset targeting scope as a JSON-encoded string with nested AND/OR logic.",
				Computed:    true,
			},
			"asset_group_ids": schema.ListAttribute{
				Description: "List of asset groups to which the policy applies. If the array is empty, the policy applies to all asset groups.",
				Computed:    true,
				ElementType: types.Int64Type,
			},
			"periodic_trigger":       periodicTriggerDataSourceAttribute(),
			"pr_trigger":             prTriggerDataSourceAttribute(),
			"cicd_trigger":           cicdTriggerDataSourceAttribute(),
			"ci_image_trigger":       ciImageTriggerDataSourceAttribute(),
			"image_registry_trigger": imageRegistryTriggerDataSourceAttribute(),
			"developer_suppression_affects": schema.BoolAttribute{
				Computed: true,
			},
			"override_issue_severity": schema.StringAttribute{
				Computed: true,
			},
			"created_by": schema.StringAttribute{
				Description: "The user or system that created the policy.",
				Computed:    true,
			},
			"date_created": schema.StringAttribute{
				Description: "The date and time when the policy was created.",
				Computed:    true,
			},
			"modified_by": schema.StringAttribute{
				Description: "The user or system that last modified the policy.",
				Computed:    true,
			},
			"date_modified": schema.StringAttribute{
				Description: "The date and time when the policy was last modified.",
				Computed:    true,
			},
			"version": schema.Float64Attribute{
				Description: "The version of the policy. Increments by one every time the policy is updated.",
				Computed:    true,
			},
		},
	}
}

// periodicTriggerDataSourceAttribute returns the read-only data source schema
// for the `periodic_trigger` block, mirroring the resource schema shape.
func periodicTriggerDataSourceAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Description: "If configured, sets the policy to be evaluated every 12 hours.",
		Computed:    true,
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Description: "Enables the periodic trigger for the policy.",
				Computed:    true,
			},
			"override_issue_severity": schema.StringAttribute{
				Description: "Set the severity of the issue, overriding the system severity. If not configured, the system severity is used.",
				Computed:    true,
			},
			"actions": schema.SingleNestedAttribute{
				Description: "Actions to take when the policy detects its target risk and the policy is triggered.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"report_issue": schema.BoolAttribute{
						Description: "Indicates if triggering the policy should create an issue in the connected system.",
						Computed:    true,
					},
				},
			},
		},
	}
}

func prTriggerDataSourceAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Description: "If configured, sets the policy is evaluated on Pull Request (PR) creation and updates.",
		Computed:    true,
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Description: "Enables the PR trigger for the policy.",
				Computed:    true,
			},
			"override_issue_severity": schema.StringAttribute{
				Description: "Sets the severity of the issue, overriding the system severity. If not configured, the system severity is used.",
				Computed:    true,
			},
			"actions": schema.SingleNestedAttribute{
				Description: "Actions to take when the policy detects its target risk and the policy is triggered.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"report_issue": schema.BoolAttribute{
						Description: "Indicates if triggering the policy should create an issue in the connected system.",
						Computed:    true,
					},
					"block_pr": schema.BoolAttribute{
						Description: "Indicates if triggering the policy should block the pull request. Ensure that the PR trigger is selected.",
						Computed:    true,
					},
					"report_pr_comment": schema.BoolAttribute{
						Description: "Indicates if triggering the policy should create comments on the pull request. Ensure that the PR trigger is selected.",
						Computed:    true,
					},
				},
			},
		},
	}
}

func cicdTriggerDataSourceAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Description: "If true, the policy is evaluated on CI/CD pipeline events.",
		Computed:    true,
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Description: "Enables the CI/CD trigger for the policy.",
				Computed:    true,
			},
			"override_issue_severity": schema.StringAttribute{
				Description: "Set the severity of the issue (and override the system severity). If not used, system severity is kept.",
				Computed:    true,
			},
			"actions": schema.SingleNestedAttribute{
				Description: "Actions to take when the policy detects its target risk and the policy is triggered.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"report_issue": schema.BoolAttribute{
						Description: "Indicates if triggering the policy should create an issue in the connected system.",
						Computed:    true,
					},
					"block_cicd": schema.BoolAttribute{
						Description: "Indicates if triggering the policy should block the CI/CD pipeline. Ensure that the CI/CD trigger is selected.",
						Computed:    true,
					},
					"report_cicd": schema.BoolAttribute{
						Description: "Indicates if triggering the policy should soft fail the CI/CD pipeline in the platform. Ensure that the CI/CD trigger is selected.",
						Computed:    true,
					},
				},
			},
		},
	}
}

func ciImageTriggerDataSourceAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Computed: true,
		Attributes: map[string]schema.Attribute{
			"enabled":                 schema.BoolAttribute{Computed: true},
			"override_issue_severity": schema.StringAttribute{Computed: true},
			"actions": schema.SingleNestedAttribute{
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"report_issue": schema.BoolAttribute{Computed: true},
					"report_cicd":  schema.BoolAttribute{Computed: true},
					"block_cicd":   schema.BoolAttribute{Computed: true},
				},
			},
		},
	}
}

func imageRegistryTriggerDataSourceAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Computed: true,
		Attributes: map[string]schema.Attribute{
			"enabled":                 schema.BoolAttribute{Computed: true},
			"override_issue_severity": schema.StringAttribute{Computed: true},
			"actions": schema.SingleNestedAttribute{
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"report_issue": schema.BoolAttribute{Computed: true},
				},
			},
		},
	}
}

func (d *policyDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *policyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config appsecModels.PolicyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	remote, err := d.client.GetPolicy(ctx, config.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Reading AppSec Policy", util.FormatAPIError(err))
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, &remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
