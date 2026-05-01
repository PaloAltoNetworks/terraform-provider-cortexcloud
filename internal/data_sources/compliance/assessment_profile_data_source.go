// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/compliance"
	complianceTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/compliance"
	complianceModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/compliance"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &assessmentProfileDataSource{}
	_ datasource.DataSourceWithConfigure = &assessmentProfileDataSource{}
)

func NewAssessmentProfileDataSource() datasource.DataSource {
	return &assessmentProfileDataSource{}
}

type assessmentProfileDataSource struct {
	client *compliance.Client
}

func (d *assessmentProfileDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_assessment_profile"
}

func (d *assessmentProfileDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides details about a Compliance Assessment Profile.",
		Attributes: map[string]schema.Attribute{
			"id":               schema.StringAttribute{Required: true},
			"name":             schema.StringAttribute{Computed: true},
			"standard_id":      schema.StringAttribute{Computed: true},
			"standard_name":    schema.StringAttribute{Computed: true},
			"asset_group_id":   schema.Int64Attribute{Computed: true},
			"asset_group_name": schema.StringAttribute{Computed: true},
			"description":      schema.StringAttribute{Computed: true},
			"report_frequency": schema.StringAttribute{Computed: true},
			"report_targets":   schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"report_type":      schema.StringAttribute{Computed: true},
			"enabled":          schema.BoolAttribute{Computed: true},
			"insert_ts":        schema.Int64Attribute{Computed: true},
			"modify_ts":        schema.Int64Attribute{Computed: true},
			"created_by":       schema.StringAttribute{Computed: true},
			"modified_by":      schema.StringAttribute{Computed: true},
		},
	}
}

func (d *assessmentProfileDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = client.Compliance
}

func (d *assessmentProfileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config complianceModels.AssessmentProfileModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	getReq := complianceTypes.GetAssessmentProfileRequest{
		ID: config.ID.ValueString(),
	}

	remote, err := d.client.GetAssessmentProfile(ctx, getReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Compliance Assessment Profile", err.Error())
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
