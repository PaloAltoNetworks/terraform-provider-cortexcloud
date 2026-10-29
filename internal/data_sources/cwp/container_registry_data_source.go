// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp

import (
	"context"

	cwpModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cwp"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	sharedModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/shared"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/cwp"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
)

// maxFilterDataSourceDepth is derived from shared.MaxFilterDepth so the data
// source always exposes the same nesting depth as the resource's
// asset_scope_filters; a mismatch would make State.Set fail on deep filters.
const maxFilterDataSourceDepth = sharedModels.MaxFilterDepth

// filterDataSourceAttributes builds a Computed-only, recursive AND/OR filter
// schema for datasource/schema. It cannot reuse
// internal/models/shared.RootFilterAttributes because that helper returns
// resource/schema.Attribute values, which are a different type than what
// datasource/schema.SingleNestedAttribute.Attributes accepts.
func filterDataSourceAttributes(depth, maxDepth int) map[string]schema.Attribute {
	attrs := map[string]schema.Attribute{
		"search_field": schema.StringAttribute{Description: "The field that was matched on.", Computed: true},
		"search_type":  schema.StringAttribute{Description: "The comparison that was applied.", Computed: true},
		"search_value": schema.StringAttribute{Description: "The value that was compared against.", Computed: true},
	}
	if depth < maxDepth {
		attrs["and"] = schema.ListNestedAttribute{
			Computed:     true,
			NestedObject: schema.NestedAttributeObject{Attributes: filterDataSourceAttributes(depth+1, maxDepth)},
		}
		attrs["or"] = schema.ListNestedAttribute{
			Computed:     true,
			NestedObject: schema.NestedAttributeObject{Attributes: filterDataSourceAttributes(depth+1, maxDepth)},
		}
	}
	return attrs
}

var (
	_ datasource.DataSource              = &containerRegistryDataSource{}
	_ datasource.DataSourceWithConfigure = &containerRegistryDataSource{}
)

// NewContainerRegistryDataSource returns the cortexcloud_container_registry data source.
func NewContainerRegistryDataSource() datasource.DataSource {
	return &containerRegistryDataSource{}
}

type containerRegistryDataSource struct {
	client *cwp.Client
}

func (d *containerRegistryDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_container_registry"
}

func (d *containerRegistryDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	stringAttr := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{Description: desc, Computed: true}
	}

	resp.Schema = schema.Schema{
		Description: "Provides details about a third-party container registry connector (CWP Registry Onboarding).\n\n" +
			"`password` and `auth_token` are never returned by the API and are always empty in this data source.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The connector ID to look up.",
				Required:    true,
			},
			"vendor":         stringAttr("The registry vendor."),
			"name":           stringAttr("The name of the registry connector."),
			"enabled":        schema.BoolAttribute{Description: "Whether the connector is enabled.", Computed: true},
			"url":            stringAttr("The URL of the registry."),
			"tenant_id":      stringAttr("The tenant ID the connector belongs to."),
			"username":       stringAttr("The username for registry authentication."),
			"password":       schema.StringAttribute{Description: "Never returned by the API.", Computed: true, Sensitive: true},
			"auth_token":     schema.StringAttribute{Description: "Never returned by the API.", Computed: true, Sensitive: true},
			"scanning_mode":  stringAttr("Where scanning runs."),
			"cloud_provider": stringAttr("The Cortex cloud provider used for CLOUD scanning."),
			"region":         stringAttr("The region used for scanning."),
			"outpost_id":     stringAttr("The outpost ID used for OUTPOST scanning."),
			"broker_type":    stringAttr("The Broker VM type used for BROKER scanning."),
			"broker_id":      stringAttr("The broker ID used for BROKER scanning."),
			"registry_type":  stringAttr("Whether the registry is cloud hosted or self hosted."),
			"insecure_pull":  schema.BoolAttribute{Description: "Whether insecure image pulls are allowed.", Computed: true},
			"ca_certificate": stringAttr("The CA certificate used to authenticate the registry."),
			"repository":     stringAttr("The repository used for image discovery."),
			"allow_static_ips": schema.BoolAttribute{
				Description: "Whether static IP addresses are allowed.",
				Computed:    true,
			},
			"ip_identifier": stringAttr("The identifier associated with the static IP address."),
			"initial_scan_configuration": schema.SingleNestedAttribute{
				Description: "Which images were scanned when the connector was onboarded.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"mode":     stringAttr("ALL, LATEST_TAG or TAGS_MODIFIED_DAYS."),
					"num_days": schema.Int64Attribute{Description: "Days within which tags must have been modified.", Computed: true},
				},
			},
			"asset_scope_filters": schema.SingleNestedAttribute{
				Description: "Filters that scope which registry assets are scanned.",
				Computed:    true,
				Attributes:  filterDataSourceAttributes(0, maxFilterDataSourceDepth),
			},
			"filter_type": stringAttr("Whether asset_scope_filters include or exclude assets."),
			"gitlab": schema.SingleNestedAttribute{
				Description: "GitLab-specific options.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"group_ids":       stringAttr("The group IDs scanned."),
					"project_ids":     stringAttr("The project IDs scanned."),
					"api_domain_name": stringAttr("The API domain name used for scanning."),
				},
			},
			"docker_hub": schema.SingleNestedAttribute{
				Description: "Docker Hub-specific options.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"repository": stringAttr("The Docker Hub repository scanned."),
				},
			},
			"openshift": schema.SingleNestedAttribute{
				Description: "OpenShift-specific options.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"cluster_id":            stringAttr("The OpenShift cluster ID."),
					"cluster_name":          stringAttr("The OpenShift cluster name."),
					"cluster_asset_id":      stringAttr("The asset ID of the cluster."),
					"cluster_asset_type_id": stringAttr("The asset type ID of the cluster."),
					"cluster_realm":         stringAttr("The realm the cluster resides in."),
				},
			},
		},
	}
}

func (d *containerRegistryDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	clients, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}
	d.client = clients.CWP
}

func (d *containerRegistryDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config cwpModels.ContainerRegistryModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	remote, err := d.client.GetRegistryConnector(ctx, config.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Container Registry", err.Error())
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
