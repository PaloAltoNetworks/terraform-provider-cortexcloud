// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp

import (
	"context"
	"fmt"

	cwpModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cwp"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	sharedModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/shared"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/planmodifiers"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/cwp"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &containerRegistryResource{}
	_ resource.ResourceWithConfigure      = &containerRegistryResource{}
	_ resource.ResourceWithImportState    = &containerRegistryResource{}
	_ resource.ResourceWithValidateConfig = &containerRegistryResource{}
)

// NewContainerRegistryResource returns the cortexcloud_container_registry resource.
func NewContainerRegistryResource() resource.Resource {
	return &containerRegistryResource{}
}

type containerRegistryResource struct {
	client *cwp.Client
}

func (r *containerRegistryResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_container_registry"
}

func (r *containerRegistryResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a third-party container registry connector (CWP Registry Onboarding).\n\n" +
			"`password` and `auth_token` are never read back from the API. After `terraform import` they are " +
			"empty in state, so the first apply that sets them sends the full connector again.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:   "The connector ID.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"vendor": schema.StringAttribute{
				Description: "The registry vendor. Changing this forces a new connector.",
				Required:    true,
				Validators:  []validator.String{stringvalidator.OneOf(enums.AllRegistryVendors()...)},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the registry connector.",
				Required:    true,
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the connector is enabled. Defaults to `true`.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"url": schema.StringAttribute{
				Description: "The URL of the registry.",
				Required:    true,
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"tenant_id": schema.StringAttribute{
				Description:   "The tenant ID the connector belongs to.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"username": schema.StringAttribute{
				Description: "The username for registry authentication. Must be set together with `password`.",
				Optional:    true,
			},
			"password": schema.StringAttribute{
				Description: "The password for registry authentication. Never read back from the API.",
				Optional:    true,
				Sensitive:   true,
			},
			"auth_token": schema.StringAttribute{
				Description: "A token for registry authentication. Never read back from the API.",
				Optional:    true,
				Sensitive:   true,
			},
			"scanning_mode": schema.StringAttribute{
				Description: "Where scanning runs. `CLOUD` requires `cloud_provider` and `region`; " +
					"`OUTPOST` requires `outpost_id`; `BROKER` requires `broker_type` and `broker_id`.",
				Required:   true,
				Validators: []validator.String{stringvalidator.OneOf(enums.AllRegistryScanningModes()...)},
			},
			"cloud_provider": schema.StringAttribute{
				Description: "The Cortex cloud provider used for `CLOUD` scanning.",
				Optional:    true,
				Validators:  []validator.String{stringvalidator.OneOf(enums.AllRegistryCloudProviders()...)},
			},
			"region": schema.StringAttribute{
				Description: "The region used for scanning. Choose the region closest to the registry.",
				Optional:    true,
			},
			"outpost_id": schema.StringAttribute{
				Description: "The outpost ID used for `OUTPOST` scanning. Required when `scanning_mode` is " +
					"`OUTPOST`. For other scanning modes the API may assign a value, which is then exported here.",
				Optional: true,
				Computed: true,
				// Keep the prior value only while scanning_mode is unchanged. Otherwise
				// an outpost ID left over from OUTPOST mode would be sent in the
				// full-replacement PUT after switching to CLOUD or BROKER.
				PlanModifiers: []planmodifier.String{
					planmodifiers.StringUseStateForUnknownIfAttributeUnchanged(path.Root("scanning_mode")),
				},
			},
			"broker_type": schema.StringAttribute{
				Description: "The Broker VM type used for `BROKER` scanning.",
				Optional:    true,
				Validators:  []validator.String{stringvalidator.OneOf(enums.AllRegistryBrokerTypes()...)},
			},
			"broker_id": schema.StringAttribute{
				Description: "The broker ID used for `BROKER` scanning.",
				Optional:    true,
			},
			"registry_type": schema.StringAttribute{
				Description: "Whether the registry is cloud hosted or self hosted.",
				Optional:    true,
				Validators:  []validator.String{stringvalidator.OneOf(enums.AllRegistryHostingTypes()...)},
			},
			"insecure_pull": schema.BoolAttribute{
				Description: "Allow image pulls from insecure registries. Defaults to `false`.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"ca_certificate": schema.StringAttribute{
				Description: "A CA certificate used to authenticate the registry.",
				Optional:    true,
			},
			"repository": schema.StringAttribute{
				Description: "The repository used for image discovery.",
				Optional:    true,
			},
			"allow_static_ips": schema.BoolAttribute{
				Description: "Whether static IP addresses are allowed. Defaults to `false`.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"ip_identifier": schema.StringAttribute{
				Description: "The identifier associated with the static IP address.",
				Optional:    true,
			},
			"initial_scan_configuration": schema.SingleNestedAttribute{
				Description: "Which images are scanned when the connector is onboarded.",
				Required:    true,
				Attributes: map[string]schema.Attribute{
					"mode": schema.StringAttribute{
						Description: "`ALL`, `LATEST_TAG` or `TAGS_MODIFIED_DAYS`.",
						Required:    true,
						Validators:  []validator.String{stringvalidator.OneOf(enums.AllRegistryScanningTypes()...)},
					},
					"num_days": schema.Int64Attribute{
						Description: "Days (1-90) within which tags must have been modified. " +
							"Required when `mode` is `TAGS_MODIFIED_DAYS`, and only allowed then.",
						Optional:   true,
						Validators: []validator.Int64{int64validator.Between(1, 90)},
					},
				},
			},
			"asset_scope_filters": schema.SingleNestedAttribute{
				Description: "Filters that scope which registry assets are scanned.",
				Optional:    true,
				Attributes:  sharedModels.RootFilterAttributes,
			},
			"filter_type": schema.StringAttribute{
				Description: "Whether `asset_scope_filters` include or exclude assets. Defaults to `INCLUDE`.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(enums.RegistryFilterTypeInclude.String()),
				Validators:  []validator.String{stringvalidator.OneOf(enums.AllRegistryFilterTypes()...)},
			},
			"gitlab": schema.SingleNestedAttribute{
				Description: "GitLab-specific options. Only valid with vendor `GITLAB_CONTAINER_REGISTRY`.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"group_ids":       schema.StringAttribute{Description: "The group IDs to scan.", Optional: true},
					"project_ids":     schema.StringAttribute{Description: "The project IDs to scan.", Optional: true},
					"api_domain_name": schema.StringAttribute{Description: "The API domain name to use for scanning.", Optional: true},
				},
			},
			"docker_hub": schema.SingleNestedAttribute{
				Description: "Docker Hub-specific options. Only valid with vendor `DOCKER_HUB`.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"repository": schema.StringAttribute{Description: "The Docker Hub repository to scan.", Optional: true},
				},
			},
			"openshift": schema.SingleNestedAttribute{
				Description: "OpenShift-specific options. Only valid with vendor `OPENSHIFT`.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"cluster_id":            schema.StringAttribute{Description: "The OpenShift cluster ID.", Optional: true},
					"cluster_name":          schema.StringAttribute{Description: "The OpenShift cluster name.", Optional: true},
					"cluster_asset_id":      schema.StringAttribute{Description: "The asset ID of the cluster.", Optional: true},
					"cluster_asset_type_id": schema.StringAttribute{Description: "The asset type ID of the cluster.", Optional: true},
					"cluster_realm":         schema.StringAttribute{Description: "The realm the cluster resides in.", Optional: true},
				},
			},
		},
	}
}

// ValidateConfig enforces the cross-attribute rules the API applies, so they
// fail at plan time instead of as a 400 during apply. A rule is skipped while
// any value it depends on is unknown.
func (r *containerRegistryResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg cwpModels.ContainerRegistryModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	requireSet := func(mode string, attr string, v types.String) {
		if v.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root(attr), "Missing Required Attribute",
				fmt.Sprintf("%q is required when scanning_mode is %q.", attr, mode))
		}
	}

	if !cfg.ScanningMode.IsUnknown() {
		switch mode := cfg.ScanningMode.ValueString(); enums.RegistryScanningMode(mode) {
		case enums.RegistryScanningModeCloud:
			requireSet(mode, "cloud_provider", cfg.CloudProvider)
			requireSet(mode, "region", cfg.Region)
		case enums.RegistryScanningModeOutpost:
			requireSet(mode, "outpost_id", cfg.OutpostID)
		case enums.RegistryScanningModeBroker:
			requireSet(mode, "broker_type", cfg.BrokerType)
			requireSet(mode, "broker_id", cfg.BrokerID)
		}
	}

	if isc := cfg.InitialScanConfiguration; isc != nil && !isc.Mode.IsUnknown() && !isc.NumDays.IsUnknown() {
		daysPath := path.Root("initial_scan_configuration").AtName("num_days")
		byDays := isc.Mode.ValueString() == enums.RegistryScanningTypeTagsModifiedDays.String()
		if byDays && isc.NumDays.IsNull() {
			resp.Diagnostics.AddAttributeError(daysPath, "Missing Required Attribute",
				"num_days is required when initial_scan_configuration.mode is TAGS_MODIFIED_DAYS.")
		}
		if !byDays && !isc.NumDays.IsNull() {
			resp.Diagnostics.AddAttributeError(daysPath, "Invalid Attribute Combination",
				"num_days is only allowed when initial_scan_configuration.mode is TAGS_MODIFIED_DAYS.")
		}
	}

	if !cfg.Username.IsUnknown() && !cfg.Password.IsUnknown() && cfg.Username.IsNull() != cfg.Password.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("password"), "Invalid Attribute Combination",
			"username and password must be set together.")
	}

	if !cfg.Vendor.IsUnknown() {
		vendor := cfg.Vendor.ValueString()
		checkBlock := func(attr string, set bool, want enums.RegistryVendor) {
			if set && vendor != want.String() {
				resp.Diagnostics.AddAttributeError(path.Root(attr), "Invalid Attribute Combination",
					fmt.Sprintf("%q is only valid when vendor is %q (vendor is %q).", attr, want, vendor))
			}
		}
		checkBlock("gitlab", cfg.GitLab != nil, enums.RegistryVendorGitLabContainerRegistry)
		checkBlock("docker_hub", cfg.DockerHub != nil, enums.RegistryVendorDockerHub)
		checkBlock("openshift", cfg.OpenShift != nil, enums.RegistryVendorOpenShift)
	}
}

func (r *containerRegistryResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	clients, ok := req.ProviderData.(*models.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedResourceConfigurationTypeError(&resp.Diagnostics, "*models.CortexCloudSDKClients", req.ProviderData)
		return
	}
	r.client = clients.CWP
}

func (r *containerRegistryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan cwpModels.ContainerRegistryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := plan.ToRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := r.client.CreateRegistryConnector(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Container Registry", err.Error())
		return
	}

	// Record the ID immediately so a failed read-back does not orphan the connector.
	plan.ID = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)

	remote, err := r.client.GetRegistryConnector(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Container Registry After Create", err.Error())
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *containerRegistryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state cwpModels.ContainerRegistryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	remote, err := r.client.GetRegistryConnector(ctx, state.ID.ValueString())
	if err != nil {
		if cwp.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error Reading Container Registry", err.Error())
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *containerRegistryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan, state cwpModels.ContainerRegistryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()
	plan.ID = state.ID

	// PUT is a full replacement, so the body is built from the whole plan.
	body := plan.ToRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.UpdateRegistryConnector(ctx, id, body); err != nil {
		resp.Diagnostics.AddError("Error Updating Container Registry", err.Error())
		return
	}

	remote, err := r.client.GetRegistryConnector(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Container Registry After Update", err.Error())
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *containerRegistryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state cwpModels.ContainerRegistryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteRegistryConnector(ctx, state.ID.ValueString()); err != nil && !cwp.IsNotFound(err) {
		resp.Diagnostics.AddError("Error Deleting Container Registry", err.Error())
	}
}

func (r *containerRegistryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
