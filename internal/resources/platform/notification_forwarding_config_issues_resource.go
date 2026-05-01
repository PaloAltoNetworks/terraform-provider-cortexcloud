// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	sdk "github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	sharedModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/shared"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &notificationForwardingConfigIssuesResource{}
	_ resource.ResourceWithConfigure      = &notificationForwardingConfigIssuesResource{}
	_ resource.ResourceWithImportState    = &notificationForwardingConfigIssuesResource{}
	_ resource.ResourceWithValidateConfig = &notificationForwardingConfigIssuesResource{}
)

// NewNotificationForwardingConfigIssuesResource is a helper function to simplify the provider implementation.
func NewNotificationForwardingConfigIssuesResource() resource.Resource {
	return &notificationForwardingConfigIssuesResource{}
}

// notificationForwardingConfigIssuesResource is the resource implementation.
type notificationForwardingConfigIssuesResource struct {
	client *sdk.Client
}

// Metadata returns the resource type name.
func (r *notificationForwardingConfigIssuesResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_forwarding_config_issues"
}

func (r *notificationForwardingConfigIssuesResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a notification forwarding configuration for issues.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the configuration.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseNonNullStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the configuration.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the configuration.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"enabled": schema.BoolAttribute{
				Description: "The status of the configuration.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"scope": schema.SingleNestedAttribute{
				Description: "The filter for the configuration.",
				Optional:    true,
				Computed:    true,
				Attributes:  sharedModels.RootFilterAttributes,
				Default: objectdefault.StaticValue(types.ObjectNull(
					sharedModels.RootFilterAttrTypeMap,
				)),
			},
			"email_config": schema.SingleNestedAttribute{
				Description: "Configure notification forwarding for a list of email addresses.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"distribution_list": schema.ListAttribute{
						Description: "The email addresses that notifications will be sent to.",
						Required:    true,
						ElementType: types.StringType,
					},
					"subject": schema.StringAttribute{
						Description: "The subject that will be used for notification emails. Leave blank to have Cortex Cloud auto-generate a subject. Must not exceed 256 characters.",
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(""),
						Validators: []validator.String{
							stringvalidator.LengthAtMost(256),
						},
					},
					"format": schema.StringAttribute{
						Description: fmt.Sprintf("The format that will be used for the email body. Possible values are \"%s\". https://docs-cortex.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Runtime-Security-Documentation/Log-format-for-IOC-and-BIOC-issues", strings.Join(enums.AllNotificationFormats(), `", "`)),
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(enums.NotificationFormatIssue.String()),
						Validators: []validator.String{
							stringvalidator.OneOf(enums.AllNotificationFormats()...),
						},
					},
					"grouping_timeframe": schema.Int32Attribute{
						Description: "The time frame, in minutes, that specifies how often Cortex Cloud sends notifications. Set to 0 to have Cortex Cloud send a notification for each issue/event. Must be a value between 0 and 1440, inclusive. Default value is 10.",
						Optional:    true,
						Computed:    true,
						Default:     int32default.StaticInt32(10),
						Validators: []validator.Int32{
							int32validator.Between(0, 1440),
						},
					},
				},
				Default: objectdefault.StaticValue(types.ObjectNull(
					map[string]attr.Type{
						"distribution_list": types.ListType{
							ElemType: types.StringType,
						},
						"subject":            types.StringType,
						"grouping_timeframe": types.Int32Type,
						"format":             types.StringType,
					},
				)),
			},
			"syslog_config": schema.SingleNestedAttribute{
				Description: "Configure notification forwarding to a syslog server.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"server_id": schema.Int64Attribute{
						Description: "The ID of the syslog server to forward notifications to.",
						Required:    true,
					},
					"format": schema.StringAttribute{
						Description: fmt.Sprintf("The format that will be used for the syslog message body. Possible values are \"%s\".", strings.Join(enums.AllNotificationFormats(), `", "`)),
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(enums.NotificationFormatIssue.String()),
						Validators: []validator.String{
							stringvalidator.OneOf(enums.AllNotificationFormats()...),
						},
					},
				},
				Default: objectdefault.StaticValue(types.ObjectNull(
					map[string]attr.Type{
						"server_id": types.Int64Type,
						"format":    types.StringType,
					},
				)),
			},
			"timezone": schema.StringAttribute{
				Description: "The timezone used by the configuration.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseNonNullStateForUnknown(),
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *notificationForwardingConfigIssuesResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)

	if !ok {
		util.AddUnexpectedResourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	r.client = client.Platform
}

func (r *notificationForwardingConfigIssuesResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config *models.NotificationForwardingConfigurationIssuesModel = &models.NotificationForwardingConfigurationIssuesModel{}
	config.FromTfsdk(ctx, &resp.Diagnostics, req.Config)
	if resp.Diagnostics.HasError() {
		return
	}

	// Throw error if no forwarding destinations have been configured
	if config.EmailConfig == nil &&
		config.SyslogConfig == nil {
		resp.Diagnostics.AddError(
			"Invalid Resource Configuration",
			"At least one of the following attributes must be configured: email_config, syslog_config",
		)
	}
}

func (r *notificationForwardingConfigIssuesResource) setEnabledAttr(ctx context.Context, diagnostics *diag.Diagnostics, id string, enabled bool) {
	var (
		toggleErr error
		op        string
	)
	if enabled {
		op = "enable"
		toggleErr = r.client.EnableNotificationForwardingConfiguration(ctx, id)
	} else {
		op = "disable"
		toggleErr = r.client.DisableNotificationForwardingConfiguration(ctx, id)
	}

	if toggleErr != nil {
		diagnostics.AddError(
			"Error Toggling Issues Notification Forwarding Configuration",
			fmt.Sprintf("Error occurred while attempting to %s notification forwarding configuration: %s", op, toggleErr.Error()),
		)
		return
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *notificationForwardingConfigIssuesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan *models.NotificationForwardingConfigurationIssuesModel = &models.NotificationForwardingConfigurationIssuesModel{}
	plan.FromTfsdk(ctx, &resp.Diagnostics, req.Plan)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := plan.ToCreateOrUpdateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	createResp, err := r.client.CreateNotificationForwardingConfiguration(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Issues Notification Forwarding Configuration",
			err.Error(),
		)
		return
	}

	if !plan.Shared.Enabled.ValueBool() {
		err := r.client.DisableNotificationForwardingConfiguration(ctx, createResp.ID)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Disabling Created Issues Notification Forwarding Configuration",
				fmt.Sprintf("Error occurred while attempting to disable the notification forwarding configuration after creation: %s\n\nThe provider will now delete the new configuration.", err.Error()),
			)

			deleteErr := r.client.DeleteNotificationForwardingConfiguration(ctx, createResp.ID)
			if deleteErr != nil {
				resp.Diagnostics.AddError(
					"Error Deleting New Issues Notification Forwarding Configuration",
					fmt.Sprintf("Error occurred while attempting to delete notification forwarding configuration: %s\n\nNavigate to the Notifications configuration page in the Cortex Cloud console to manually remove the dangling configuration.", err.Error()),
				)
			}
			return
		}
		createResp.Enabled = false
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, createResp)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &struct {
		ID           types.String                    `tfsdk:"id"`
		Name         types.String                    `tfsdk:"name"`
		Description  types.String                    `tfsdk:"description"`
		Enabled      types.Bool                      `tfsdk:"enabled"`
		Scope        *sharedModels.RootFilterModel   `tfsdk:"scope"`
		EmailConfig  *models.EmailConfigIssuesModel  `tfsdk:"email_config"`
		SyslogConfig *models.SyslogConfigIssuesModel `tfsdk:"syslog_config"`
		Timezone     types.String                    `tfsdk:"timezone"`
	}{
		ID:           plan.Shared.ID,
		Name:         plan.Shared.Name,
		Description:  plan.Shared.Description,
		Enabled:      plan.Shared.Enabled,
		Scope:        plan.Shared.Scope,
		Timezone:     plan.Shared.Timezone,
		EmailConfig:  plan.EmailConfig,
		SyslogConfig: plan.SyslogConfig,
	})...)
}

// Read refreshes the Terraform state with the latest data.
func (r *notificationForwardingConfigIssuesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state *models.NotificationForwardingConfigurationIssuesModel = &models.NotificationForwardingConfigurationIssuesModel{}
	state.FromTfsdk(ctx, &resp.Diagnostics, req.State)
	if resp.Diagnostics.HasError() {
		return
	}

	remote, err := r.client.GetNotificationForwardingConfiguration(ctx, state.Shared.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Issues Notification Forwarding Configuration",
			err.Error(),
		)
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, remote)

	// Set refreshed state
	tflog.Debug(ctx, "Setting refreshed state")
	resp.Diagnostics.Append(resp.State.Set(ctx, &struct {
		ID           types.String                    `tfsdk:"id"`
		Name         types.String                    `tfsdk:"name"`
		Description  types.String                    `tfsdk:"description"`
		Enabled      types.Bool                      `tfsdk:"enabled"`
		Scope        *sharedModels.RootFilterModel   `tfsdk:"scope"`
		EmailConfig  *models.EmailConfigIssuesModel  `tfsdk:"email_config"`
		SyslogConfig *models.SyslogConfigIssuesModel `tfsdk:"syslog_config"`
		Timezone     types.String                    `tfsdk:"timezone"`
	}{
		ID:           state.Shared.ID,
		Name:         state.Shared.Name,
		Description:  state.Shared.Description,
		Enabled:      state.Shared.Enabled,
		Scope:        state.Shared.Scope,
		Timezone:     state.Shared.Timezone,
		EmailConfig:  state.EmailConfig,
		SyslogConfig: state.SyslogConfig,
	})...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *notificationForwardingConfigIssuesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan *models.NotificationForwardingConfigurationIssuesModel = &models.NotificationForwardingConfigurationIssuesModel{}
	plan.FromTfsdk(ctx, &resp.Diagnostics, req.Plan)
	if resp.Diagnostics.HasError() {
		return
	}

	var state *models.NotificationForwardingConfigurationIssuesModel = &models.NotificationForwardingConfigurationIssuesModel{}
	state.FromTfsdk(ctx, &resp.Diagnostics, req.State)
	if resp.Diagnostics.HasError() {
		return
	}

	var (
		isDisablingConfig   bool = !plan.Shared.Enabled.ValueBool()
		isUpdatingOtherAttr bool = false
	)

	if !plan.Shared.ID.Equal(state.Shared.ID) || !plan.Shared.Name.Equal(state.Shared.Name) ||
		!plan.Shared.Description.Equal(state.Shared.Description) || !plan.Shared.Timezone.Equal(state.Shared.Timezone) ||
		!plan.EmailConfig.Equals(state.EmailConfig) || !plan.SyslogConfig.Equals(state.SyslogConfig) || !plan.Shared.Scope.Equals(state.Shared.Scope) {
		tflog.Trace(ctx, "Updating other fields in issues notification forwarding configuration")
		isUpdatingOtherAttr = true
	}

	// Re-enable notification forwarding configuration if disabled
	if !state.Shared.Enabled.ValueBool() {
		r.setEnabledAttr(ctx, &resp.Diagnostics, state.Shared.ID.ValueString(), true)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if isUpdatingOtherAttr {
		updateReq := plan.ToCreateOrUpdateRequest(ctx, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		updateResp, err := r.client.UpdateNotificationForwardingConfiguration(ctx, state.Shared.ID.ValueString(), updateReq)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Updating Issues Notification Forwarding Configuration",
				fmt.Sprintf("Error occurred while attempting to update notification forwarding configuration \"%s\": %s", state.Shared.Name.ValueString(), err.Error()),
			)
			return
		}

		plan.RefreshFromRemote(ctx, &resp.Diagnostics, updateResp)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if isDisablingConfig {
		r.setEnabledAttr(ctx, &resp.Diagnostics, state.Shared.ID.ValueString(), false)
		if resp.Diagnostics.HasError() {
			return
		}

		// Re-set enabled attribute to false, in case it was set to
		// true while updating the other resource attributes
		plan.Shared.Enabled = types.BoolValue(false)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &struct {
		ID           types.String                    `tfsdk:"id"`
		Name         types.String                    `tfsdk:"name"`
		Description  types.String                    `tfsdk:"description"`
		Enabled      types.Bool                      `tfsdk:"enabled"`
		Scope        *sharedModels.RootFilterModel   `tfsdk:"scope"`
		EmailConfig  *models.EmailConfigIssuesModel  `tfsdk:"email_config"`
		SyslogConfig *models.SyslogConfigIssuesModel `tfsdk:"syslog_config"`
		Timezone     types.String                    `tfsdk:"timezone"`
	}{
		ID:           plan.Shared.ID,
		Name:         plan.Shared.Name,
		Description:  plan.Shared.Description,
		Enabled:      plan.Shared.Enabled,
		Scope:        plan.Shared.Scope,
		Timezone:     plan.Shared.Timezone,
		EmailConfig:  plan.EmailConfig,
		SyslogConfig: plan.SyslogConfig,
	})...)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *notificationForwardingConfigIssuesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state *models.NotificationForwardingConfigurationIssuesModel = &models.NotificationForwardingConfigurationIssuesModel{}
	state.FromTfsdk(ctx, &resp.Diagnostics, req.State)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteNotificationForwardingConfiguration(ctx, state.Shared.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Issues Notification Forwarding Configuration",
			err.Error(),
		)
	}

	resp.State.RemoveResource(ctx)
}

// ImportState imports the resource into the Terraform state.
func (r *notificationForwardingConfigIssuesResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
