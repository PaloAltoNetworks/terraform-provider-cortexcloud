// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/validators"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &CloudIntegrationInstanceResource{}
	_ resource.ResourceWithImportState = &CloudIntegrationInstanceResource{}
)

// NewCloudIntegrationInstanceResource is a helper function to simplify the provider implementation.
func NewCloudIntegrationInstanceResource() resource.Resource {
	return &CloudIntegrationInstanceResource{}
}

// CloudIntegrationInstanceResource is the resource implementation. It manages an
// existing, connected cloud integration instance so that in-place edits (for
// example toggling additional_capabilities) are applied via the platform's
// edit_instance API instead of forcing a destroy-and-recreate.
type CloudIntegrationInstanceResource struct {
	client *cloudonboarding.Client
}

// Metadata returns the resource type name.
func (r *CloudIntegrationInstanceResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_integration_instance"
}

// Schema defines the schema for the resource.
func (r *CloudIntegrationInstanceResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an existing, connected Cloud Service Provider " +
			"integration instance. This resource supports in-place edits of a " +
			"connected instance (for example, enabling or disabling additional " +
			"security capabilities) without forcing a destroy-and-recreate. The " +
			"instance is created by the platform (via the console or a cloud " +
			"integration template resource) and adopted into Terraform with " +
			"`terraform import`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "A unique identifier of the connected integration " +
					"instance. Changing this value refers to a different " +
					"instance and forces the resource to be recreated.",
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"instance_name": schema.StringAttribute{
				Description: "Name of the integration instance. If left " +
					"empty, the name will be auto-populated.",
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					validators.ValidateCloudIntegrationInstanceName(),
				},
			},
			"outpost_id": schema.StringAttribute{
				Description: "The ID of the outpost used for scanning.",
				Optional:    true,
				Computed:    true,
			},
			"cloud_provider": schema.StringAttribute{
				Description: "The cloud service provider that is being integrated.",
				Optional:    true,
				Computed:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllCloudProviders()...,
					),
				},
			},
			"cloud_partition": schema.StringAttribute{
				Description: "The cloud partition of the integration (for " +
					"example, an AWS GovCloud or China partition). This is a " +
					"write-only attribute: it is sent on edit but is not " +
					"returned by the platform and is therefore not refreshed " +
					"into state.",
				Optional: true,
			},
			"additional_capabilities": schema.SingleNestedAttribute{
				Description: "Define which additional security capabilities " +
					"to enable. Changes to these capabilities are applied " +
					"in-place to the connected instance.",
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"data_security_posture_management": schema.BoolAttribute{
						Description: "Whether to enable data security " +
							"posture management, an agentless data security " +
							"scanner that discovers, classifies, protects, " +
							"and governs sensitive data.",
						Optional: true,
						Computed: true,
					},
					"registry_scanning": schema.BoolAttribute{
						Description: "Whether to enable registry scanning, " +
							"a container registry scanner that scans " +
							"registry images for vulnerabilities, malware, " +
							"and secrets.",
						Optional: true,
						Computed: true,
					},
					"registry_scanning_options": schema.SingleNestedAttribute{
						Description: "Additional configuration options for registry scanning.",
						Optional:    true,
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Description: "Type of registry scanning. " +
									"Must be one of `ALL`, `LATEST_TAG` or " +
									"`TAGS_MODIFIED_DAYS`. If set to " +
									"`TAGS_MODIFIED_DAYS`, `last_days` must " +
									"be configured.",
								Optional: true,
								Computed: true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										enums.AllRegistryScanningTypes()...,
									),
									validators.AlsoRequiresOnStringValues(
										[]string{
											enums.RegistryScanningTypeTagsModifiedDays.String(),
										},
										path.MatchRelative().AtParent().AtName("last_days"),
									),
								},
							},
							"last_days": schema.Int32Attribute{
								Description: "Number of days within which " +
									"the tags on a registry image must have " +
									"been created or updated for the image " +
									"to be scanned. Minimum value is 0 and " +
									"maximum value is 90. Cannot be " +
									"configured if `type` is not set to " +
									"`TAGS_MODIFIED_DAYS`.",
								Optional: true,
								Computed: true,
							},
						},
					},
					"agentless_disk_scanning": schema.BoolAttribute{
						Description: "Whether to enable agentless disk scanning to remotely detect and remediate vulnerabilities during the development lifecycle.",
						Optional:    true,
						Computed:    true,
					},
					"serverless_scanning": schema.BoolAttribute{
						Description: "Whether to enable serverless scanning to detect and remediate vulnerabilities within serverless functions during the development lifecycle.",
						Optional:    true,
						Computed:    true,
					},
					"xsiam_analytics": schema.BoolAttribute{
						Description: "Whether to enable XSIAM analytics to " +
							"analyze your endpoint data to develop a " +
							"baseline and raise Analytics and Analytics " +
							"BIOC alerts when anomalies and malicious " +
							"behaviors are detected.",
						Optional: true,
						Computed: true,
					},
				},
			},
			"collection_configuration": schema.SingleNestedAttribute{
				Description: "Configure the data that will be collected.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"audit_logs": schema.SingleNestedAttribute{
						Description: "Configuration for audit logs " +
							"collection.",
						Optional: true,
						Computed: true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether to enable audit log " +
									"collection.",
								Optional: true,
								Computed: true,
							},
							"collection_method": schema.StringAttribute{
								Description: "Method of audit log collection.",
								Optional:    true,
								Computed:    true,
							},
							"data_events": schema.BoolAttribute{
								Description: "Whether to collect data " +
									"events as part of audit log collection.",
								Optional: true,
								Computed: true,
							},
						},
					},
				},
			},
			"custom_resources_tags": schema.SetNestedAttribute{
				Description: "Custom tags that will be applied to any new " +
					"resource created by Cortex in the cloud environment. " +
					"Updating an instance replaces the whole tag list with " +
					"the one configured here, so any tag that is not included " +
					"is removed from the instance. Declare every tag the " +
					"instance should carry. Omit the attribute to leave the " +
					"instance's existing tags untouched; it cannot be set to " +
					"an empty list, which the platform rejects.",
				Optional: true,
				Computed: true,
				Validators: []validator.Set{
					// The platform accepts a populated tag list and rejects an
					// omitted or null one, but returns HTTP 500 for an empty
					// list. Reject it here so the practitioner is told during
					// plan instead of part-way through an apply.
					setvalidator.SizeAtLeast(1),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"key": schema.StringAttribute{
							Description: "The key of the custom resource tag.",
							Optional:    true,
							Computed:    true,
						},
						"value": schema.StringAttribute{
							Description: "The value of the custom resource tag.",
							Optional:    true,
							Computed:    true,
						},
					},
				},
			},
			"scope_modifications": schema.SingleNestedAttribute{
				Description: "Modifications to the integration scope (accounts, " +
					"projects, subscriptions, or regions). This is a write-only " +
					"attribute: it is sent on edit but is not returned by the " +
					"platform and is therefore not refreshed into state.",
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"accounts":      scopeModificationGenericAttribute(),
					"projects":      scopeModificationGenericAttribute(),
					"subscriptions": scopeModificationGenericAttribute(),
					"regions": schema.SingleNestedAttribute{
						Description: "Modifications to the scanned regions.",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether the region modification is enabled.",
								Optional:    true,
							},
							"type": schema.StringAttribute{
								Description: "The type of the region modification.",
								Optional:    true,
							},
							"regions": schema.SetAttribute{
								Description: "The set of regions to modify.",
								Optional:    true,
								ElementType: types.StringType,
							},
						},
					},
				},
			},
			"collector": schema.StringAttribute{
				Description: "The collector used for this integration.",
				Computed:    true,
			},
			"scope": schema.StringAttribute{
				Description: "The scope of the integration.",
				Computed:    true,
			},
			"status": schema.StringAttribute{
				Description: "Status of the integration.",
				Computed:    true,
			},
			"security_capabilities": schema.SetNestedAttribute{
				Description: "The security capabilities enabled for this integration.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "The name of the security capability.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "The description of the security capability.",
							Computed:    true,
						},
						"status": schema.StringAttribute{
							Description: "The status of the security capability.",
							Computed:    true,
						},
						"status_code": schema.Int32Attribute{
							Description: "The status code of the security capability.",
							Computed:    true,
						},
						"last_scan_coverage": schema.SingleNestedAttribute{
							Description: "Coverage statistics from the last scan.",
							Computed:    true,
							Attributes: map[string]schema.Attribute{
								"excluded": schema.Int32Attribute{
									Description: "Number of resources excluded from the scan.",
									Computed:    true,
								},
								"issues": schema.Int32Attribute{
									Description: "Number of resources with issues found during the scan.",
									Computed:    true,
								},
								"pending": schema.Int32Attribute{
									Description: "Number of resources pending scan.",
									Computed:    true,
								},
								"success": schema.Int32Attribute{
									Description: "Number of resources successfully scanned.",
									Computed:    true,
								},
								"unsupported": schema.Int32Attribute{
									Description: "Number of resources not supported for scanning.",
									Computed:    true,
								},
							},
						},
					},
				},
			},
			"scan": schema.SingleNestedAttribute{
				Description: "Scan configuration for the integration.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"scan_method": schema.StringAttribute{
						Description: "Define what infrastructure the integration will use to scan cloud workloads.",
						Computed:    true,
					},
					"outpost_id": schema.StringAttribute{
						Description: "The ID of the outpost used for scanning.",
						Computed:    true,
					},
					"status_ui": schema.Int32Attribute{
						Description: "The scan status code as displayed in the UI.",
						Computed:    true,
					},
				},
			},
			"upgrade_available": schema.BoolAttribute{
				Description: "Indicates whether an upgrade is available for this integration.",
				Computed:    true,
			},
		},
	}
}

// scopeModificationGenericAttribute returns the nested attribute definition
// shared by the accounts, projects, and subscriptions scope_modifications
// blocks. The attribute is write-only (no refresh from remote).
func scopeModificationGenericAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Description: "A generic scope modification block (accounts, projects, " +
			"or subscriptions).",
		Optional: true,
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Description: "Whether the scope modification is enabled.",
				Optional:    true,
			},
			"type": schema.StringAttribute{
				Description: "The type of the scope modification.",
				Optional:    true,
			},
			"account_ids": schema.SetAttribute{
				Description: "The set of account IDs to modify.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"project_ids": schema.SetAttribute{
				Description: "The set of project IDs to modify.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"subscription_ids": schema.SetAttribute{
				Description: "The set of subscription IDs to modify.",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *CloudIntegrationInstanceResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured
	if req.ProviderData == nil {
		return
	}

	ctx = tflog.SetField(ctx, "resource_type", "cloud_integration_instance")
	ctx = tflog.SetField(ctx, "resource_operation", "Configure")
	tflog.Debug(ctx, "Configuring SDK client")

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)

	if !ok {
		util.AddUnexpectedResourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	r.client = client.CloudOnboarding
}

// Create is not supported: this resource manages an existing, connected
// integration instance created by the platform (via the console or a cloud
// integration template resource). Instead of provisioning a new instance, it
// returns an actionable error instructing the user to adopt an existing
// instance with `terraform import`.
func (r *CloudIntegrationInstanceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "cloud_integration_instance")
	ctx = tflog.SetField(ctx, "resource_operation", "Create")
	tflog.Debug(ctx, "Create is not supported; instructing user to import")

	addImportRequiredError(&resp.Diagnostics)
}

// addImportRequiredError appends the actionable error that instructs the user
// to adopt an existing connected integration instance with `terraform import`.
// It is a standalone helper so the diagnostic can be unit-tested without a live
// API or a fully-constructed create request.
func addImportRequiredError(diags *diag.Diagnostics) {
	diags.AddError(
		"Resource Must Be Imported",
		"The cortexcloud_cloud_integration_instance resource manages an "+
			"EXISTING, connected cloud integration instance; it cannot create "+
			"a new one. Create the instance via the Cortex Cloud console or a "+
			"cortexcloud_cloud_integration_template_* resource, then adopt it "+
			"into Terraform by running:\n\n"+
			"    terraform import cortexcloud_cloud_integration_instance.<name> <instance_id>\n\n"+
			"where <instance_id> is the ID of the connected integration "+
			"instance.",
	)
}

// Read refreshes the Terraform state with the latest values for the connected
// instance.
func (r *CloudIntegrationInstanceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "cloud_integration_instance")
	ctx = tflog.SetField(ctx, "resource_id_field", "id")
	ctx = tflog.SetField(ctx, "resource_operation", "Read")

	// Retrieve values from state
	tflog.Debug(ctx, "Retrieving values from state")
	var state models.CloudIntegrationInstanceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "resource_id_value", state.ID.ValueString())

	// Retrieve integration details from API
	tflog.Debug(ctx, "Executing API request")
	data, err := r.client.GetIntegrationInstanceDetails(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Cloud Integration Instance",
			err.Error(),
		)
		return
	}

	if data.ID == "" {
		tflog.Debug(ctx, "Instance not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	// Refresh state values
	tflog.Debug(ctx, "Refreshing configured attributes")
	state.RefreshFromRemote(ctx, &resp.Diagnostics, data)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set refreshed state
	tflog.Debug(ctx, "Setting refreshed state")
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update applies in-place edits to the connected integration instance via the
// platform's edit_instance API. This is the core behavior of the resource: it
// lets users toggle configurable attributes (for example
// additional_capabilities) without forcing a destroy-and-recreate. After the
// edit succeeds, the computed fields are refreshed by reading the instance back
// from the platform.
func (r *CloudIntegrationInstanceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "cloud_integration_instance")
	ctx = tflog.SetField(ctx, "resource_id_field", "id")
	ctx = tflog.SetField(ctx, "resource_operation", "Update")

	// Retrieve values from plan
	tflog.Debug(ctx, "Retrieving values from plan")
	var plan models.CloudIntegrationInstanceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "resource_id_value", plan.ID.ValueString())

	// edit_instance is a strict full-replace: any editable field omitted from the
	// request is blanked server-side. Read the current instance first and merge
	// its live values into the plan for fields the practitioner left unspecified,
	// so only intentionally-configured fields diverge from the live state.
	tflog.Debug(ctx, "Reading current instance to merge unspecified fields (full-replace edit)")
	current, err := r.client.GetIntegrationInstanceDetails(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Cloud Integration Instance Before Update",
			err.Error(),
		)
		return
	}
	plan.MergeFromRemote(ctx, &resp.Diagnostics, current)
	if resp.Diagnostics.HasError() {
		return
	}

	// scan_env_id is required and non-empty on edit_instance. The instance GET
	// does not surface it, so resolve it: prefer an explicitly-configured
	// outpost_id, otherwise look up the managed outpost whose cloud_provider
	// matches the instance via get_outposts.
	tflog.Debug(ctx, "Resolving scan_env_id (outpost) for edit")
	r.resolveScanEnvID(ctx, &resp.Diagnostics, &plan)
	if resp.Diagnostics.HasError() {
		return
	}

	// Generate the edit request payload from the merged plan.
	tflog.Debug(ctx, "Generating API request payload")
	editRequest := plan.ToEditRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply the in-place edit.
	tflog.Debug(ctx, "Executing edit API request")
	_, err = r.client.EditIntegrationInstance(ctx, editRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Cloud Integration Instance",
			err.Error(),
		)
		return
	}

	// Read the instance back to refresh computed fields (status,
	// security_capabilities, scan, etc.). The edit response does not return the
	// full instance representation, so a follow-up GET is required.
	tflog.Debug(ctx, "Executing read-back API request")
	data, err := r.client.GetIntegrationInstanceDetails(ctx, plan.ID.ValueString())
	if err != nil {
		// The edit already succeeded, so the platform has been mutated. Returning
		// without writing state would leave Terraform believing the pre-apply
		// values are live, and the next plan would propose changes that have in
		// fact already been applied. Persist the values that were just sent so
		// state reflects the mutation; the computed fields stay stale until the
		// next refresh, which the diagnostic tells the practitioner to run.
		tflog.Warn(ctx, "Read-back after a successful edit failed; persisting the applied plan to state")
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		resp.Diagnostics.AddError(
			"Error Reading Cloud Integration Instance After Update",
			"The edit was applied to the integration instance, but reading the "+
				"instance back to refresh Terraform state failed. State has "+
				"been updated with the values that were sent, so the edit is "+
				"not lost, but computed attributes may be stale. Run "+
				"`terraform refresh` (or the next `terraform plan`) to "+
				"reconcile. Underlying error: "+err.Error(),
		)
		return
	}

	// RefreshFromRemote only overwrites read fields; the write-only attributes
	// (cloud_partition, scope_modifications) are absent from the read type and
	// are therefore preserved from the plan on the model. additional_capabilities
	// is refreshed to the platform-reported value.
	tflog.Debug(ctx, "Refreshing configured attributes")
	plan.RefreshFromRemote(ctx, &resp.Diagnostics, data)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set updated state.
	tflog.Debug(ctx, "Setting updated state")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// resolveScanEnvID ensures the plan carries a non-empty outpost_id (serialized
// as scan_env_id) for the edit_instance request. edit_instance requires a
// non-empty scan_env_id, and the instance GET does not surface it. If the
// practitioner explicitly configured outpost_id it is honored as-is; otherwise
// the managed outpost whose cloud_provider matches the instance is looked up via
// get_outposts and its outpost_id is used.
func (r *CloudIntegrationInstanceResource) resolveScanEnvID(ctx context.Context, diags *diag.Diagnostics, plan *models.CloudIntegrationInstanceResourceModel) {
	// Prefer an explicitly-configured outpost_id.
	if !plan.OutpostID.IsNull() && !plan.OutpostID.IsUnknown() && plan.OutpostID.ValueString() != "" {
		tflog.Debug(ctx, "Using explicitly-configured outpost_id as scan_env_id")
		return
	}

	cloudProvider := plan.CloudProvider.ValueString()
	if cloudProvider == "" {
		diags.AddError(
			"Unable to Resolve scan_env_id",
			"cloud_provider is empty; it is required to look up the managed "+
				"outpost used as scan_env_id for the edit. Set cloud_provider "+
				"or configure outpost_id explicitly.",
		)
		return
	}

	tflog.Debug(ctx, "Looking up managed outpost via get_outposts")
	listReq := cloudOnboardingTypes.NewListOutpostsRequest(
		cloudOnboardingTypes.WithOutpostFilterData(filterTypes.FilterData{
			Filter: filterTypes.NewAndFilter(
				filterTypes.NewSearchFilter(
					enums.SearchFieldProvider.String(),
					enums.SearchTypeEqualTo.String(),
					cloudProvider,
				),
			),
			Paging: filterTypes.PagingFilter{From: 0, To: 1000},
		}),
	)

	outpostsResp, err := r.client.ListOutposts(ctx, &listReq)
	if err != nil {
		diags.AddError("Error Listing Outposts for scan_env_id", err.Error())
		return
	}
	if outpostsResp == nil {
		diags.AddError(
			"Error Listing Outposts for scan_env_id",
			"get_outposts returned a nil response.",
		)
		return
	}

	outpostID, err := selectManagedOutpostID(outpostsResp.Data, cloudProvider)
	if err != nil {
		diags.AddError("Unable to Resolve scan_env_id", err.Error())
		return
	}

	plan.OutpostID = types.StringValue(outpostID)
}

// selectManagedOutpostID returns the outpost_id of the managed outpost whose
// cloud_provider matches the given provider. It is a pure helper (no SDK calls)
// so the selection logic can be unit-tested. It errors when no matching managed
// outpost exists, and also when more than one matches: get_outposts result
// ordering is not a documented stability guarantee, so picking the first would
// make the resolved scan_env_id vary between runs and point a full-replace edit
// at a different outpost.
func selectManagedOutpostID(outposts []cloudOnboardingTypes.Outpost, cloudProvider string) (string, error) {
	var candidates []string
	for _, outpost := range outposts {
		if !strings.EqualFold(outpost.CloudProvider, cloudProvider) {
			continue
		}
		if !strings.EqualFold(outpost.Type, enums.ScanModeManaged.String()) {
			continue
		}
		if outpost.OutpostID == "" {
			continue
		}
		candidates = append(candidates, outpost.OutpostID)
	}

	switch len(candidates) {
	case 1:
		return candidates[0], nil
	case 0:
		return "", fmt.Errorf(
			"no managed outpost found for cloud_provider %q via get_outposts; "+
				"a managed outpost is required to derive scan_env_id, or configure "+
				"outpost_id explicitly", cloudProvider,
		)
	default:
		sort.Strings(candidates)
		return "", fmt.Errorf(
			"found %d managed outposts for cloud_provider %q via get_outposts "+
				"(%s); the one to use as scan_env_id is ambiguous, so set "+
				"outpost_id explicitly to choose",
			len(candidates), cloudProvider, strings.Join(candidates, ", "),
		)
	}
}

// Delete removes the resource from Terraform state only. It does NOT delete the
// underlying integration instance in Cortex Cloud, because this resource merely
// adopts an existing, connected instance. A warning is emitted so the user
// understands the connected integration continues to exist server-side.
func (r *CloudIntegrationInstanceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "cloud_integration_instance")
	ctx = tflog.SetField(ctx, "resource_id_field", "id")
	ctx = tflog.SetField(ctx, "resource_operation", "Delete")

	// Retrieve the ID from state so the warning can reference the specific
	// instance that remains connected.
	var state models.CloudIntegrationInstanceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "resource_id_value", state.ID.ValueString())

	tflog.Debug(ctx, "Removing resource from state without deleting server-side")
	addStateOnlyDeletionWarning(&resp.Diagnostics, state.ID.ValueString())
	resp.State.RemoveResource(ctx)
}

// addStateOnlyDeletionWarning appends the warning explaining that removing the
// resource from Terraform state does not delete the connected integration
// instance in Cortex Cloud. It is a standalone helper so the diagnostic can be
// unit-tested without a live API or a fully-constructed delete request.
func addStateOnlyDeletionWarning(diags *diag.Diagnostics, instanceID string) {
	diags.AddWarning(
		"Cloud Integration Instance Not Deleted from Cortex Cloud",
		fmt.Sprintf("Removing this resource only deletes it from the Terraform "+
			"state; the connected cloud integration instance with ID \"%s\" "+
			"continues to exist in Cortex Cloud and will keep collecting data "+
			"and scanning. To fully remove the integration, delete it in the "+
			"Cortex Cloud console under Settings > Data Sources.", instanceID),
	)
}

// ImportState adopts an existing connected instance into Terraform by its
// instance ID, triggering a Read to populate state.
func (r *CloudIntegrationInstanceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
