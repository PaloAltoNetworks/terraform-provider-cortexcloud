// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"fmt"
	"strings"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/cloudonboarding"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	cloudOnboardingTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"

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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &CloudManualIntegrationInstanceResource{}
	_ resource.ResourceWithImportState = &CloudManualIntegrationInstanceResource{}
)

// manualProvisioningMethod is what the platform reports for a connector that
// was onboarded manually, and so the only provisioning method this resource
// manages. Observed on every manually onboarded connector in the captured live
// listings; template-provisioned connectors report CF, ARM or TF instead.
const manualProvisioningMethod = "MANUAL"

// manualOnboardingFeatureName names this capability in diagnostics.
const manualOnboardingFeatureName = "manual cloud onboarding"

// manualInstanceSupportedCloudProviders is the set of cloud providers manual
// onboarding supports.
//
// This is intentionally narrower than enums.AllCloudProviders(). The platform
// supports GCP for template-driven onboarding, but not for manual onboarding,
// so the shared enum overstates what this resource can do.
var manualInstanceSupportedCloudProviders = []string{
	enums.CloudProviderAWS.String(),
	enums.CloudProviderAzure.String(),
}

// manualInstanceUnsupportedCloudProviders is the set of cloud providers the
// platform knows but manual onboarding does not accept. Naming them lets the
// diagnostic distinguish an unsupported capability from a misspelling.
var manualInstanceUnsupportedCloudProviders = []string{
	enums.CloudProviderGCP.String(),
}

// The automation log levels the platform accepts are OFF, Debug and Verbose,
// in that casing. There is deliberately no enumeration of them in code: the
// platform validates the value itself and names the alternatives in its own
// error,
//
//	422 literal_error "Input should be 'OFF', 'Debug' or 'Verbose'"
//
// so a copy here would only restate a rule we do not own. Measured against
// the live API 2026-09-10, including every case variant a practitioner is
// likely to reach for - "Off", "off" and "DEBUG" are each refused.
//
// The mixed casing is the platform's, not a transcription error, and the
// console displays the disabled state as "Off" while the API accepts only
// "OFF". That trap is carried in the attribute's description, where it
// reaches the practitioner as guidance rather than as a refusal.

// NewCloudManualIntegrationInstanceResource is a helper function to simplify
// the provider implementation.
func NewCloudManualIntegrationInstanceResource() resource.Resource {
	return &CloudManualIntegrationInstanceResource{}
}

// CloudManualIntegrationInstanceResource is the resource implementation for a
// manually onboarded cloud connector.
//
// This is a separate resource type from cloud_integration_instance, which
// manages connectors provisioned from a template. The two use different write
// endpoints whose schemas are disjoint: each rejects the fields the other
// requires, so a manual connector cannot be managed through the template
// resource.
type CloudManualIntegrationInstanceResource struct {
	client *cloudonboarding.Client
}

// Metadata returns the resource type name.
func (r *CloudManualIntegrationInstanceResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_manual_integration_instance"
}

// Schema defines the schema for the resource.
func (r *CloudManualIntegrationInstanceResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a manually onboarded cloud connector instance. " +
			"Use this resource when the cloud-side identities are created " +
			"outside Cortex Cloud and supplied to it, rather than deployed " +
			"from a Cortex Cloud template.\n\n" +
			"Manual onboarding is behind a feature flag. Contact Palo Alto " +
			"Networks support to have it enabled on your tenant before using " +
			"this resource.\n\n" +
			"Importing a connector does not recover \"manual_details\". The " +
			"platform reports the cloud-side identities in a different shape " +
			"from the one it accepts, and never reports \"cloudtrail_role\", " +
			"\"sqs_url\" or \"subscription_id\" at all, so the first plan " +
			"after an import is not empty.",
		MarkdownDescription: "Manages a manually onboarded cloud connector instance. " +
			"Use this resource when the cloud-side identities are created " +
			"outside Cortex Cloud and supplied to it, rather than deployed " +
			"from a Cortex Cloud template.\n\n" +
			"~> **Manual onboarding is behind a feature flag.** Contact Palo " +
			"Alto Networks support to have it enabled on your tenant before " +
			"using this resource.\n\n" +
			"~> **Importing a connector does not recover `manual_details`.** " +
			"The platform reports the cloud-side identities in a different " +
			"shape from the one it accepts, and never reports " +
			"`cloudtrail_role`, `sqs_url` or `subscription_id` at all. You " +
			"must re-declare `manual_details` after importing, and the first " +
			"plan after an import is not empty.\n\n" +
			"### Which `manual_details` fields apply to which cloud\n\n" +
			"Every field below is also labelled `(AWS)`, `(Azure)` or " +
			"`(AWS and Azure)` in its own description, because the attribute " +
			"list is sorted alphabetically rather than grouped by cloud.\n\n" +
			"| | AWS | Azure |\n" +
			"|---|---|---|\n" +
			"| **Identity** | `role_arn`, `external_id`, `organization_id` | " +
			"`tenant_id`, `subscription_id` |\n" +
			"| **Audit logs** | `cloudtrail_role`, `sqs_url` | `eventhub_name`, " +
			"`eventhub_namespace`, `eventhub_resource_group_name`, " +
			"`eventhub_audit_client_id`, " +
			"`azure_audit_eventhub_consumer_group_name`, " +
			"`storage_account_name` |\n" +
			"| **Deployment** | `outpost_scanner_role_arn` | " +
			"`resource_group_name`, `resource_group_location`, " +
			"`ads_image_gallery_resource_id` |\n" +
			"| **Both clouds** | `account_id`, `account_name` | |\n\n" +
			"These values are produced by the cloud-side deployment. The " +
			"Cortex Cloud API returns them from its manual connector " +
			"identifiers call, so take them from there rather than " +
			"assembling them by hand.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:         "The unique ID assigned to the connector on creation.",
				MarkdownDescription: "The unique ID assigned to the connector on creation.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cloud_provider": schema.StringAttribute{
				Description: "The cloud provider the connector onboards. " +
					"Manual onboarding supports AWS and AZURE only; GCP is not " +
					"supported. " +
					"Changing this value forces the connector to be replaced: " +
					"the platform refuses an edit that carries a different " +
					"cloud provider from the one used at creation.",
				MarkdownDescription: "The cloud provider the connector onboards. " +
					"Manual onboarding supports `AWS` and `AZURE` only; `GCP` is " +
					"not supported. " +
					"Changing this value forces the connector to be replaced: " +
					"the platform refuses an edit that carries a different " +
					"cloud provider from the one used at creation.",
				Required: true,
				// Deliberately not enums.AllCloudProviders(): that set is the
				// platform's and is shared with the automated onboarding
				// resources, which do support GCP. Manual onboarding is a
				// narrower capability, so it carries its own list. Widening the
				// shared enum would silently re-admit GCP here.
				Validators: []validator.String{
					validators.CloudProviderIsSupported(
						manualOnboardingFeatureName,
						manualInstanceSupportedCloudProviders,
						manualInstanceUnsupportedCloudProviders,
					),
				},
				// Measured, not assumed: an edit resending the connector's own
				// cloud provider succeeds, and an edit carrying a different one
				// is rejected. Without this modifier Terraform would produce a
				// plan that can never apply.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"scope": schema.StringAttribute{
				Description: "The scope of the connector. Changing this value " +
					"forces the connector to be replaced, as the platform " +
					"documents the scope as fixed at creation.",
				MarkdownDescription: "The scope of the connector. Changing this value " +
					"forces the connector to be replaced, as the platform " +
					"documents the scope as fixed at creation.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(enums.AllScopes()...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"scan_mode": schema.StringAttribute{
				Description: "How the connector's workloads are scanned. " +
					"Changing this value forces the connector to be replaced, " +
					"as the platform documents the scan mode as fixed at " +
					"creation. \"OUTPOST\" additionally requires \"outpost_id\".",
				MarkdownDescription: "How the connector's workloads are scanned. " +
					"Changing this value forces the connector to be replaced, " +
					"as the platform documents the scan mode as fixed at " +
					"creation. `OUTPOST` additionally requires `outpost_id`.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(enums.AllScanModes()...),
					validators.AlsoRequiresOnStringValues(
						[]string{enums.ScanModeOutpost.String()},
						path.MatchRoot("outpost_id"),
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"outpost_id": schema.StringAttribute{
				Description:         "The outpost that scans this connector. Required when \"scan_mode\" is \"OUTPOST\".",
				MarkdownDescription: "The outpost that scans this connector. Required when `scan_mode` is `OUTPOST`.",
				Optional:            true,
			},
			"instance_name": schema.StringAttribute{
				Description: "The display name of the connector. When omitted, " +
					"the platform assigns one and it is recorded in state.",
				MarkdownDescription: "The display name of the connector. When omitted, " +
					"the platform assigns one and it is recorded in state.",
				Optional: true,
				Computed: true,
			},
			"cloud_partition": schema.StringAttribute{
				Description: "The partition of the cloud provider the connector " +
					"onboards. When omitted, the platform applies its own " +
					"default and it is recorded in state.",
				MarkdownDescription: "The partition of the cloud provider the connector " +
					"onboards. When omitted, the platform applies its own " +
					"default and it is recorded in state.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"manual_details": schema.SingleNestedAttribute{
				Description: "The cloud-side identities of the connector. Which " +
					"members apply depends on \"cloud_provider\", \"scope\" and " +
					"whether audit-log collection is enabled; supply only the " +
					"members your configuration is offered.",
				MarkdownDescription: "The cloud-side identities of the connector. Which " +
					"members apply depends on `cloud_provider`, `scope` and " +
					"whether audit-log collection is enabled; supply only the " +
					"members your configuration is offered.",
				Required:   true,
				Attributes: manualDetailsWriteAttributes(),
			},
			// Every attribute below that is both Optional and Computed carries
			// UseStateForUnknown.
			//
			// Without it Terraform marks the attribute unknown on every plan,
			// because it cannot know whether the platform will choose a
			// different default this time. The plan then reads
			// "false -> (known after apply)" for values the connector already
			// holds and no apply ever settles it -- the classic perpetual diff,
			// observed live on the first successful apply of this resource.
			//
			// Reusing the prior state is correct here because these values only
			// change when something changes them: the practitioner edits the
			// configuration, in which case the configured value wins over this
			// modifier, or the connector is changed outside Terraform, which is
			// what the refresh before each plan exists to detect.
			"reported_manual_details": schema.SingleNestedAttribute{
				Description: "The cloud-side identities as the platform reports " +
					"them, refreshed on every read. Terraform populates this " +
					"attribute -- nothing outside Terraform is needed to obtain " +
					"it.\n\n" +
					"It is separate from \"manual_details\" because the " +
					"platform's read and write shapes differ by four members. " +
					"\"client_id\" (Azure) is reported here and refused on " +
					"write, so this attribute is the only way to obtain it. " +
					"\"cloudtrail_role\", \"sqs_url\" and \"subscription_id\" " +
					"are accepted on write but never reported, so they appear " +
					"in \"manual_details\" only. The remaining members appear " +
					"in both. This attribute is never sent back to the platform.",
				MarkdownDescription: "The cloud-side identities as the platform reports " +
					"them, refreshed on every read. Terraform populates this " +
					"attribute -- nothing outside Terraform is needed to obtain " +
					"it.\n\n" +
					"It is separate from `manual_details` because the platform's " +
					"read and write shapes differ by four members:\n\n" +
					"- `client_id` (Azure) is reported here and **refused on " +
					"write**, so this attribute is the only way to obtain it.\n" +
					"- `cloudtrail_role`, `sqs_url` and `subscription_id` are " +
					"accepted on write but **never reported**, so they appear " +
					"in `manual_details` only.\n\n" +
					"The remaining members appear in both. This attribute is " +
					"never sent back to the platform.",
				Computed:      true,
				Attributes:    manualDetailsReadAttributes(),
				PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
			},
			// Required by the API contract. Nothing was invented here before:
			// {} and registry_scanning = false were measured to store
			// byte-identical capabilities. registry_scanning below is Required
			// so the object cannot be satisfied by an empty block.
			"additional_capabilities": schema.SingleNestedAttribute{
				Description: "The security capabilities to enable on the connector. " +
					"Toggles left unset are disabled by the platform and recorded in state.",
				MarkdownDescription: "The security capabilities to enable on the connector. " +
					"Toggles left unset are disabled by the platform and recorded in state.",
				Required: true,
				Attributes: map[string]schema.Attribute{
					// Not paired with automation_log_level here: the platform
					// enforces it and its message is clearer than ours would
					// be. The rule is truthiness, not presence -- automation =
					// false with a level set is still refused.
					"automation": schema.BoolAttribute{
						Description:   "Whether to enable automation.",
						Optional:      true,
						Computed:      true,
						PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
					},
					// Values documented, not validated: the platform names the
					// legal set in its own error. The OFF/Off note stays in the
					// description because the console shows "Off" and the API
					// takes "OFF".
					"automation_log_level": schema.StringAttribute{
						Description: "How much detail automation logs: " +
							"OFF, Debug or Verbose. Note that the console " +
							"displays this setting as \"Off\", which is not " +
							"the value the API accepts: the API takes \"OFF\".",
						MarkdownDescription: "How much detail automation logs: " +
							"`OFF`, `Debug` or `Verbose`. Note that the console " +
							"displays this setting as `Off`, which is **not** " +
							"the value the API accepts: the API takes `OFF`.",
						Optional:      true,
						Computed:      true,
						PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
					},
					"xsiam_analytics": schema.BoolAttribute{
						Description:   "Whether to enable analytics over the connector's data.",
						Optional:      true,
						Computed:      true,
						PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
					},
					// Pairing with registry_scanning_options is left to the
					// platform, same as automation above.
					//
					// Required so additional_capabilities cannot be satisfied
					// by an empty block; false alone is accepted, so opting out
					// costs one line.
					"registry_scanning": schema.BoolAttribute{
						Description: "Whether to enable container registry scanning. " +
							"Enabling it also requires registry_scanning_options.",
						MarkdownDescription: "Whether to enable container registry scanning. " +
							"Enabling it also requires `registry_scanning_options`.",
						Required: true,
					},
					"registry_scanning_options": schema.SingleNestedAttribute{
						Description:   "The scope of container registry scanning.",
						Optional:      true,
						Computed:      true,
						PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
						Attributes: map[string]schema.Attribute{
							// Required because the field has no omitempty: an
							// omitted type goes on the wire as "". Values are
							// documented, not enforced -- the platform accepts
							// unrecognised ones, so the description must not
							// promise otherwise.
							"type": schema.StringAttribute{
								Description: "Which images to scan: " +
									"ALL, LATEST_TAG or TAGS_MODIFIED_DAYS.",
								MarkdownDescription: "Which images to scan: " +
									"`ALL`, `LATEST_TAG` or `TAGS_MODIFIED_DAYS`.",
								Required: true,
							},
							// Not tied to a type and not range-checked: the
							// platform enforces neither, so we would be
							// inventing both.
							"last_days": schema.Int64Attribute{
								Description:   "How many days back to scan, when the type restricts scanning by age.",
								Optional:      true,
								Computed:      true,
								PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
							},
						},
					},
					"kubernetes_security": schema.BoolAttribute{
						Description:   "Whether to enable Kubernetes security.",
						Optional:      true,
						Computed:      true,
						PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
					},
					"serverless_scanning": schema.BoolAttribute{
						Description:   "Whether to enable serverless function scanning.",
						Optional:      true,
						Computed:      true,
						PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
					},
					"agentless_disk_scanning": schema.BoolAttribute{
						Description:   "Whether to enable agentless disk scanning.",
						Optional:      true,
						Computed:      true,
						PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
					},
					"data_security_posture_management": schema.BoolAttribute{
						Description:   "Whether to enable data security posture management.",
						Optional:      true,
						Computed:      true,
						PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
					},
					"upload_files_to_wildfire": schema.BoolAttribute{
						Description:   "Whether to upload files to WildFire for analysis.",
						Optional:      true,
						Computed:      true,
						PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
					},
				},
			},
			// Required by the API contract, even where the platform currently
			// accepts members missing: coding to today's leniency would break
			// practitioners when its validator is finished.
			//
			// Required and Computed are mutually exclusive, so the flip drops
			// Computed and UseStateForUnknown here -- nothing is unknown at
			// plan time once the practitioner supplies every value.
			"collection_configuration": schema.SingleNestedAttribute{
				Description:         "Audit-log collection configuration.",
				MarkdownDescription: "Audit-log collection configuration.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"audit_logs": schema.SingleNestedAttribute{
						Description:         "Configuration for audit-log collection.",
						MarkdownDescription: "Configuration for audit-log collection.",
						Required:            true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "(AWS and Azure) Whether audit-log collection is enabled.",
								Required:    true,
							},
							// Absent and false are different connectors, not
							// the same one: the platform stores a missing field
							// as absent. Required, so the practitioner picks.
							"data_events": schema.BoolAttribute{
								Description: "(AWS and Azure) Whether data events are " +
									"collected alongside audit logs.",
								Required: true,
							},
							// CUSTOM is the only documented value, but the
							// platform owns the enum: a OneOf here would keep
							// rejecting values after it starts accepting them.
							"collection_method": schema.StringAttribute{
								Description: "(AWS and Azure) How audit logs are collected. " +
									"The only value the API documents is CUSTOM.",
								MarkdownDescription: "(AWS and Azure) How audit logs are collected. " +
									"The only value the API documents is `CUSTOM`.",
								Required: true,
							},
							// The Computed members below keep
							// UseStateForUnknown: without it a platform-supplied
							// value re-plans as "(known after apply)" forever,
							// so an unchanged configuration never plans clean.
							// Observed live on is_control_tower_byob.
							"is_control_tower_byob": schema.BoolAttribute{
								Description:         "(AWS) Whether the audit-log bucket is a Control Tower bring-your-own bucket.",
								MarkdownDescription: "(AWS) Whether the audit-log bucket is a Control Tower bring-your-own bucket.",
								Optional:            true,
								Computed:            true,
								PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
							},
							// cloudtrail_role and sqs_url are deliberately NOT
							// offered here. The platform refuses both inside
							// audit_logs with "extra_forbidden", so every apply
							// of a configuration that set them failed. Both
							// belong in manual_details, where the same values
							// onboard a connector successfully.
						},
					},
				},
			},
			// Required for the same contract reason as
			// collection_configuration, plus one more: while it was optional
			// the provider invented a region scope on silence, because the
			// platform refuses a write without regions. That substitution was
			// invisible in the plan and impossible to opt out of.
			"scope_modifications": schema.SingleNestedAttribute{
				Description: "Restrictions on what the connector covers. " +
					"Region scope is always stated explicitly.",
				MarkdownDescription: "Restrictions on what the connector covers. " +
					"Region scope is always stated explicitly.",
				Required: true,
				Attributes: map[string]schema.Attribute{
					"accounts": schema.SingleNestedAttribute{
						Description: "Restriction by account.",
						Optional:    true,
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether the account restriction applies.",
								Required:    true,
							},
							"type": schema.StringAttribute{
								Description: "Whether the listed accounts are included or excluded.",
								Optional:    true,
							},
							"account_ids": schema.ListAttribute{
								Description: "The accounts the restriction applies to.",
								ElementType: types.StringType,
								Optional:    true,
							},
						},
					},
					"projects": schema.SingleNestedAttribute{
						Description: "Restriction by project.",
						Optional:    true,
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether the project restriction applies.",
								Required:    true,
							},
							"type": schema.StringAttribute{
								Description: "Whether the listed projects are included or excluded.",
								Optional:    true,
							},
							"project_ids": schema.ListAttribute{
								Description: "The projects the restriction applies to.",
								ElementType: types.StringType,
								Optional:    true,
							},
						},
					},
					"subscriptions": schema.SingleNestedAttribute{
						Description: "Restriction by subscription.",
						Optional:    true,
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether the subscription restriction applies.",
								Required:    true,
							},
							"type": schema.StringAttribute{
								Description: "Whether the listed subscriptions are included or excluded.",
								Optional:    true,
							},
							"subscription_ids": schema.ListAttribute{
								Description: "The subscriptions the restriction applies to.",
								ElementType: types.StringType,
								Optional:    true,
							},
						},
					},
					// Required, unlike its siblings: the platform refuses any
					// write that omits it.
					"regions": schema.SingleNestedAttribute{
						Description: "Restriction by region. " +
							"Set enabled to false to leave every region in scope.",
						MarkdownDescription: "Restriction by region. " +
							"Set `enabled` to `false` to leave every region in scope.",
						Required: true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether the region restriction applies.",
								Required:    true,
							},
							"type": schema.StringAttribute{
								Description: "Whether the listed regions are included or excluded.",
								Optional:    true,
							},
							"regions": schema.ListAttribute{
								Description: "The regions the restriction applies to.",
								ElementType: types.StringType,
								Optional:    true,
							},
						},
					},
				},
			},
			"custom_resources_tags": schema.SetNestedAttribute{
				Description: "Tags applied to the cloud resources Cortex Cloud " +
					"creates for this connector. Omitting the attribute leaves " +
					"the connector's existing tags untouched, so tags cannot be " +
					"cleared by removing the attribute from the configuration. " +
					"Declaring the attribute replaces the stored list in full: " +
					"dropping one entry from a list that is still declared does " +
					"remove that tag. Cortex Cloud also adds a managed_by tag of " +
					"its own when it creates a connector; that tag is not " +
					"recorded in Terraform state, and an update that declares " +
					"this attribute replaces it along with the rest.",
				MarkdownDescription: "Tags applied to the cloud resources Cortex Cloud " +
					"creates for this connector. Omitting the attribute leaves " +
					"the connector's existing tags untouched, so tags cannot be " +
					"cleared by removing the attribute from the configuration. " +
					"Declaring the attribute replaces the stored list in full: " +
					"dropping one entry from a list that is still declared does " +
					"remove that tag. Cortex Cloud also adds a `managed_by` tag " +
					"of its own when it creates a connector; that tag is not " +
					"recorded in Terraform state, and an update that declares " +
					"this attribute replaces it along with the rest.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()},
				Validators: []validator.Set{
					// [] is refused for what it does, not because the endpoint
					// rejects it: edit_manual_instance accepts it with HTTP 200
					// and clears the tags, after which the field reads back as
					// {} -- a shape no configuration can produce deliberately.
					//
					// Not the sibling resource's reasoning: that endpoint does
					// answer [] with HTTP 500. Easy to conflate.
					setvalidator.SizeAtLeast(1),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"key": schema.StringAttribute{
							Description: "The tag key.",
							Required:    true,
						},
						"value": schema.StringAttribute{
							Description: "The tag value.",
							Required:    true,
						},
					},
				},
			},
		},
	}
}

// manualDetailsWriteAttributes declares the members the manual write endpoints
// accept.
//
// client_id is deliberately absent: every captured create that sent it was
// refused, so offering it here would let a practitioner write a configuration
// that cannot apply. It is reported through reported_manual_details instead.
func manualDetailsWriteAttributes() map[string]schema.Attribute {
	attributes := map[string]schema.Attribute{
		// AWS.
		// Fixed at creation by the platform, and refused on update by
		// assertImmutableFieldsUnchanged rather than by RequiresReplace: a
		// mistyped account should be reported, not answered by destroying a
		// live connector. Saying so here is what puts it in the generated
		// documentation, so a practitioner learns the rule before an apply
		// fails rather than after.
		"account_id": schema.StringAttribute{
			Description: "(AWS and Azure) The account the connector onboards. " +
				"Fixed when the connector is created: changing it is refused, " +
				"and the connector has to be replaced instead.",
			Optional: true,
		},
		"account_name": schema.StringAttribute{
			Description: "(AWS and Azure) The display name of the onboarded " +
				"account. Azure refuses an empty string on update.",
			Optional: true,
		},
		"organization_id": schema.StringAttribute{
			Description: "(AWS) The organization the onboarded account belongs to.",
			Optional:    true,
		},
		"role_arn": schema.StringAttribute{
			Description: "(AWS) The role Cortex Cloud assumes.",
			Optional:    true,
		},
		// Sensitive because this is the one member of the block that is a
		// shared secret rather than an identifier: in the AWS cross-account
		// model the external ID is what prevents the confused-deputy attack
		// against the assumable role. The ARNs, queue URLs and account,
		// subscription and tenant identifiers around it are published values
		// and are deliberately left unmarked, so plans stay readable.
		"external_id": schema.StringAttribute{
			Description: "(AWS) The external ID that guards the assumed role.",
			Optional:    true,
			Sensitive:   true,
		},
		"outpost_scanner_role_arn": schema.StringAttribute{
			Description: "(AWS) The role the outpost scanner assumes.",
			Optional:    true,
		},
		"cloudtrail_role": schema.StringAttribute{
			Description: "(AWS) The role Cortex Cloud assumes to read CloudTrail. " +
				"Write-only: the platform accepts this value but never reports " +
				"it back, so it cannot be recovered by an import.",
			MarkdownDescription: "(AWS) The role Cortex Cloud assumes to read CloudTrail. " +
				"Write-only: the platform accepts this value but never reports " +
				"it back, so it cannot be recovered by an import.",
			Optional: true,
		},
		"sqs_url": schema.StringAttribute{
			Description: "(AWS) The SQS queue CloudTrail notifications are read from. " +
				"Write-only: the platform accepts this value but never reports " +
				"it back, so it cannot be recovered by an import.",
			MarkdownDescription: "(AWS) The SQS queue CloudTrail notifications are read from. " +
				"Write-only: the platform accepts this value but never reports " +
				"it back, so it cannot be recovered by an import.",
			Optional: true,
		},

		// GCP is not supported for manual onboarding, so the GCP-only
		// members (service_account_email, outpost_scanner_service_account_email,
		// audit_service_account_email, audit_pubsub_subscription_id and
		// account_group) are deliberately absent. Declaring them would document
		// a set of fields no accepted cloud_provider value can use.

		// Azure.
		"subscription_id": schema.StringAttribute{
			Description: "(Azure) The subscription the connector onboards. " +
				"Write-only: the platform accepts this value but never reports " +
				"it back, so it cannot be recovered by an import.",
			MarkdownDescription: "(Azure) The subscription the connector onboards. " +
				"Write-only: the platform accepts this value but never reports " +
				"it back, so it cannot be recovered by an import.",
			Optional: true,
		},
	}

	for name, attribute := range manualDetailsSharedAzureAttributes() {
		attributes[name] = attribute
	}

	return attributes
}

// manualDetailsReadAttributes declares the members the platform reports.
//
// It is not the write set. cloudtrail_role, sqs_url and subscription_id are
// absent because they are accepted on write and never reported; client_id is
// present because it is reported and refused on write.
func manualDetailsReadAttributes() map[string]schema.Attribute {
	attributes := map[string]schema.Attribute{
		// AWS.
		"account_id": schema.StringAttribute{
			Description: "(AWS and Azure) The account the connector onboards.",
			Computed:    true,
		},
		"account_name": schema.StringAttribute{
			Description: "(AWS and Azure) The display name of the onboarded account.",
			Computed:    true,
		},
		"organization_id": schema.StringAttribute{
			Description: "(AWS) The organization the onboarded account belongs to.",
			Computed:    true,
		},
		"role_arn": schema.StringAttribute{
			Description: "(AWS) The role Cortex Cloud assumes.",
			Computed:    true,
		},
		// Sensitive for the same reason as its counterpart in the write block:
		// the value is a secret wherever it appears, and the platform reports
		// it back here on every refresh.
		"external_id": schema.StringAttribute{
			Description: "(AWS) The external ID that guards the assumed role.",
			Computed:    true,
			Sensitive:   true,
		},
		"outpost_scanner_role_arn": schema.StringAttribute{
			Description: "(AWS) The role the outpost scanner assumes.",
			Computed:    true,
		},

		// GCP-only members are absent here for the same reason as in the
		// write block: manual onboarding does not support GCP.

		// Azure.
		"client_id": schema.StringAttribute{
			Description: "(Azure) The application Cortex Cloud authenticates as. " +
				"Read-only: the platform reports this value and refuses it on " +
				"write, so this attribute is the only way to obtain it.",
			MarkdownDescription: "(Azure) The application Cortex Cloud authenticates as. " +
				"Read-only: the platform reports this value and refuses it on " +
				"write, so this attribute is the only way to obtain it.",
			Computed: true,
		},
	}

	for name, attribute := range manualDetailsSharedAzureAttributes() {
		stringAttribute := attribute
		stringAttribute.Optional = false
		stringAttribute.Computed = true
		attributes[name] = stringAttribute
	}

	return attributes
}

// manualDetailsSharedAzureAttributes declares the Azure members that appear on
// both the write and the read side, as optional write attributes. The read set
// re-marks them computed.
func manualDetailsSharedAzureAttributes() map[string]schema.StringAttribute {
	return map[string]schema.StringAttribute{
		"tenant_id": {
			Description: "(Azure) The tenant the connector onboards.",
			Optional:    true,
		},
		"resource_group_name": {
			Description: "(Azure) The resource group Cortex Cloud deploys into.",
			Optional:    true,
		},
		"resource_group_location": {
			Description: "(Azure) The location of the resource group.",
			Optional:    true,
		},
		"ads_image_gallery_resource_id": {
			Description: "(Azure) The compute gallery used by agentless disk scanning.",
			Optional:    true,
		},
		"eventhub_name": {
			Description: "(Azure) The Event Hub audit logs are read from.",
			Optional:    true,
		},
		"eventhub_resource_group_name": {
			Description: "(Azure) The resource group of the audit-log Event Hub.",
			Optional:    true,
		},
		"eventhub_namespace": {
			Description: "(Azure) The namespace of the audit-log Event Hub.",
			Optional:    true,
		},
		"azure_audit_eventhub_consumer_group_name": {
			Description: "(Azure) The consumer group used to read the audit-log Event Hub.",
			Optional:    true,
		},
		"storage_account_name": {
			Description: "(Azure) The storage account used to checkpoint audit-log collection.",
			Optional:    true,
		},
		"eventhub_audit_client_id": {
			Description: "(Azure) The identity used to read the audit-log Event Hub.",
			Optional:    true,
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *CloudManualIntegrationInstanceResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	ctx = tflog.SetField(ctx, "resource_type", "cloud_manual_integration_instance")
	ctx = tflog.SetField(ctx, "resource_operation", "Configure")
	tflog.Debug(ctx, "Configuring SDK client")

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedResourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	r.client = client.CloudOnboarding
}

// Create onboards a new manual connector and records the identifier the
// platform assigns to it.
//
// The payload is the complete desired configuration, built field by field from
// the plan. Nothing read back from the platform is ever folded into it: the
// read shape carries members the write endpoint refuses, so an echo would
// produce a request that cannot be accepted.
//
// No cleanup is attempted on failure: the platform no longer leaves a record
// behind, and a cleanup step would mean deleting a resource whose identifier
// was never returned.
func (r *CloudManualIntegrationInstanceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "cloud_manual_integration_instance")
	ctx = tflog.SetField(ctx, "resource_operation", "Create")

	tflog.Debug(ctx, "Retrieving values from plan")
	var plan models.CloudManualIntegrationInstanceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest := plan.ToCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Executing API request")
	created, err := r.client.CreateManualInstance(ctx, createRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Manual Cloud Integration Instance",
			"The request to onboard the connector failed:\n\n"+
				util.FormatAPIError(err)+"\n\n"+
				"Manual onboarding is behind a feature flag. If the message "+
				"above does not name something in your configuration, check "+
				"that the feature is enabled on your tenant.",
		)
		return
	}

	if created.ID == "" {
		resp.Diagnostics.AddError(
			"Error Creating Manual Cloud Integration Instance",
			"The platform accepted the onboarding request but returned no "+
				"connector ID, so Terraform cannot manage the result. A "+
				"connector may exist; check the Cortex Cloud console before "+
				"retrying.",
		)
		return
	}

	ctx = tflog.SetField(ctx, "resource_id_value", created.ID)
	tflog.Debug(ctx, "Connector created")

	plan.ID = types.StringValue(created.ID)

	// Read the connector back before recording it.
	//
	// The create reply carries nothing but the identifier, so every Computed
	// attribute is still unknown at this point. Terraform requires all of them
	// to be known once the apply returns and fails the whole operation with
	// "Provider returned invalid result object after apply" otherwise -- after
	// the connector has already been created, which leaves a live connector
	// with no state tracking it. Only the platform can supply those values,
	// because it is the platform that defaults them.
	r.refreshAfterWrite(ctx, &resp.Diagnostics, &plan, "Creating")
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// refreshAfterWrite reads the connector back and folds the reply into the
// model, so that state records what the platform holds rather than what was
// asked for.
//
// Both writes need this and for the same reason: neither the create nor the
// edit reply carries the connector's configuration, so without a read-back the
// Computed attributes are left unknown by a create and stale by an edit.
//
// A failure here is reported as an error rather than ignored. The write itself
// has already happened, so the connector exists either way, and reporting the
// failure is what tells the practitioner that state may not describe it.
func (r *CloudManualIntegrationInstanceResource) refreshAfterWrite(
	ctx context.Context,
	diagnostics *diag.Diagnostics,
	model *models.CloudManualIntegrationInstanceModel,
	operation string,
) {
	instanceID := model.ID.ValueString()

	readRequest := model.ToReadRequest(ctx, diagnostics)
	if diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading the connector back after the write")
	details, err := r.client.GetEditInstanceDetails(ctx, readRequest)
	if err != nil {
		diagnostics.AddError(
			fmt.Sprintf("Error %s Manual Cloud Integration Instance", operation),
			fmt.Sprintf("The write succeeded, but connector %s could not be "+
				"read back to record what the platform now holds:\n\n%s\n\n"+
				"The connector exists. Run \"terraform plan\" to reconcile "+
				"Terraform state with it.", instanceID, util.FormatAPIError(err)),
		)
		return
	}

	model.RefreshFromReadResponse(ctx, diagnostics, details.Fields)
}

// Read refreshes state from the platform.
//
// Two properties of the read endpoint shape this method.
//
// First, its reply is not the write shape, so it is never folded back into
// manual_details. What the platform reports goes to reported_manual_details;
// the configured values stay as the practitioner wrote them.
//
// Second, a successful reply is not proof that the requested connector exists.
// The endpoint has been observed answering 200 with a payload belonging to a
// different connector, and the payload carries no identifier to check that
// against. Only the platform's explicit "doesn't exist" rejection is treated as
// absence; every other failure is surfaced as an error. Removing a resource on
// an ambiguous reply would destroy a live connector on the next apply, which is
// the worse of the two failures.
func (r *CloudManualIntegrationInstanceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "cloud_manual_integration_instance")
	ctx = tflog.SetField(ctx, "resource_id_field", "id")
	ctx = tflog.SetField(ctx, "resource_operation", "Read")

	tflog.Debug(ctx, "Retrieving values from state")
	var state models.CloudManualIntegrationInstanceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	instanceID := state.ID.ValueString()
	ctx = tflog.SetField(ctx, "resource_id_value", instanceID)

	readRequest := state.ToReadRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Confirming the connector still exists")
	listed, err := r.connectorIsListed(ctx, &state, instanceID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Manual Cloud Integration Instance",
			fmt.Sprintf("Could not confirm that connector %s still exists:\n\n%s\n\n"+
				"The connector is being kept in Terraform state: a check that "+
				"could not be completed is not evidence that the connector is "+
				"gone, and removing it here would make the next apply rebuild "+
				"infrastructure that may still be running.",
				instanceID, util.FormatAPIError(err)),
		)
		return
	}
	if !listed {
		tflog.Debug(ctx, "Connector absent from the listing, removing from state")
		resp.Diagnostics.AddWarning(
			"Manual Cloud Integration Instance Not Found",
			fmt.Sprintf("Connector %s is no longer present on the platform. It "+
				"has been removed from Terraform state, so the next plan will "+
				"offer to create it again.", instanceID),
		)
		resp.State.RemoveResource(ctx)
		return
	}

	tflog.Debug(ctx, "Executing API request")
	details, err := r.client.GetEditInstanceDetails(ctx, readRequest)
	if err != nil {
		if isConnectorGoneError(err, instanceID) {
			tflog.Debug(ctx, "Connector reported as non-existent, removing from state")
			resp.Diagnostics.AddWarning(
				"Manual Cloud Integration Instance Not Found",
				fmt.Sprintf("The platform reports that connector %s no longer "+
					"exists. It has been removed from Terraform state.", instanceID),
			)
			resp.State.RemoveResource(ctx)
			return
		}

		resp.Diagnostics.AddError(
			"Error Reading Manual Cloud Integration Instance",
			fmt.Sprintf("Could not read connector %s:\n\n%s", instanceID, util.FormatAPIError(err)),
		)
		return
	}

	if assertConnectorWasProvisionedManually(&resp.Diagnostics, instanceID, details.Fields.ProvisioningMethod); resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Refreshing state")
	state.RefreshFromReadResponse(ctx, &resp.Diagnostics, details.Fields)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// assertConnectorWasProvisionedManually refuses a connector this resource does
// not own.
//
// Both connector resources take a bare identifier on import, and the names are
// similar, so importing into the wrong one is an ordinary mistake. It is not a
// harmless one in this direction: this resource's Delete really does remove the
// connector, so a practitioner who imports a template-provisioned connector
// here and later runs "terraform destroy" deletes something a template still
// believes it owns -- and that template's own Delete is state-only, so nothing
// else notices. Refusing at read time is the last point where the mistake is
// still free to correct.
//
// Only a reported method that is not MANUAL is refused. An absent value is
// accepted: the platform omits the field for the PENDING template rows a manual
// create leaves behind, and treating absence as a refusal would break the
// import path for a shape the platform genuinely produces.
//
// The test is "present and not MANUAL" rather than a list of known automated
// spellings. The captured live listings show CF for AWS CloudFormation, ARM for
// Azure and TF for Terraform, but the API publishes no enumeration of this
// field, so an allowlist would quietly adopt any value added later -- which is
// the outcome this exists to prevent.
func assertConnectorWasProvisionedManually(diagnostics *diag.Diagnostics, instanceID, provisioningMethod string) {
	if provisioningMethod == "" || provisioningMethod == manualProvisioningMethod {
		return
	}

	diagnostics.AddError(
		"Connector Not Managed By This Resource Type",
		fmt.Sprintf("Connector %s reports a provisioning method of %q, not %q, "+
			"so it was not onboarded manually.\n\n"+
			"Manage it with \"cortexcloud_cloud_integration_instance\" instead. "+
			"Destroying it through this resource would delete a connector that "+
			"was provisioned elsewhere, and the resource that provisioned it "+
			"would not notice.\n\n"+
			"No change has been made. If this connector really was onboarded "+
			"manually, remove it from Terraform state with "+
			"\"terraform state rm\" and report the reported provisioning method "+
			"above.", instanceID, provisioningMethod, manualProvisioningMethod),
	)
}

// isConnectorGoneError reports whether the platform explicitly told us the
// connector does not exist.
//
// This is deliberately narrow. The read endpoint answers 200 for identifiers it
// does not hold, so absence can only be inferred from the one rejection that
// names the connector as missing. Any other failure — a transport error, a
// server fault, an authorization problem — must not be read as deletion, or a
// transient outage would silently destroy live infrastructure.
func isConnectorGoneError(err error, instanceID string) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	if !strings.Contains(message, "connector id") {
		return false
	}
	if !strings.Contains(message, "doesn't exist") && !strings.Contains(message, "does not exist") {
		return false
	}

	// The rejection names the identifier that was asked for. Requiring the
	// match keeps an unrelated message about some other connector from
	// evicting this one.
	return strings.Contains(message, strings.ToLower(instanceID))
}

// Update applies the planned configuration to an existing connector.
//
// The payload is the complete desired state, built from the plan by the same
// conversion the create path uses. It is never a diff and never derived from a
// read: the edit the platform performs is partial, so anything left out of the
// request keeps whatever the platform already held, and the read shape is not a
// legal write body in the first place.
//
// Two situations are refused rather than attempted.
//
// The first is a change to cloud_provider, scope or scan_mode. Those carry
// RequiresReplace, so Terraform should have planned a replacement and this
// method should never see one; if it does, something upstream is wrong and the
// platform would reject the edit anyway. Failing here names the field instead
// of surfacing an opaque rejection.
//
// The second is clearing a member of manual_details. A cleared member is absent
// from the request, an absent member leaves the stored value untouched, and the
// wire format offers no way to say "remove this". Applying such a plan would
// report a success that did not happen and the difference would never be raised
// again, so the attempt is reported instead.
func (r *CloudManualIntegrationInstanceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "cloud_manual_integration_instance")
	ctx = tflog.SetField(ctx, "resource_operation", "Update")

	tflog.Debug(ctx, "Retrieving values from plan and state")
	var plan, state models.CloudManualIntegrationInstanceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The identifier is held by Terraform and never returned by the edit
	// endpoint, so it has to be carried across from prior state.
	plan.ID = state.ID
	instanceID := plan.ID.ValueString()
	ctx = tflog.SetField(ctx, "resource_id_value", instanceID)

	if instanceID == "" {
		resp.Diagnostics.AddError(
			"Error Updating Manual Cloud Integration Instance",
			"The connector has no identifier in Terraform state, so there is "+
				"nothing to address the update to. Remove the resource from "+
				"state and import it before updating it.",
		)
		return
	}

	assertImmutableFieldsUnchanged(&resp.Diagnostics, state, plan)
	assertNoManualDetailsCleared(&resp.Diagnostics, state, plan)
	if resp.Diagnostics.HasError() {
		return
	}

	editRequest := plan.ToEditRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Executing API request")
	if err := r.client.EditManualInstance(ctx, editRequest); err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Manual Cloud Integration Instance",
			fmt.Sprintf("Could not update connector %s:\n\n%s", instanceID, util.FormatAPIError(err)),
		)
		return
	}

	tflog.Debug(ctx, "Connector updated")

	// The edit reply is empty, so the same read-back the create needs applies
	// here: without it the Computed attributes keep their pre-edit values and
	// the next plan reports a difference the edit already applied.
	r.refreshAfterWrite(ctx, &resp.Diagnostics, &plan, "Updating")
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// assertImmutableFieldsUnchanged refuses an update that would change a field
// the platform fixes at creation.
//
// The API contract names three such fields -- scope, scan_mode and
// manual_details.account_id -- and states of the last that it "cannot be
// changed" and must be provided "exactly as it was at creation". cloud_provider
// is held to the same rule because the edit endpoint answers a changed provider
// with a bare rejection that names nothing.
//
// The first three carry RequiresReplace, so reaching this check with one of
// them altered means the plan was not built the way the schema describes.
// account_id is different and is the reason this check has to exist rather than
// being left to the schema: it carries no RequiresReplace, so Terraform plans an
// ordinary in-place update, and the edit endpoint answers 200 whether or not it
// honoured the new value. Left unchecked the change is recorded as applied,
// never reported as a difference again, and the practitioner is told the
// connector onboards an account it does not onboard.
func assertImmutableFieldsUnchanged(diagnostics *diag.Diagnostics, state, plan models.CloudManualIntegrationInstanceModel) {
	for _, field := range []struct {
		name string
		// replaced records whether the attribute carries RequiresReplace, which
		// decides what the practitioner is told to do about the difference.
		replaced bool
		prior    types.String
		next     types.String
	}{
		{"cloud_provider", true, state.CloudProvider, plan.CloudProvider},
		{"scope", true, state.Scope, plan.Scope},
		{"scan_mode", true, state.ScanMode, plan.ScanMode},
		{
			"manual_details.account_id", false,
			manualDetailsAccountID(state.ManualDetails),
			manualDetailsAccountID(plan.ManualDetails),
		},
	} {
		if field.prior.IsNull() || field.next.IsNull() {
			continue
		}
		if field.prior.Equal(field.next) {
			continue
		}

		remedy := "Terraform should have planned a replacement; that it did " +
			"not means the plan is inconsistent with the resource schema."
		if !field.replaced {
			remedy = "Restore the original value and replace the connector " +
				"instead. The platform accepts the edit without applying it, " +
				"so allowing this plan would record a change that did not " +
				"happen and no later plan would report the difference."
		}

		diagnostics.AddError(
			"Error Updating Manual Cloud Integration Instance",
			fmt.Sprintf("The connector's %q cannot be changed from %q to %q. "+
				"The platform fixes this value when the connector is created, "+
				"so the connector has to be replaced rather than updated. %s "+
				"The connector has NOT been changed.",
				field.name, field.prior.ValueString(), field.next.ValueString(),
				remedy),
		)
	}
}

// manualDetailsAccountID reads account_id out of a manual_details object,
// answering null whenever there is nothing to compare.
//
// Null is the right answer for an absent, unknown or not-yet-populated block
// rather than an error, because the guard treats null on either side as
// "nothing to compare". Import depends on that: it leaves manual_details null,
// so the first plan after an import moves the whole block from null to a value
// and must not be read as a change of account.
func manualDetailsAccountID(details types.Object) types.String {
	if details.IsNull() || details.IsUnknown() {
		return types.StringNull()
	}

	value, present := details.Attributes()["account_id"]
	if !present {
		return types.StringNull()
	}

	accountID, ok := value.(types.String)
	if !ok || accountID.IsUnknown() {
		return types.StringNull()
	}

	return accountID
}

// assertNoManualDetailsCleared refuses an update that removes a value from
// manual_details.
//
// The edit is partial and the request omits members that hold no value, so a
// cleared member is indistinguishable on the wire from one that was never
// mentioned, and the platform keeps what it already had. Terraform would then
// record the cleared value as applied and stop reporting the difference, which
// is worse than refusing the plan.
func assertNoManualDetailsCleared(diagnostics *diag.Diagnostics, state, plan models.CloudManualIntegrationInstanceModel) {
	cleared := models.ClearedManualDetails(state.ManualDetails, plan.ManualDetails)
	if len(cleared) == 0 {
		return
	}

	diagnostics.AddError(
		"Error Updating Manual Cloud Integration Instance",
		fmt.Sprintf("The configuration removes %s from \"manual_details\", "+
			"which the platform cannot carry out. Its edit is a partial "+
			"update: a value that is not sent is left as it was, and there is "+
			"no way to ask for one to be removed. Applying this plan would "+
			"report a change that did not happen. Give the field a new value "+
			"instead, or replace the connector. The connector has NOT been "+
			"changed.", strings.Join(quoted(cleared), ", ")),
	)
}

// quoted renders names for a diagnostic.
func quoted(names []string) []string {
	rendered := make([]string, 0, len(names))
	for _, name := range names {
		rendered = append(rendered, fmt.Sprintf("%q", name))
	}

	return rendered
}

// Delete removes the connector and then proves that it is gone.
//
// The endpoint used is the connector delete, not the template delete. They act
// on different records: the connector delete removes the row that the manual
// create returns an identifier for, and has been observed genuinely removing a
// connected manual connector. The template delete removes the separate template
// row created alongside it, which Terraform does not track and whose identifier
// it never receives.
//
// The reply cannot be trusted on its own. The endpoint answers 200 both when it
// removed a connector and when it matched nothing, and a partially applied
// batch has been seen answering with a server error after having already
// deleted rows. A listing therefore decides the outcome, and Terraform only
// drops the resource once the connector is absent from it. Reporting a delete
// that did not happen would leave a live connector with nothing tracking it,
// which is the failure this ordering exists to prevent.
func (r *CloudManualIntegrationInstanceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "cloud_manual_integration_instance")
	ctx = tflog.SetField(ctx, "resource_id_field", "id")
	ctx = tflog.SetField(ctx, "resource_operation", "Delete")

	tflog.Debug(ctx, "Retrieving values from state")
	var state models.CloudManualIntegrationInstanceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	instanceID := state.ID.ValueString()
	ctx = tflog.SetField(ctx, "resource_id_value", instanceID)

	if instanceID == "" {
		resp.Diagnostics.AddError(
			"Error Deleting Manual Cloud Integration Instance",
			"The connector has no identifier in Terraform state, so there is "+
				"nothing to delete. Remove the resource from state manually if "+
				"it is no longer wanted.",
		)
		return
	}

	tflog.Debug(ctx, "Executing API request")
	if err := r.client.DeleteIntegrationInstances(ctx, []string{instanceID}); err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Manual Cloud Integration Instance",
			fmt.Sprintf("Could not delete connector %s:\n\n%s\n\n"+
				"The connector is being kept in Terraform state because it may "+
				"still exist. Check the Cortex Cloud console before retrying.",
				instanceID, util.FormatAPIError(err)),
		)
		return
	}

	// The 200 above says nothing. Only the listing does.
	verificationRequest := state.ToDeleteVerificationRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Verifying the connector is gone")
	instances, err := r.client.ListIntegrationInstances(ctx, verificationRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Manual Cloud Integration Instance",
			fmt.Sprintf("The delete request for connector %s was accepted, but "+
				"confirming the connector is gone failed:\n\n%s\n\n"+
				"The platform reports success for a delete that removed "+
				"nothing, so the request alone is not evidence. The connector "+
				"is being kept in Terraform state until its removal can be "+
				"confirmed.", instanceID, util.FormatAPIError(err)),
		)
		return
	}

	if instanceStillListed(instances, instanceID) {
		resp.Diagnostics.AddError(
			"Error Deleting Manual Cloud Integration Instance",
			fmt.Sprintf("The delete request for connector %s was accepted, but "+
				"the connector is still present on the platform. The delete "+
				"endpoint reports success even when it removes nothing, which "+
				"is what appears to have happened here. The connector is being "+
				"kept in Terraform state so that it is not left unmanaged; "+
				"remove it through the Cortex Cloud console.", instanceID),
		)
		return
	}

	tflog.Debug(ctx, "Connector deletion confirmed")
}

// ImportState adopts an existing manual connector by its identifier.
//
// The identifier is all that is needed to address the connector: the read
// builds its request from that value alone, and the refresh that follows
// supplies cloud_provider, scope, scan_mode and the platform-reported details.
//
// What the refresh cannot supply is manual_details. The platform reports the
// cloud-side identities under a different shape from the one it accepts, and
// three of the members it accepts -- cloudtrail_role, sqs_url and
// subscription_id -- are never reported at all. Those values exist only in the
// configuration that created the connector, so an import cannot recover them
// and they are deliberately not guessed at from the reported shape.
//
// The consequence is that the first plan after an import is not empty: it
// proposes writing the manual_details the practitioner declares. That is
// intended, and it is safe in both directions that matter. An empty
// manual_details cannot slip through, because the attribute is required and
// Terraform rejects a configuration that omits it before this provider is
// consulted. A destroy cannot be provoked by the difference either, since the
// attributes carrying RequiresReplace are all populated by the refresh, so a
// configuration that agrees with the connector plans an update rather than a
// replacement.
//
// The practitioner must still read that first plan. It is an update, and it
// sends whatever manual_details the configuration declares, so a value that
// disagrees with the connector's real configuration will be applied to it.
func (r *CloudManualIntegrationInstanceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "cloud_manual_integration_instance")
	ctx = tflog.SetField(ctx, "resource_operation", "ImportState")
	ctx = tflog.SetField(ctx, "resource_id_value", req.ID)
	tflog.Debug(ctx, "Importing connector by identifier")

	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// connectorIsListed reports whether the connector is present in the listing.
//
// Read cannot establish existence from the read endpoint. Measured against a
// live tenant: after a connector was deleted, get_edit_instance_details went on
// answering 200 with its complete record over three samples across two minutes,
// while the listing dropped it immediately -- and a positive control on a
// connector that really existed returned it at the same moment, so the listing's
// silence was absence rather than a broken query. The only rejection the read
// endpoint gives is for an identifier that never existed at all, which a deleted
// connector does not produce.
//
// Left to the read endpoint, an out-of-band delete makes "terraform plan" report
// "No changes" forever: the resource stays in state pointing at nothing and
// Terraform never offers to rebuild it. The listing is the same instrument
// Delete already uses to confirm removal, and the same AND-wrapped filter, so
// this adds no new assumption about the platform.
//
// An error is returned rather than swallowed. A check that could not be
// completed says nothing about whether the connector exists, and reading it as
// absence would evict live infrastructure from state during an outage.
func (r *CloudManualIntegrationInstanceResource) connectorIsListed(
	ctx context.Context,
	state *models.CloudManualIntegrationInstanceModel,
	instanceID string,
) (bool, error) {
	var diagnostics diag.Diagnostics

	request := state.ToDeleteVerificationRequest(ctx, &diagnostics)
	if diagnostics.HasError() {
		return false, fmt.Errorf("could not build the listing request: %v", diagnostics.Errors())
	}

	instances, err := r.client.ListIntegrationInstances(ctx, request)
	if err != nil {
		return false, err
	}

	return instanceStillListed(instances, instanceID), nil
}

// instanceStillListed reports whether the listing still contains the connector.
//
// Only a positive match counts. An empty listing is what a successful delete
// looks like, and the caller has already handled the case where the listing
// itself failed, so absence here is evidence rather than an assumption.
func instanceStillListed(instances []cloudOnboardingTypes.IntegrationInstance, instanceID string) bool {
	for _, instance := range instances {
		if instance.ID == instanceID {
			return true
		}
	}

	return false
}
