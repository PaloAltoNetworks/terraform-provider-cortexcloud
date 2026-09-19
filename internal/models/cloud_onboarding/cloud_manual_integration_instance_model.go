// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"sort"

	cortexEnums "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	cloudOnboardingTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// CloudManualIntegrationInstanceModel is the Terraform representation of a
// manually onboarded cloud connector instance.
//
// The manual onboarding endpoints are a separate surface from the template
// driven ones: the two schemas are disjoint and each endpoint rejects the
// fields the other requires. This model therefore stands alone rather than
// extending the template models.
//
// ManualDetails and ReportedManualDetails are deliberately two different object
// types. The write surface accepts keys the read surface never returns, and the
// read surface returns a key the write surface rejects, so a value read back
// from the platform cannot be echoed into a write. Every conversion below maps
// field by field for that reason.
type CloudManualIntegrationInstanceModel struct {
	ID                      types.String `tfsdk:"id"`
	CloudProvider           types.String `tfsdk:"cloud_provider"`
	Scope                   types.String `tfsdk:"scope"`
	ScanMode                types.String `tfsdk:"scan_mode"`
	OutpostID               types.String `tfsdk:"outpost_id"`
	InstanceName            types.String `tfsdk:"instance_name"`
	CloudPartition          types.String `tfsdk:"cloud_partition"`
	ManualDetails           types.Object `tfsdk:"manual_details"`
	ReportedManualDetails   types.Object `tfsdk:"reported_manual_details"`
	AdditionalCapabilities  types.Object `tfsdk:"additional_capabilities"`
	CollectionConfiguration types.Object `tfsdk:"collection_configuration"`
	ScopeModifications      types.Object `tfsdk:"scope_modifications"`
	CustomResourcesTags     types.Set    `tfsdk:"custom_resources_tags"`
}

// ----------------------------------------------------------------------------
// Nested value types
// ----------------------------------------------------------------------------

// manualDetailsWrite mirrors the provider-specific identifiers the manual
// create and edit endpoints accept. Every member is a pointer because the API
// shapes this object per cloud provider and an absent key is not the same as an
// empty one.
type manualDetailsWrite struct {
	// AWS.
	AccountID             *string `tfsdk:"account_id"`
	AccountName           *string `tfsdk:"account_name"`
	OrganizationID        *string `tfsdk:"organization_id"`
	RoleARN               *string `tfsdk:"role_arn"`
	ExternalID            *string `tfsdk:"external_id"`
	OutpostScannerRoleARN *string `tfsdk:"outpost_scanner_role_arn"`
	CloudTrailRole        *string `tfsdk:"cloudtrail_role"`
	SQSURL                *string `tfsdk:"sqs_url"`

	// GCP is not supported for manual onboarding, so no GCP-only members are
	// modelled. These structs are decoded against the schema by tfsdk tag, so a
	// member here without a matching attribute would fail at runtime.

	// Azure.
	TenantID                            *string `tfsdk:"tenant_id"`
	SubscriptionID                      *string `tfsdk:"subscription_id"`
	ResourceGroupName                   *string `tfsdk:"resource_group_name"`
	ResourceGroupLocation               *string `tfsdk:"resource_group_location"`
	ADSImageGalleryResourceID           *string `tfsdk:"ads_image_gallery_resource_id"`
	EventHubName                        *string `tfsdk:"eventhub_name"`
	EventHubResourceGroupName           *string `tfsdk:"eventhub_resource_group_name"`
	EventHubNamespace                   *string `tfsdk:"eventhub_namespace"`
	AzureAuditEventHubConsumerGroupName *string `tfsdk:"azure_audit_eventhub_consumer_group_name"`
	StorageAccountName                  *string `tfsdk:"storage_account_name"`
	EventHubAuditClientID               *string `tfsdk:"eventhub_audit_client_id"`
}

// manualDetailsRead mirrors what the read endpoint reports back. It is not
// manualDetailsWrite: client_id is reported but refused on write, while
// cloudtrail_role, sqs_url and subscription_id are accepted on write and never
// reported. The GCP members have no observed read shape behind them; they are
// modelled from the same identifier offer as their write counterparts so that a
// value that does arrive is not silently discarded.
type manualDetailsRead struct {
	// AWS.
	AccountID             *string `tfsdk:"account_id"`
	AccountName           *string `tfsdk:"account_name"`
	OrganizationID        *string `tfsdk:"organization_id"`
	RoleARN               *string `tfsdk:"role_arn"`
	ExternalID            *string `tfsdk:"external_id"`
	OutpostScannerRoleARN *string `tfsdk:"outpost_scanner_role_arn"`

	// GCP-only members are absent: manual onboarding does not support GCP.

	// Azure.
	TenantID                            *string `tfsdk:"tenant_id"`
	ClientID                            *string `tfsdk:"client_id"`
	ResourceGroupName                   *string `tfsdk:"resource_group_name"`
	ResourceGroupLocation               *string `tfsdk:"resource_group_location"`
	ADSImageGalleryResourceID           *string `tfsdk:"ads_image_gallery_resource_id"`
	EventHubName                        *string `tfsdk:"eventhub_name"`
	EventHubResourceGroupName           *string `tfsdk:"eventhub_resource_group_name"`
	EventHubNamespace                   *string `tfsdk:"eventhub_namespace"`
	AzureAuditEventHubConsumerGroupName *string `tfsdk:"azure_audit_eventhub_consumer_group_name"`
	StorageAccountName                  *string `tfsdk:"storage_account_name"`
	EventHubAuditClientID               *string `tfsdk:"eventhub_audit_client_id"`
}

// manualAdditionalCapabilities holds the capability toggles the manual write
// endpoints accept. The read endpoint reports further keys that no manual write
// endpoint accepts; they are not modelled, because a configurable attribute
// that cannot be written would be a promise the API does not keep.
type manualAdditionalCapabilities struct {
	Automation                    *bool                          `tfsdk:"automation"`
	AutomationLogLevel            *string                        `tfsdk:"automation_log_level"`
	XSIAMAnalytics                *bool                          `tfsdk:"xsiam_analytics"`
	RegistryScanning              *bool                          `tfsdk:"registry_scanning"`
	RegistryScanningOptions       *manualRegistryScanningOptions `tfsdk:"registry_scanning_options"`
	KubernetesSecurity            *bool                          `tfsdk:"kubernetes_security"`
	ServerlessScanning            *bool                          `tfsdk:"serverless_scanning"`
	AgentlessDiskScanning         *bool                          `tfsdk:"agentless_disk_scanning"`
	DataSecurityPostureManagement *bool                          `tfsdk:"data_security_posture_management"`
	UploadFilesToWildfire         *bool                          `tfsdk:"upload_files_to_wildfire"`
}

// manualRegistryScanningOptions is the option set that must accompany
// registry_scanning. The platform validates the two as a pair and refuses
// either one alone with
//
//	422 "Registry scanning and registry scanning options must both be provided
//	     together or neither should be provided"
type manualRegistryScanningOptions struct {
	Type     *string `tfsdk:"type"`
	LastDays *int64  `tfsdk:"last_days"`
}

type manualCollectionConfiguration struct {
	AuditLogs *manualAuditLogs `tfsdk:"audit_logs"`
}

// manualAuditLogs mirrors collection_configuration.audit_logs.
//
// It carries no cloudtrail_role or sqs_url: the platform refuses both in this
// block with "extra_forbidden". They live in manualDetails instead.
type manualAuditLogs struct {
	Enabled            *bool   `tfsdk:"enabled"`
	DataEvents         *bool   `tfsdk:"data_events"`
	CollectionMethod   *string `tfsdk:"collection_method"`
	IsControlTowerBYOB *bool   `tfsdk:"is_control_tower_byob"`
}

type manualScopeModifications struct {
	Accounts      *manualScopeAccounts      `tfsdk:"accounts"`
	Projects      *manualScopeProjects      `tfsdk:"projects"`
	Subscriptions *manualScopeSubscriptions `tfsdk:"subscriptions"`
	Regions       *scopeModificationRegions `tfsdk:"regions"`
}

type manualScopeAccounts struct {
	Enabled    bool      `tfsdk:"enabled"`
	Type       *string   `tfsdk:"type"`
	AccountIDs *[]string `tfsdk:"account_ids"`
}

type manualScopeProjects struct {
	Enabled    bool      `tfsdk:"enabled"`
	Type       *string   `tfsdk:"type"`
	ProjectIDs *[]string `tfsdk:"project_ids"`
}

type manualScopeSubscriptions struct {
	Enabled         bool      `tfsdk:"enabled"`
	Type            *string   `tfsdk:"type"`
	SubscriptionIDs *[]string `tfsdk:"subscription_ids"`
}

// ----------------------------------------------------------------------------
// Attribute types
//
// The schema and the conversions below are built from the same maps, so a key
// cannot drift out of step between the two.
// ----------------------------------------------------------------------------

// ManualDetailsWriteAttributeTypes returns the attribute types of the
// configurable manual_details object.
func ManualDetailsWriteAttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"account_id":               types.StringType,
		"account_name":             types.StringType,
		"organization_id":          types.StringType,
		"role_arn":                 types.StringType,
		"external_id":              types.StringType,
		"outpost_scanner_role_arn": types.StringType,
		"cloudtrail_role":          types.StringType,
		"sqs_url":                  types.StringType,

		"tenant_id":                                types.StringType,
		"subscription_id":                          types.StringType,
		"resource_group_name":                      types.StringType,
		"resource_group_location":                  types.StringType,
		"ads_image_gallery_resource_id":            types.StringType,
		"eventhub_name":                            types.StringType,
		"eventhub_resource_group_name":             types.StringType,
		"eventhub_namespace":                       types.StringType,
		"azure_audit_eventhub_consumer_group_name": types.StringType,
		"storage_account_name":                     types.StringType,
		"eventhub_audit_client_id":                 types.StringType,
	}
}

// ManualDetailsReadAttributeTypes returns the attribute types of the reported
// manual_details object.
func ManualDetailsReadAttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"account_id":               types.StringType,
		"account_name":             types.StringType,
		"organization_id":          types.StringType,
		"role_arn":                 types.StringType,
		"external_id":              types.StringType,
		"outpost_scanner_role_arn": types.StringType,

		"tenant_id":                                types.StringType,
		"client_id":                                types.StringType,
		"resource_group_name":                      types.StringType,
		"resource_group_location":                  types.StringType,
		"ads_image_gallery_resource_id":            types.StringType,
		"eventhub_name":                            types.StringType,
		"eventhub_resource_group_name":             types.StringType,
		"eventhub_namespace":                       types.StringType,
		"azure_audit_eventhub_consumer_group_name": types.StringType,
		"storage_account_name":                     types.StringType,
		"eventhub_audit_client_id":                 types.StringType,
	}
}

// ManualAdditionalCapabilitiesAttributeTypes returns the attribute types of the
// additional_capabilities object.
func ManualAdditionalCapabilitiesAttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"automation":           types.BoolType,
		"automation_log_level": types.StringType,
		"xsiam_analytics":      types.BoolType,
		"registry_scanning":    types.BoolType,
		"registry_scanning_options": types.ObjectType{
			AttrTypes: ManualRegistryScanningOptionsAttributeTypes(),
		},
		"kubernetes_security":              types.BoolType,
		"serverless_scanning":              types.BoolType,
		"agentless_disk_scanning":          types.BoolType,
		"data_security_posture_management": types.BoolType,
		"upload_files_to_wildfire":         types.BoolType,
	}
}

// ManualRegistryScanningOptionsAttributeTypes returns the attribute types of
// the additional_capabilities.registry_scanning_options object.
func ManualRegistryScanningOptionsAttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type":      types.StringType,
		"last_days": types.Int64Type,
	}
}

// ManualAuditLogsAttributeTypes returns the attribute types of the
// collection_configuration.audit_logs object.
func ManualAuditLogsAttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enabled":               types.BoolType,
		"data_events":           types.BoolType,
		"collection_method":     types.StringType,
		"is_control_tower_byob": types.BoolType,
	}
}

// ManualCollectionConfigurationAttributeTypes returns the attribute types of
// the collection_configuration object.
func ManualCollectionConfigurationAttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"audit_logs": types.ObjectType{AttrTypes: ManualAuditLogsAttributeTypes()},
	}
}

// ManualScopeModificationsAttributeTypes returns the attribute types of the
// scope_modifications object.
func ManualScopeModificationsAttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"accounts": types.ObjectType{AttrTypes: map[string]attr.Type{
			"enabled":     types.BoolType,
			"type":        types.StringType,
			"account_ids": types.ListType{ElemType: types.StringType},
		}},
		"projects": types.ObjectType{AttrTypes: map[string]attr.Type{
			"enabled":     types.BoolType,
			"type":        types.StringType,
			"project_ids": types.ListType{ElemType: types.StringType},
		}},
		"subscriptions": types.ObjectType{AttrTypes: map[string]attr.Type{
			"enabled":          types.BoolType,
			"type":             types.StringType,
			"subscription_ids": types.ListType{ElemType: types.StringType},
		}},
		"regions": types.ObjectType{AttrTypes: map[string]attr.Type{
			"enabled": types.BoolType,
			"type":    types.StringType,
			"regions": types.ListType{ElemType: types.StringType},
		}},
	}
}

// ManualCustomResourcesTagType returns the element type of the
// custom_resources_tags set.
func ManualCustomResourcesTagType() attr.Type {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"key":   types.StringType,
		"value": types.StringType,
	}}
}

// ----------------------------------------------------------------------------
// Terraform to API
// ----------------------------------------------------------------------------

// ToCreateRequest builds the create payload from the planned configuration.
func (m *CloudManualIntegrationInstanceModel) ToCreateRequest(ctx context.Context, diagnostics *diag.Diagnostics) *cloudOnboardingTypes.CreateManualInstanceRequest {
	ctx = tflog.SetField(ctx, "resource_operation", "ToCreateRequest")

	manualDetails := m.manualDetails(ctx, diagnostics)
	additionalCapabilities := m.additionalCapabilities(ctx, diagnostics)
	collectionConfiguration := m.collectionConfiguration(ctx, diagnostics)
	scopeModifications := m.scopeModifications(ctx, diagnostics)
	customResourcesTags := m.customResourcesTags(ctx, diagnostics)

	if diagnostics.HasError() {
		return nil
	}

	options := []cloudOnboardingTypes.CreateManualInstanceRequestOption{
		cloudOnboardingTypes.WithManualCreateAdditionalCapabilities(additionalCapabilities),
		cloudOnboardingTypes.WithManualCreateCollectionConfiguration(collectionConfiguration),
		cloudOnboardingTypes.WithManualCreateScopeModifications(scopeModifications),
	}

	if len(customResourcesTags) > 0 {
		options = append(options, cloudOnboardingTypes.WithManualCreateCustomResourcesTags(customResourcesTags))
	}
	if value, ok := stringValue(m.InstanceName); ok {
		options = append(options, cloudOnboardingTypes.WithManualCreateInstanceName(value))
	}
	if value, ok := stringValue(m.CloudPartition); ok {
		options = append(options, cloudOnboardingTypes.WithManualCreateCloudPartition(value))
	}
	if value, ok := stringValue(m.OutpostID); ok {
		options = append(options, cloudOnboardingTypes.WithManualCreateOutpostID(value))
	}

	return cloudOnboardingTypes.NewCreateManualInstanceRequest(
		m.CloudProvider.ValueString(),
		m.Scope.ValueString(),
		m.ScanMode.ValueString(),
		manualDetails,
		options...,
	)
}

// ToEditRequest builds the edit payload from the planned configuration.
//
// The edit is a partial update: a field left out of the payload keeps its
// previous server-side value instead of being cleared. The payload is therefore
// built from the complete desired state, exactly as the create payload is, and
// never from a diff against prior state.
func (m *CloudManualIntegrationInstanceModel) ToEditRequest(ctx context.Context, diagnostics *diag.Diagnostics) *cloudOnboardingTypes.EditManualInstanceRequest {
	ctx = tflog.SetField(ctx, "resource_operation", "ToEditRequest")

	manualDetails := m.manualDetails(ctx, diagnostics)
	additionalCapabilities := m.additionalCapabilities(ctx, diagnostics)
	collectionConfiguration := m.collectionConfiguration(ctx, diagnostics)
	scopeModifications := m.scopeModifications(ctx, diagnostics)
	customResourcesTags := m.customResourcesTags(ctx, diagnostics)

	if diagnostics.HasError() {
		return nil
	}

	options := []cloudOnboardingTypes.EditManualInstanceRequestOption{
		cloudOnboardingTypes.WithManualEditAdditionalCapabilities(additionalCapabilities),
		cloudOnboardingTypes.WithManualEditCollectionConfiguration(collectionConfiguration),
		cloudOnboardingTypes.WithManualEditScopeModifications(scopeModifications),
	}

	if len(customResourcesTags) > 0 {
		options = append(options, cloudOnboardingTypes.WithManualEditCustomResourcesTags(customResourcesTags))
	}
	if value, ok := stringValue(m.InstanceName); ok {
		options = append(options, cloudOnboardingTypes.WithManualEditInstanceName(value))
	}
	if value, ok := stringValue(m.CloudPartition); ok {
		options = append(options, cloudOnboardingTypes.WithManualEditCloudPartition(value))
	}
	if value, ok := stringValue(m.OutpostID); ok {
		options = append(options, cloudOnboardingTypes.WithManualEditOutpostID(value))
	}

	return cloudOnboardingTypes.NewEditManualInstanceRequest(
		m.ID.ValueString(),
		m.CloudProvider.ValueString(),
		m.Scope.ValueString(),
		m.ScanMode.ValueString(),
		manualDetails,
		options...,
	)
}

// ToReadRequest builds the read payload for the connector held in state.
func (m *CloudManualIntegrationInstanceModel) ToReadRequest(ctx context.Context, _ *diag.Diagnostics) *cloudOnboardingTypes.GetEditInstanceDetailsRequest {
	ctx = tflog.SetField(ctx, "resource_operation", "ToReadRequest")
	tflog.Debug(ctx, "Building the read request")

	return cloudOnboardingTypes.NewGetEditInstanceDetailsRequest(m.ID.ValueString())
}

// ToDeleteVerificationRequest builds a listing request narrowed to the single
// connector held in state.
//
// The delete endpoint answers 200 whether it removed a connector or did
// nothing at all, so its reply cannot be used as evidence. This listing is what
// establishes the outcome: the connector is gone when, and only when, the
// listing no longer returns it.
//
// The identifier is matched with a filter rather than a sort, because sorting
// on the identifier field is answered with a server error.
//
// The predicate is wrapped in an AND even though there is only one of them.
// That is not decoration. The listing endpoint parses the top level of
// "filter" as a boolean operator and accepts nothing else: handed a bare
// comparison it answers
//
//	500 _parse_filters - Type mismatch, expected: dict_values(['AND', 'NOT',
//	'OR']), Got: SEARCH_FIELD
//
// so every request built without the wrapper fails, for a connector that
// exists and for one that does not alike. Wrapping is what the template
// listings already do, and it is what makes this request able to tell those
// two cases apart -- which is the only reason the request exists.
func (m *CloudManualIntegrationInstanceModel) ToDeleteVerificationRequest(ctx context.Context, _ *diag.Diagnostics) *cloudOnboardingTypes.ListIntegrationInstancesRequest {
	ctx = tflog.SetField(ctx, "resource_operation", "ToDeleteVerificationRequest")
	tflog.Debug(ctx, "Building the listing request that establishes existence")

	return cloudOnboardingTypes.NewListIntegrationInstancesRequest(
		cloudOnboardingTypes.WithIntegrationFilterData(
			filterTypes.FilterData{
				Filter: filterTypes.NewAndFilter(
					filterTypes.NewSearchFilter(
						cortexEnums.SearchFieldID.String(),
						cortexEnums.SearchTypeEqualTo.String(),
						m.ID.ValueString(),
					),
				),
				Paging: filterTypes.PagingFilter{From: 0, To: 1000},
			},
		),
	)
}

// ClearedManualDetails reports the members of manual_details that the plan
// clears relative to the prior state.
//
// This exists because such a change cannot be carried out. The edit endpoint
// applies a partial update, and the request type omits a member whose value is
// absent, so a cleared member never reaches the platform and the old value
// survives. Terraform would record the clear as applied and never report the
// difference again.
//
// Detecting the situation is the only honest option available. The provider
// cannot express "clear this" on this wire format, and substituting an empty
// string is refused by at least one cloud provider, so the attempt is reported
// rather than silently dropped.
func ClearedManualDetails(prior, planned types.Object) []string {
	if prior.IsNull() || prior.IsUnknown() || planned.IsNull() || planned.IsUnknown() {
		return nil
	}

	priorAttributes := prior.Attributes()
	plannedAttributes := planned.Attributes()

	var cleared []string
	for name, priorValue := range priorAttributes {
		priorString, ok := priorValue.(types.String)
		if !ok || priorString.IsNull() || priorString.IsUnknown() {
			continue
		}

		plannedValue, present := plannedAttributes[name]
		if !present {
			continue
		}
		plannedString, ok := plannedValue.(types.String)
		if !ok {
			continue
		}

		if plannedString.IsNull() {
			cleared = append(cleared, name)
		}
	}

	sort.Strings(cleared)

	return cleared
}

// unknownMembersAsAbsent reads an object whose members are not all known.
//
// Every optional member of these blocks is also Computed, because the platform
// defaults the ones the practitioner does not set. Terraform marks exactly
// those members UNKNOWN while it plans, so a configuration that enables one
// capability and leaves the rest alone produces an object that is partly
// unknown. That is the ordinary shape of a plan, not an edge case.
//
// The Go structs these objects are read into hold pointers, and there is no
// pointer that means "not yet known". Without this option the framework
// answers a partly-unknown object with a Value Conversion Error and the apply
// stops before any request is sent -- which is how the first live apply of this
// resource failed.
//
// Mapping unknown to the zero pointer is not merely a way to silence that. It
// is the correct payload. The edit is a partial update and every member of the
// request type is a pointer tagged ",omitempty", so a nil member is left out of
// the request entirely and the platform keeps whatever it already had. That is
// precisely what "the practitioner did not express an opinion" should mean.
// Resolving an unknown toggle to false instead would transmit a decision the
// configuration never made and silently disable a live capability.
var unknownMembersAsAbsent = basetypes.ObjectAsOptions{UnhandledUnknownAsEmpty: true}

func (m *CloudManualIntegrationInstanceModel) manualDetails(ctx context.Context, diagnostics *diag.Diagnostics) cloudOnboardingTypes.ManualDetails {
	var value manualDetailsWrite
	if m.ManualDetails.IsNull() || m.ManualDetails.IsUnknown() {
		return cloudOnboardingTypes.ManualDetails{}
	}

	diagnostics.Append(m.ManualDetails.As(ctx, &value, unknownMembersAsAbsent)...)
	if diagnostics.HasError() {
		return cloudOnboardingTypes.ManualDetails{}
	}

	return cloudOnboardingTypes.ManualDetails{
		AccountID:             value.AccountID,
		AccountName:           value.AccountName,
		OrganizationID:        value.OrganizationID,
		RoleARN:               value.RoleARN,
		ExternalID:            value.ExternalID,
		OutpostScannerRoleARN: value.OutpostScannerRoleARN,
		CloudTrailRole:        value.CloudTrailRole,
		SQSURL:                value.SQSURL,

		TenantID:                            value.TenantID,
		SubscriptionID:                      value.SubscriptionID,
		ResourceGroupName:                   value.ResourceGroupName,
		ResourceGroupLocation:               value.ResourceGroupLocation,
		ADSImageGalleryResourceID:           value.ADSImageGalleryResourceID,
		EventHubName:                        value.EventHubName,
		EventHubResourceGroupName:           value.EventHubResourceGroupName,
		EventHubNamespace:                   value.EventHubNamespace,
		AzureAuditEventHubConsumerGroupName: value.AzureAuditEventHubConsumerGroupName,
		StorageAccountName:                  value.StorageAccountName,
		EventHubAuditClientID:               value.EventHubAuditClientID,
	}
}

func (m *CloudManualIntegrationInstanceModel) additionalCapabilities(ctx context.Context, diagnostics *diag.Diagnostics) cloudOnboardingTypes.ManualAdditionalCapabilities {
	var value manualAdditionalCapabilities
	if m.AdditionalCapabilities.IsNull() || m.AdditionalCapabilities.IsUnknown() {
		return cloudOnboardingTypes.ManualAdditionalCapabilities{}
	}

	diagnostics.Append(m.AdditionalCapabilities.As(ctx, &value, unknownMembersAsAbsent)...)
	if diagnostics.HasError() {
		return cloudOnboardingTypes.ManualAdditionalCapabilities{}
	}

	capabilities := cloudOnboardingTypes.ManualAdditionalCapabilities{
		Automation:                    value.Automation,
		AutomationLogLevel:            value.AutomationLogLevel,
		XSIAMAnalytics:                value.XSIAMAnalytics,
		RegistryScanning:              value.RegistryScanning,
		KubernetesSecurity:            value.KubernetesSecurity,
		ServerlessScanning:            value.ServerlessScanning,
		AgentlessDiskScanning:         value.AgentlessDiskScanning,
		DataSecurityPostureManagement: value.DataSecurityPostureManagement,
		UploadFilesToWildfire:         value.UploadFilesToWildfire,
	}

	// registry_scanning and registry_scanning_options are validated as a pair.
	// Sending the toggle alone is refused with 422 "Registry scanning and
	// registry scanning options must both be provided together or neither
	// should be provided", so the option set has to travel with it.
	if value.RegistryScanningOptions != nil {
		options := &cloudOnboardingTypes.RegistryScanningOptions{}
		if value.RegistryScanningOptions.Type != nil {
			options.Type = *value.RegistryScanningOptions.Type
		}
		if value.RegistryScanningOptions.LastDays != nil {
			lastDays := int(*value.RegistryScanningOptions.LastDays)
			options.LastDays = &lastDays
		}
		capabilities.RegistryScanningOptions = options
	}

	return capabilities
}

// collectionConfiguration converts the configured collection_configuration.
//
// The attribute, its audit_logs member and that member's enabled, data_events
// and collection_method fields are all Required, so the remaining nil guards
// cover only the genuinely optional members.
func (m *CloudManualIntegrationInstanceModel) collectionConfiguration(ctx context.Context, diagnostics *diag.Diagnostics) cloudOnboardingTypes.ManualCollectionConfiguration {
	var value manualCollectionConfiguration

	// Required, so this is unreachable from a configuration. It guards the
	// paths that skip validation -- prior state, and the null objects tests
	// build -- where As() would fail on a null. The zero value invents nothing.
	if m.CollectionConfiguration.IsNull() || m.CollectionConfiguration.IsUnknown() {
		return cloudOnboardingTypes.ManualCollectionConfiguration{}
	}

	diagnostics.Append(m.CollectionConfiguration.As(ctx, &value, unknownMembersAsAbsent)...)
	if diagnostics.HasError() || value.AuditLogs == nil {
		return cloudOnboardingTypes.ManualCollectionConfiguration{}
	}

	auditLogs := cloudOnboardingTypes.ManualAuditLogsConfiguration{
		IsControlTowerBYOB: value.AuditLogs.IsControlTowerBYOB,
	}
	if value.AuditLogs.Enabled != nil {
		auditLogs.Enabled = *value.AuditLogs.Enabled
	}
	if value.AuditLogs.DataEvents != nil {
		auditLogs.DataEvents = *value.AuditLogs.DataEvents
	}
	if value.AuditLogs.CollectionMethod != nil {
		auditLogs.CollectionMethod = *value.AuditLogs.CollectionMethod
	}

	return cloudOnboardingTypes.ManualCollectionConfiguration{AuditLogs: auditLogs}
}

// scopeModifications converts the configured scope_modifications.
//
// The platform rejects a write without scope_modifications.regions
// ("Field required"), so both the attribute and its regions member are
// Required. The provider no longer substitutes regions{enabled:false} when a
// configuration stays silent: that sent a region policy nobody wrote.
func (m *CloudManualIntegrationInstanceModel) scopeModifications(ctx context.Context, diagnostics *diag.Diagnostics) cloudOnboardingTypes.ManualScopeModifications {
	var value manualScopeModifications

	// As above: guards the non-configuration paths, and invents no scope.
	if m.ScopeModifications.IsNull() || m.ScopeModifications.IsUnknown() {
		return cloudOnboardingTypes.ManualScopeModifications{}
	}

	diagnostics.Append(m.ScopeModifications.As(ctx, &value, unknownMembersAsAbsent)...)
	if diagnostics.HasError() {
		return cloudOnboardingTypes.ManualScopeModifications{}
	}

	scopeModifications := cloudOnboardingTypes.ManualScopeModifications{}
	if value.Accounts != nil {
		scopeModifications.Accounts = &cloudOnboardingTypes.ScopeModificationGeneric{
			Enabled:    value.Accounts.Enabled,
			Type:       value.Accounts.Type,
			AccountIDs: value.Accounts.AccountIDs,
		}
	}
	if value.Projects != nil {
		scopeModifications.Projects = &cloudOnboardingTypes.ScopeModificationGeneric{
			Enabled:    value.Projects.Enabled,
			Type:       value.Projects.Type,
			ProjectIDs: value.Projects.ProjectIDs,
		}
	}
	if value.Subscriptions != nil {
		scopeModifications.Subscriptions = &cloudOnboardingTypes.ScopeModificationGeneric{
			Enabled:         value.Subscriptions.Enabled,
			Type:            value.Subscriptions.Type,
			SubscriptionIDs: value.Subscriptions.SubscriptionIDs,
		}
	}
	// Required, so always present; the guard is here because As() cannot
	// promise a non-nil pointer.
	if value.Regions != nil {
		scopeModifications.Regions = &cloudOnboardingTypes.ScopeModificationRegions{
			Enabled: value.Regions.Enabled,
			Type:    value.Regions.Type,
			Regions: value.Regions.Regions,
		}
	}

	return scopeModifications
}

func (m *CloudManualIntegrationInstanceModel) customResourcesTags(ctx context.Context, diagnostics *diag.Diagnostics) []cloudOnboardingTypes.Tag {
	if m.CustomResourcesTags.IsNull() || m.CustomResourcesTags.IsUnknown() {
		return nil
	}

	var tags []cloudOnboardingTypes.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &tags, false)...)
	if diagnostics.HasError() {
		return nil
	}

	return tags
}

// stringValue reports the value of a configured, non-empty string attribute.
func stringValue(value types.String) (string, bool) {
	if value.IsNull() || value.IsUnknown() || value.ValueString() == "" {
		return "", false
	}

	return value.ValueString(), true
}

// ----------------------------------------------------------------------------
// API to Terraform
// ----------------------------------------------------------------------------

// RefreshFromReadResponse maps a read reply into state.
//
// The reply is never echoed into manual_details. Its shape is not accepted by
// the write endpoints, so feeding it back would produce a payload the platform
// rejects. What the platform reports lands in reported_manual_details, which is
// computed and never sent, and the configured manual_details is left untouched.
func (m *CloudManualIntegrationInstanceModel) RefreshFromReadResponse(ctx context.Context, diagnostics *diag.Diagnostics, fields cloudOnboardingTypes.InstanceEditFields) {
	ctx = tflog.SetField(ctx, "resource_operation", "RefreshFromReadResponse")

	m.CloudProvider = types.StringValue(fields.CloudProvider)
	m.Scope = types.StringValue(fields.Scope)
	m.ScanMode = types.StringValue(fields.ScanMode)

	if fields.InstanceName == "" {
		m.InstanceName = types.StringNull()
	} else {
		m.InstanceName = types.StringValue(fields.InstanceName)
	}

	if fields.CloudPartition == "" {
		m.CloudPartition = types.StringNull()
	} else {
		m.CloudPartition = types.StringValue(fields.CloudPartition)
	}

	// scan_env_id is the read reply's name for the value outpost_id is sent as:
	// the identifier a connector's listing row reports as outpost_id appears
	// verbatim as scan_env_id in that connector's edit-details reply.
	//
	// It is only adopted for a configuration that asked for an outpost. The
	// platform reports one for connectors that did not -- every MANAGED row in
	// the captured listings carries a non-empty outpost identifier, the
	// tenant's default -- and outpost_id is Optional and not Computed, so
	// Terraform requires the applied value to equal the configuration exactly.
	// Recording an outpost nobody asked for would turn that null into a value
	// and the apply would fail with "Provider produced inconsistent result
	// after apply". This refresh also runs after create and edit, so that would
	// fire on the first apply of every MANAGED connector, not just on a read.
	//
	// For a connector that did ask, the reported value wins: that is what makes
	// an outpost change applied outside Terraform show up as drift rather than
	// leaving every plan reporting no changes.
	if !m.OutpostID.IsNull() && !m.OutpostID.IsUnknown() && fields.ScanEnvID != "" {
		m.OutpostID = types.StringValue(fields.ScanEnvID)
	}

	m.ReportedManualDetails = reportedManualDetailsObject(ctx, diagnostics, fields.ManualDetails)

	m.AdditionalCapabilities = refreshedAdditionalCapabilities(ctx, diagnostics, fields.AdditionalCapabilities)

	m.CollectionConfiguration = refreshedCollectionConfiguration(ctx, diagnostics, m.CollectionConfiguration, fields.CollectionConfiguration)

	m.ScopeModifications = refreshedScopeModifications(ctx, diagnostics, m.ScopeModifications, fields.ScopeModifications)

	tags, diags := types.SetValueFrom(ctx, ManualCustomResourcesTagType(),
		configurableTags(ctx, diagnostics, m.CustomResourcesTags, fields.CustomResourcesTags))
	diagnostics.Append(diags...)
	if !diagnostics.HasError() {
		m.CustomResourcesTags = tags
	}
}

// platformOwnedTag is the tag Cortex Cloud stamps on connectors it creates.
//
// The key is reserved: onboarding with it under any other value is refused with
// 400 "Invalid connector details", while the same value under a different key,
// and a near-miss key under this value, are both accepted. This exact pair is
// therefore the only form of the key a configuration may contain -- and it IS
// permitted, verified live: creating a connector with it returns 200.
const (
	platformOwnedTagKey   = "managed_by"
	platformOwnedTagValue = "paloaltonetworks"
)

// configurableTags drops the platform's own tag unless the configuration asked
// for it.
//
// A refresh reports every tag on the connector, including the one the platform
// added by itself. Recording an unasked-for tag makes the state hold more than
// the plan and Terraform aborts with "Provider produced inconsistent result
// after apply: .custom_resources_tags: length changed from 1 to 2".
//
// Discarding it unconditionally is the same defect mirrored. The pair is legal
// to declare, so for a configuration that does declare it the state would then
// hold less than the plan -- "length changed from 1 to 0". Whether the tag
// belongs in state is a question about the configuration, not about the tag,
// so the configuration is what decides.
func configurableTags(
	ctx context.Context,
	diagnostics *diag.Diagnostics,
	configured types.Set,
	tags []cloudOnboardingTypes.Tag,
) []cloudOnboardingTypes.Tag {
	if declaresPlatformOwnedTag(ctx, diagnostics, configured) {
		return tags
	}

	configurable := make([]cloudOnboardingTypes.Tag, 0, len(tags))
	for _, tag := range tags {
		if tag.Key == platformOwnedTagKey && tag.Value == platformOwnedTagValue {
			continue
		}
		configurable = append(configurable, tag)
	}
	return configurable
}

// declaresPlatformOwnedTag reports whether the configuration itself asked for
// the platform's own tag.
//
// An unknown set is treated as not declaring it. During the create plan the
// tags are known -- they come from the configuration -- so the only unknown
// case is a value derived from something else, and guessing "declared" there
// would put a tag into state that the plan may not contain.
func declaresPlatformOwnedTag(ctx context.Context, diagnostics *diag.Diagnostics, configured types.Set) bool {
	if configured.IsNull() || configured.IsUnknown() {
		return false
	}

	var declared []cloudOnboardingTypes.Tag
	diagnostics.Append(configured.ElementsAs(ctx, &declared, false)...)
	if diagnostics.HasError() {
		return false
	}

	for _, tag := range declared {
		if tag.Key == platformOwnedTagKey && tag.Value == platformOwnedTagValue {
			return true
		}
	}
	return false
}

// reportedManualDetailsObject converts a read reply's manual_details into the
// computed object. It maps member by member: the read and write shapes do not
// agree on which keys exist, so the two cannot share a conversion.
func reportedManualDetailsObject(ctx context.Context, diagnostics *diag.Diagnostics, details *cloudOnboardingTypes.ManualDetailsRead) types.Object {
	attributeTypes := ManualDetailsReadAttributeTypes()

	if details == nil {
		return types.ObjectNull(attributeTypes)
	}

	value := manualDetailsRead{
		AccountID:             details.AccountID,
		AccountName:           details.AccountName,
		OrganizationID:        details.OrganizationID,
		RoleARN:               details.RoleARN,
		ExternalID:            details.ExternalID,
		OutpostScannerRoleARN: details.OutpostScannerRoleARN,

		TenantID:                            details.TenantID,
		ClientID:                            details.ClientID,
		ResourceGroupName:                   details.ResourceGroupName,
		ResourceGroupLocation:               details.ResourceGroupLocation,
		ADSImageGalleryResourceID:           details.ADSImageGalleryResourceID,
		EventHubName:                        details.EventHubName,
		EventHubResourceGroupName:           details.EventHubResourceGroupName,
		EventHubNamespace:                   details.EventHubNamespace,
		AzureAuditEventHubConsumerGroupName: details.AzureAuditEventHubConsumerGroupName,
		StorageAccountName:                  details.StorageAccountName,
		EventHubAuditClientID:               details.EventHubAuditClientID,
	}

	object, diags := types.ObjectValueFrom(ctx, attributeTypes, value)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return types.ObjectNull(attributeTypes)
	}

	return object
}

// refreshedAdditionalCapabilities keeps only the toggles the write endpoints
// accept. The reply carries further keys; storing them would offer the
// practitioner a value they cannot configure.
func refreshedAdditionalCapabilities(ctx context.Context, diagnostics *diag.Diagnostics, capabilities *cloudOnboardingTypes.AdditionalCapabilitiesRead) types.Object {
	attributeTypes := ManualAdditionalCapabilitiesAttributeTypes()

	if capabilities == nil {
		return types.ObjectNull(attributeTypes)
	}

	value := manualAdditionalCapabilities{
		Automation:                    capabilities.Automation,
		AutomationLogLevel:            capabilities.AutomationLogLevel,
		XSIAMAnalytics:                capabilities.XSIAMAnalytics,
		RegistryScanning:              capabilities.RegistryScanning,
		KubernetesSecurity:            capabilities.KubernetesSecurity,
		ServerlessScanning:            capabilities.ServerlessScanning,
		AgentlessDiskScanning:         capabilities.AgentlessDiskScanning,
		DataSecurityPostureManagement: capabilities.DataSecurityPostureManagement,
		UploadFilesToWildfire:         capabilities.UploadFilesToWildfire,
	}

	// The option set is reported as well as accepted, so a refresh can record
	// it. Leaving it out would make the applied value differ from the planned
	// one for any configuration that sets it.
	if capabilities.RegistryScanningOptions != nil {
		optionType := capabilities.RegistryScanningOptions.Type
		options := &manualRegistryScanningOptions{Type: &optionType}
		if capabilities.RegistryScanningOptions.LastDays != nil {
			lastDays := int64(*capabilities.RegistryScanningOptions.LastDays)
			options.LastDays = &lastDays
		}
		value.RegistryScanningOptions = options
	}

	object, diags := types.ObjectValueFrom(ctx, attributeTypes, value)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return types.ObjectNull(attributeTypes)
	}

	return object
}

// refreshedCollectionConfiguration maps the reported audit-log configuration.
//
// cloudtrail_role and sqs_url are accepted on write but never reported, so
// there is nothing to refresh them from. The configured values are carried
// through unchanged rather than being nulled, which would otherwise show as
// drift on every plan.
func refreshedCollectionConfiguration(ctx context.Context, diagnostics *diag.Diagnostics, configured types.Object, collection *cloudOnboardingTypes.CollectionConfigurationRead) types.Object {
	attributeTypes := ManualCollectionConfigurationAttributeTypes()

	if collection == nil {
		return types.ObjectNull(attributeTypes)
	}

	// Nothing is carried forward from the configured object any more. It used
	// to supply cloudtrail_role and sqs_url, which the platform never reports
	// back -- but it also never accepted them here, so the schema no longer
	// offers them and every remaining member is refreshed from the response.
	enabled := collection.AuditLogs.Enabled
	dataEvents := collection.AuditLogs.DataEvents
	collectionMethod := collection.AuditLogs.CollectionMethod

	value := manualCollectionConfiguration{
		AuditLogs: &manualAuditLogs{
			Enabled:            &enabled,
			DataEvents:         &dataEvents,
			CollectionMethod:   &collectionMethod,
			IsControlTowerBYOB: collection.AuditLogs.IsControlTowerBYOB,
		},
	}

	object, diags := types.ObjectValueFrom(ctx, attributeTypes, value)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return types.ObjectNull(attributeTypes)
	}

	return object
}

// refreshedScopeModifications maps the reported scope restriction.
func refreshedScopeModifications(ctx context.Context, diagnostics *diag.Diagnostics, configured types.Object, modifications *cloudOnboardingTypes.ScopeModificationsRead) types.Object {
	attributeTypes := ManualScopeModificationsAttributeTypes()

	// A reply that says nothing about scope leaves nothing to refresh from.
	// Which value belongs in state then depends on whether the configuration
	// supplied one, and the two cases fail in opposite directions.
	//
	// The attribute is Optional+Computed, so a configuration that does not
	// mention it plans as unknown. Handing that unknown back writes it into
	// state, and Terraform rejects an apply that returns an unknown value with
	// "Provider returned invalid result object after apply" -- after the
	// connector has been created, which leaves it live with no state. Absence
	// is resolved to null, as the sibling refreshers already do.
	//
	// A configured value is known, so the plan holds it and Terraform requires
	// the applied state to match. Nulling it would be the mirrored defect --
	// "Provider produced inconsistent result after apply" -- and would erase a
	// value the practitioner wrote, so a known value is carried through.
	if modifications == nil {
		if configured.IsUnknown() {
			return types.ObjectNull(attributeTypes)
		}
		return configured
	}

	value := manualScopeModifications{}
	if modifications.Accounts != nil {
		value.Accounts = &manualScopeAccounts{
			Enabled:    modifications.Accounts.Enabled,
			Type:       modifications.Accounts.Type,
			AccountIDs: modifications.Accounts.AccountIDs,
		}
	}
	if modifications.Projects != nil {
		value.Projects = &manualScopeProjects{
			Enabled:    modifications.Projects.Enabled,
			Type:       modifications.Projects.Type,
			ProjectIDs: modifications.Projects.ProjectIDs,
		}
	}
	if modifications.Subscriptions != nil {
		value.Subscriptions = &manualScopeSubscriptions{
			Enabled:         modifications.Subscriptions.Enabled,
			Type:            modifications.Subscriptions.Type,
			SubscriptionIDs: modifications.Subscriptions.SubscriptionIDs,
		}
	}
	if modifications.Regions != nil {
		value.Regions = &scopeModificationRegions{
			Enabled: modifications.Regions.Enabled,
			Type:    modifications.Regions.Type,
			Regions: modifications.Regions.Regions,
		}
	}

	object, diags := types.ObjectValueFrom(ctx, attributeTypes, value)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return types.ObjectNull(attributeTypes)
	}

	return object
}
