// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import "encoding/json"

// ----------------------------------------------------------------------------
// Manual Cloud Onboarding
//
// These types back the manual onboarding endpoints (create_instance and
// edit_manual_instance). They are deliberately separate from the automated
// template flow (create_instance_template / edit_instance): the two schemas are
// disjoint, and each endpoint rejects the fields the other requires.
// ----------------------------------------------------------------------------

// ManualDetails carries the provider-specific identifiers of a manually
// onboarded connector. The API shapes this object per cloud provider, so every
// field is a pointer and is omitted when unset. Unknown keys are silently
// discarded by the API, so only names observed in accepted traffic appear here.
//
// The GCP members are the one exception to "observed in accepted traffic". No
// GCP create or edit has been accepted: the only captured GCP create sent real
// values and returned HTTP 500. Their names instead come from
// get_manual_connector_identifiers, which the API documents as the source of
// this object — "Pass the manual_details object returned by the Get Manual
// Connector Identifiers call" — and which returns them as a template of empty
// strings. 18 captured GCP calls to that endpoint, covering all three scopes
// and both audit settings, agree on the same seven keys.
type ManualDetails struct {
	// AWS.
	AccountID             *string `json:"account_id,omitempty"`
	AccountName           *string `json:"account_name,omitempty"`
	OrganizationID        *string `json:"organization_id,omitempty"`
	RoleARN               *string `json:"role_arn,omitempty"`
	ExternalID            *string `json:"external_id,omitempty"`
	OutpostScannerRoleARN *string `json:"outpost_scanner_role_arn,omitempty"`
	CloudTrailRole        *string `json:"cloudtrail_role,omitempty"`
	SQSURL                *string `json:"sqs_url,omitempty"`

	// GCP.
	//
	// AccountID and OrganizationID above are shared with the other providers;
	// for GCP they carry the project ID and the organization number.
	//
	// AccountGroup is offered only for ACCOUNT_GROUP scope. It is a distinct
	// field from the account_group on InstanceAccountDetails, which belongs to
	// the read-only account_details object.
	//
	// The two audit fields are offered only when audit-log collection is
	// enabled on the identifiers request.
	//
	// The suffix is _email on all three service-account members. The _mail
	// spelling seen alongside these belongs to the sibling identifiers object
	// (outpost_service_account_mail, saas_collector_service_account_mail) and
	// has never appeared inside manual_details.
	ServiceAccountEmail               *string `json:"service_account_email,omitempty"`
	OutpostScannerServiceAccountEmail *string `json:"outpost_scanner_service_account_email,omitempty"`
	AuditServiceAccountEmail          *string `json:"audit_service_account_email,omitempty"`
	AuditPubSubSubscriptionID         *string `json:"audit_pubsub_subscription_id,omitempty"`
	AccountGroup                      *string `json:"account_group,omitempty"`

	// Azure.
	TenantID                            *string `json:"tenant_id,omitempty"`
	SubscriptionID                      *string `json:"subscription_id,omitempty"`
	ResourceGroupName                   *string `json:"resource_group_name,omitempty"`
	ResourceGroupLocation               *string `json:"resource_group_location,omitempty"`
	ADSImageGalleryResourceID           *string `json:"ads_image_gallery_resource_id,omitempty"`
	EventHubName                        *string `json:"eventhub_name,omitempty"`
	EventHubResourceGroupName           *string `json:"eventhub_resource_group_name,omitempty"`
	EventHubNamespace                   *string `json:"eventhub_namespace,omitempty"`
	AzureAuditEventHubConsumerGroupName *string `json:"azure_audit_eventhub_consumer_group_name,omitempty"`
	StorageAccountName                  *string `json:"storage_account_name,omitempty"`
	EventHubAuditClientID               *string `json:"eventhub_audit_client_id,omitempty"`
}

// ManualAdditionalCapabilities holds the security capability toggles accepted
// by the manual onboarding endpoints. The create endpoint accepts an empty
// object and defaults the unset toggles.
//
// The toggles are not all independent. RegistryScanning and
// RegistryScanningOptions are validated as a pair, and sending one without the
// other is refused:
//
//	422 {"type": "value_error", "loc": [],
//	     "msg": "Value error, Registry scanning and registry scanning options
//	             must both be provided together or neither should be provided"}
//
// Automation and AutomationLogLevel are governed by the same rule:
//
//	422 "Value error, Automation and Automation log level must both be provided
//	     together or neither should be provided"
//
// AutomationLogLevel is validated against a closed set; an unsupported value is
// refused with "Input should be 'OFF', 'Debug' or 'Verbose'".
type ManualAdditionalCapabilities struct {
	Automation                    *bool                    `json:"automation,omitempty"`
	AutomationLogLevel            *string                  `json:"automation_log_level,omitempty"`
	XSIAMAnalytics                *bool                    `json:"xsiam_analytics,omitempty"`
	RegistryScanning              *bool                    `json:"registry_scanning,omitempty"`
	RegistryScanningOptions       *RegistryScanningOptions `json:"registry_scanning_options,omitempty"`
	KubernetesSecurity            *bool                    `json:"kubernetes_security,omitempty"`
	ServerlessScanning            *bool                    `json:"serverless_scanning,omitempty"`
	AgentlessDiskScanning         *bool                    `json:"agentless_disk_scanning,omitempty"`
	DataSecurityPostureManagement *bool                    `json:"data_security_posture_management,omitempty"`
	UploadFilesToWildfire         *bool                    `json:"upload_files_to_wildfire,omitempty"`
}

// ManualCollectionConfiguration is the audit-log collection configuration.
type ManualCollectionConfiguration struct {
	AuditLogs ManualAuditLogsConfiguration `json:"audit_logs"`
}

// ManualAuditLogsConfiguration configures audit-log collection. Enabled and
// DataEvents are always marshalled because accepted traffic always carries
// them; IsControlTowerBYOB is AWS-only and omitted when unset.
type ManualAuditLogsConfiguration struct {
	Enabled            bool    `json:"enabled"`
	DataEvents         bool    `json:"data_events"`
	CollectionMethod   string  `json:"collection_method,omitempty"`
	IsControlTowerBYOB *bool   `json:"is_control_tower_byob,omitempty"`
	CloudTrailRole     *string `json:"cloudtrail_role,omitempty"`
	SQSURL             *string `json:"sqs_url,omitempty"`
}

// ManualScopeModifications restricts the scope of a manual connector. It
// differs from ScopeModifications by carrying OnboardOnlyMode, which the manual
// edit endpoint accepts and the template endpoints do not.
type ManualScopeModifications struct {
	Accounts        *ScopeModificationGeneric `json:"accounts,omitempty"`
	Projects        *ScopeModificationGeneric `json:"projects,omitempty"`
	Subscriptions   *ScopeModificationGeneric `json:"subscriptions,omitempty"`
	Regions         *ScopeModificationRegions `json:"regions,omitempty"`
	OnboardOnlyMode *bool                     `json:"onboard_only_mode,omitempty"`
}

// ----------------------------------------------------------------------------
// Create
// ----------------------------------------------------------------------------

// CreateManualInstanceRequest is the request for creating a manually onboarded
// connector instance.
type CreateManualInstanceRequest struct {
	cloudProvider           string
	scope                   string
	scanMode                string
	manualDetails           ManualDetails
	additionalCapabilities  ManualAdditionalCapabilities
	collectionConfiguration ManualCollectionConfiguration
	scopeModifications      ManualScopeModifications
	customResourcesTags     []Tag
	instanceName            *string
	cloudPartition          *string
	outpostID               *string
}

// CreateManualInstanceRequestOption defines a functional option for CreateManualInstanceRequest.
type CreateManualInstanceRequestOption func(*CreateManualInstanceRequest)

// NewCreateManualInstanceRequest creates a new CreateManualInstanceRequest.
// cloudProvider, scope, scanMode and manualDetails are required by the API.
func NewCreateManualInstanceRequest(cloudProvider, scope, scanMode string, manualDetails ManualDetails, options ...CreateManualInstanceRequestOption) *CreateManualInstanceRequest {
	r := &CreateManualInstanceRequest{
		cloudProvider: cloudProvider,
		scope:         scope,
		scanMode:      scanMode,
		manualDetails: manualDetails,
	}
	for _, option := range options {
		option(r)
	}
	return r
}

// WithManualCreateInstanceName sets the display name for the request.
func WithManualCreateInstanceName(instanceName string) CreateManualInstanceRequestOption {
	return func(r *CreateManualInstanceRequest) {
		r.instanceName = &instanceName
	}
}

// WithManualCreateAdditionalCapabilities sets the capability toggles for the request.
func WithManualCreateAdditionalCapabilities(additionalCapabilities ManualAdditionalCapabilities) CreateManualInstanceRequestOption {
	return func(r *CreateManualInstanceRequest) {
		r.additionalCapabilities = additionalCapabilities
	}
}

// WithManualCreateCollectionConfiguration sets the collection configuration for the request.
func WithManualCreateCollectionConfiguration(collectionConfiguration ManualCollectionConfiguration) CreateManualInstanceRequestOption {
	return func(r *CreateManualInstanceRequest) {
		r.collectionConfiguration = collectionConfiguration
	}
}

// WithManualCreateScopeModifications sets the scope modifications for the request.
func WithManualCreateScopeModifications(scopeModifications ManualScopeModifications) CreateManualInstanceRequestOption {
	return func(r *CreateManualInstanceRequest) {
		r.scopeModifications = scopeModifications
	}
}

// WithManualCreateCustomResourcesTags sets the custom resource tags for the request.
func WithManualCreateCustomResourcesTags(customResourcesTags []Tag) CreateManualInstanceRequestOption {
	return func(r *CreateManualInstanceRequest) {
		r.customResourcesTags = customResourcesTags
	}
}

// WithManualCreateCloudPartition sets the cloud partition for the request.
func WithManualCreateCloudPartition(cloudPartition string) CreateManualInstanceRequestOption {
	return func(r *CreateManualInstanceRequest) {
		r.cloudPartition = &cloudPartition
	}
}

// WithManualCreateOutpostID sets the outpost ID, required for OUTPOST scan mode.
func WithManualCreateOutpostID(outpostID string) CreateManualInstanceRequestOption {
	return func(r *CreateManualInstanceRequest) {
		r.outpostID = &outpostID
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (r *CreateManualInstanceRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		CloudProvider           string                        `json:"cloud_provider"`
		Scope                   string                        `json:"scope"`
		ScanMode                string                        `json:"scan_mode"`
		ManualDetails           ManualDetails                 `json:"manual_details"`
		AdditionalCapabilities  ManualAdditionalCapabilities  `json:"additional_capabilities"`
		CollectionConfiguration ManualCollectionConfiguration `json:"collection_configuration"`
		ScopeModifications      ManualScopeModifications      `json:"scope_modifications"`
		InstanceName            *string                       `json:"instance_name,omitempty"`
		CloudPartition          *string                       `json:"cloud_partition,omitempty"`
		OutpostID               *string                       `json:"outpost_id,omitempty"`
		CustomResourcesTags     []Tag                         `json:"custom_resources_tags,omitempty"`
	}

	return json.Marshal(&alias{
		CloudProvider:           r.cloudProvider,
		Scope:                   r.scope,
		ScanMode:                r.scanMode,
		ManualDetails:           r.manualDetails,
		AdditionalCapabilities:  r.additionalCapabilities,
		CollectionConfiguration: r.collectionConfiguration,
		ScopeModifications:      r.scopeModifications,
		InstanceName:            r.instanceName,
		CloudPartition:          r.cloudPartition,
		OutpostID:               r.outpostID,
		CustomResourcesTags:     r.customResourcesTags,
	})
}

// CreateManualInstanceResponse is the response for creating a manual connector
// instance. The API returns the new connector's identifier as reply.id.
type CreateManualInstanceResponse struct {
	ID string `json:"id"`
}

// ----------------------------------------------------------------------------
// Edit
// ----------------------------------------------------------------------------

// EditManualInstanceRequest is the request for editing a manually onboarded
// connector instance.
//
// The edit is partial: any optional field left unset retains its previous
// server-side value rather than being cleared. Callers should therefore send
// the complete desired state instead of a computed diff.
type EditManualInstanceRequest struct {
	instanceID              string
	cloudProvider           string
	scope                   string
	scanMode                string
	manualDetails           ManualDetails
	additionalCapabilities  ManualAdditionalCapabilities
	collectionConfiguration ManualCollectionConfiguration
	scopeModifications      ManualScopeModifications
	customResourcesTags     []Tag
	instanceName            *string
	cloudPartition          *string
	outpostID               *string
}

// EditManualInstanceRequestOption defines a functional option for EditManualInstanceRequest.
type EditManualInstanceRequestOption func(*EditManualInstanceRequest)

// NewEditManualInstanceRequest creates a new EditManualInstanceRequest.
//
// cloudProvider, scope and scanMode are immutable server-side but must still be
// supplied at their current values: omitting cloudProvider fails the request,
// and changing it is rejected.
func NewEditManualInstanceRequest(instanceID, cloudProvider, scope, scanMode string, manualDetails ManualDetails, options ...EditManualInstanceRequestOption) *EditManualInstanceRequest {
	r := &EditManualInstanceRequest{
		instanceID:    instanceID,
		cloudProvider: cloudProvider,
		scope:         scope,
		scanMode:      scanMode,
		manualDetails: manualDetails,
	}
	for _, option := range options {
		option(r)
	}
	return r
}

// WithManualEditInstanceName sets the display name for the request.
func WithManualEditInstanceName(instanceName string) EditManualInstanceRequestOption {
	return func(r *EditManualInstanceRequest) {
		r.instanceName = &instanceName
	}
}

// WithManualEditAdditionalCapabilities sets the capability toggles for the request.
func WithManualEditAdditionalCapabilities(additionalCapabilities ManualAdditionalCapabilities) EditManualInstanceRequestOption {
	return func(r *EditManualInstanceRequest) {
		r.additionalCapabilities = additionalCapabilities
	}
}

// WithManualEditCollectionConfiguration sets the collection configuration for the request.
func WithManualEditCollectionConfiguration(collectionConfiguration ManualCollectionConfiguration) EditManualInstanceRequestOption {
	return func(r *EditManualInstanceRequest) {
		r.collectionConfiguration = collectionConfiguration
	}
}

// WithManualEditScopeModifications sets the scope modifications for the request.
func WithManualEditScopeModifications(scopeModifications ManualScopeModifications) EditManualInstanceRequestOption {
	return func(r *EditManualInstanceRequest) {
		r.scopeModifications = scopeModifications
	}
}

// WithManualEditCustomResourcesTags sets the custom resource tags for the request.
func WithManualEditCustomResourcesTags(customResourcesTags []Tag) EditManualInstanceRequestOption {
	return func(r *EditManualInstanceRequest) {
		r.customResourcesTags = customResourcesTags
	}
}

// WithManualEditCloudPartition sets the cloud partition for the request.
func WithManualEditCloudPartition(cloudPartition string) EditManualInstanceRequestOption {
	return func(r *EditManualInstanceRequest) {
		r.cloudPartition = &cloudPartition
	}
}

// WithManualEditOutpostID sets the outpost ID, required for OUTPOST scan mode.
func WithManualEditOutpostID(outpostID string) EditManualInstanceRequestOption {
	return func(r *EditManualInstanceRequest) {
		r.outpostID = &outpostID
	}
}

// MarshalJSON implements the json.Marshaler interface.
//
// cloud_provider, scope and scan_mode are intentionally marshalled without
// omitempty: the endpoint requires all three, and omitting cloud_provider
// results in a server error rather than a validation message.
func (r *EditManualInstanceRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		InstanceID              string                        `json:"id"`
		CloudProvider           string                        `json:"cloud_provider"`
		Scope                   string                        `json:"scope"`
		ScanMode                string                        `json:"scan_mode"`
		ManualDetails           ManualDetails                 `json:"manual_details"`
		AdditionalCapabilities  ManualAdditionalCapabilities  `json:"additional_capabilities"`
		CollectionConfiguration ManualCollectionConfiguration `json:"collection_configuration"`
		ScopeModifications      ManualScopeModifications      `json:"scope_modifications"`
		InstanceName            *string                       `json:"instance_name,omitempty"`
		CloudPartition          *string                       `json:"cloud_partition,omitempty"`
		OutpostID               *string                       `json:"outpost_id,omitempty"`
		CustomResourcesTags     []Tag                         `json:"custom_resources_tags,omitempty"`
	}

	return json.Marshal(&alias{
		InstanceID:              r.instanceID,
		CloudProvider:           r.cloudProvider,
		Scope:                   r.scope,
		ScanMode:                r.scanMode,
		ManualDetails:           r.manualDetails,
		AdditionalCapabilities:  r.additionalCapabilities,
		CollectionConfiguration: r.collectionConfiguration,
		ScopeModifications:      r.scopeModifications,
		InstanceName:            r.instanceName,
		CloudPartition:          r.cloudPartition,
		OutpostID:               r.outpostID,
		CustomResourcesTags:     r.customResourcesTags,
	})
}
