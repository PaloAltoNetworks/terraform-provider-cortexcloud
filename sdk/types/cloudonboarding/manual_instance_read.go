// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ----------------------------------------------------------------------------
// Manual Cloud Onboarding — read and delete
//
// These types back get_edit_instance_details and delete_instance_template.
//
// The read shape is deliberately a separate set of types from the write shape
// in manual_instance.go. The two are not symmetric: an accepted write body and
// the reply of a read do not agree on which keys exist. The differences below
// are each grounded in captured traffic, not inferred.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Get edit instance details
// ----------------------------------------------------------------------------

// GetEditInstanceDetailsRequest is the request for reading the editable
// configuration of a connector instance.
type GetEditInstanceDetailsRequest struct {
	instanceID string
}

// NewGetEditInstanceDetailsRequest creates a new GetEditInstanceDetailsRequest.
// instanceID is the only field the endpoint accepts.
func NewGetEditInstanceDetailsRequest(instanceID string) *GetEditInstanceDetailsRequest {
	return &GetEditInstanceDetailsRequest{instanceID: instanceID}
}

// MarshalJSON implements the json.Marshaler interface.
func (r *GetEditInstanceDetailsRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		InstanceID string `json:"id"`
	}

	return json.Marshal(&alias{InstanceID: r.instanceID})
}

// GetEditInstanceDetailsResponse is the reply of get_edit_instance_details.
//
// Callers must not treat a successful response as proof that the requested
// instance exists: the endpoint has been observed returning identical payloads
// for different identifiers. Use the returned fields, not the call's success,
// to decide what a connector is.
type GetEditInstanceDetailsResponse struct {
	Fields InstanceEditFields `json:"fields"`

	// PendingChanges has only ever been observed as an empty object, so its
	// contents are unmodelled and left as raw JSON.
	PendingChanges json.RawMessage `json:"pending_changes,omitempty"`
}

// InstanceEditFields is the editable configuration of a connector instance as
// returned by the read endpoint.
//
// Fields observed in every captured reply are plain values; fields that appear
// only for some providers or configurations are pointers so that absent and
// zero remain distinguishable.
type InstanceEditFields struct {
	InstanceName        string      `json:"instance_name"`
	CloudProvider       string      `json:"cloud_provider"`
	Scope               string      `json:"scope"`
	ScanMode            string      `json:"scan_mode"`
	ProvisioningMethod  string      `json:"provisioning_method"`
	ScanEnvID           string      `json:"scan_env_id"`
	CloudPartition      string      `json:"cloud_partition"`
	UpgradeAvailable    bool        `json:"upgrade_available"`
	CustomResourcesTags ReadTagList `json:"custom_resources_tags"`

	AccountDetails          *InstanceAccountDetails      `json:"account_details,omitempty"`
	ManualDetails           *ManualDetailsRead           `json:"manual_details,omitempty"`
	AdditionalCapabilities  *AdditionalCapabilitiesRead  `json:"additional_capabilities,omitempty"`
	CollectionConfiguration *CollectionConfigurationRead `json:"collection_configuration,omitempty"`
	ScopeModifications      *ScopeModificationsRead      `json:"scope_modifications,omitempty"`
	GCPWorkspace            *InstanceGCPWorkspaceRead    `json:"gcp_workspace,omitempty"`
}

// ReadTagList is a list of tags as the read endpoint reports it.
//
// It exists because the endpoint renders custom_resources_tags in two
// different JSON shapes depending on whether the connector has any tags:
//
//	a connector with tags  ->  [{"key": "...", "value": "..."}]
//	a connector with none  ->  {}
//
// The second is an object where the first is an array, so a plain []Tag
// cannot decode it. Without this type a connector whose tags have been
// cleared cannot be read at all, and every plan, apply and refresh against it
// fails on a JSON error naming a field the practitioner never touched.
//
// The provider itself cannot produce that state: custom_resources_tags
// declares SizeAtLeast(1), and an omitted or empty set is dropped from the
// request body rather than sent as []. A connector can still reach it through
// the console, another API client, or an instance onboarded outside Terraform
// and then imported -- none of which a schema validator can defend against,
// because the drift happens on the platform rather than in configuration.
type ReadTagList []Tag

// UnmarshalJSON decodes either shape the read endpoint uses.
//
// Only the three spellings of emptiness are tolerated -- {}, null and an empty
// document. Anything else is still decoded as an array and still fails, so a
// genuine change in the reply's shape is reported rather than silently read as
// "no tags".
func (t *ReadTagList) UnmarshalJSON(data []byte) error {
	switch string(bytes.TrimSpace(data)) {
	case "", "null", "{}":
		*t = nil
		return nil
	}

	// The alias sheds the custom method, so this is the ordinary slice
	// decoding rather than a recursive call into UnmarshalJSON.
	var tags []Tag
	if err := json.Unmarshal(data, &tags); err != nil {
		return fmt.Errorf("decoding custom_resources_tags: %w", err)
	}

	*t = tags
	return nil
}

// InstanceAccountDetails is the resolved account identity of a connector. It
// is returned by the read endpoint only; no write endpoint accepts it.
type InstanceAccountDetails struct {
	AccountID      string `json:"account_id"`
	AccountName    string `json:"account_name"`
	AccountGroup   string `json:"account_group"`
	CSPOrgID       string `json:"csp_org_id"`
	OrganizationID string `json:"organization_id"`
}

// ManualDetailsRead is the provider-specific identity of a manually onboarded
// connector as returned by the read endpoint.
//
// This is intentionally not ManualDetails. Two differences are load-bearing:
//
//   - ClientID is returned here but is rejected on write: every captured create
//     that sent client_id was refused with HTTP 422.
//   - SubscriptionID is accepted on write but has never appeared in a reply.
//
// Round-tripping a read straight back into a write is therefore not safe.
//
// The GCP members are weaker evidence than the rest of this type. Every
// captured get_edit_instance_details reply is for an AWS or Azure connector, so
// no GCP read shape has been observed. They are modelled from the write shape
// the identifiers endpoint publishes, on the same basis as their counterparts
// in ManualDetails. For the two providers where both a read-back and an offer
// exist, the read returns nearly all of the offered keys — 6 of 8 for AWS, 10
// of 11 for Azure — which makes omitting them the larger risk: an unmodelled
// key is discarded silently, whereas a modelled key that never arrives simply
// stays nil.
type ManualDetailsRead struct {
	// AWS.
	AccountID             *string `json:"account_id,omitempty"`
	AccountName           *string `json:"account_name,omitempty"`
	OrganizationID        *string `json:"organization_id,omitempty"`
	RoleARN               *string `json:"role_arn,omitempty"`
	ExternalID            *string `json:"external_id,omitempty"`
	OutpostScannerRoleARN *string `json:"outpost_scanner_role_arn,omitempty"`

	// GCP. Inferred from the identifiers offer, not from a captured reply; see
	// the type comment. AccountGroup here is the manual_details member, not the
	// account_group on InstanceAccountDetails.
	ServiceAccountEmail               *string `json:"service_account_email,omitempty"`
	OutpostScannerServiceAccountEmail *string `json:"outpost_scanner_service_account_email,omitempty"`
	AuditServiceAccountEmail          *string `json:"audit_service_account_email,omitempty"`
	AuditPubSubSubscriptionID         *string `json:"audit_pubsub_subscription_id,omitempty"`
	AccountGroup                      *string `json:"account_group,omitempty"`

	// Azure.
	TenantID                            *string `json:"tenant_id,omitempty"`
	ClientID                            *string `json:"client_id,omitempty"`
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

// AdditionalCapabilitiesRead is the capability set as returned by the read
// endpoint.
//
// The seven toggles it shares with ManualAdditionalCapabilities appear in every
// captured reply. The remaining fields are returned for some connectors only
// and are not accepted by the manual write endpoints.
type AdditionalCapabilitiesRead struct {
	Automation                    *bool `json:"automation,omitempty"`
	XSIAMAnalytics                *bool `json:"xsiam_analytics,omitempty"`
	RegistryScanning              *bool `json:"registry_scanning,omitempty"`
	KubernetesSecurity            *bool `json:"kubernetes_security,omitempty"`
	ServerlessScanning            *bool `json:"serverless_scanning,omitempty"`
	AgentlessDiskScanning         *bool `json:"agentless_disk_scanning,omitempty"`
	DataSecurityPostureManagement *bool `json:"data_security_posture_management,omitempty"`

	AutomationLogLevel      *string                  `json:"automation_log_level,omitempty"`
	UploadFilesToWildfire   *bool                    `json:"upload_files_to_wildfire,omitempty"`
	RegistryScanningOptions *RegistryScanningOptions `json:"registry_scanning_options,omitempty"`
}

// CollectionConfigurationRead is the audit-log collection configuration as
// returned by the read endpoint.
type CollectionConfigurationRead struct {
	AuditLogs AuditLogsRead `json:"audit_logs"`
}

// AuditLogsRead is the audit-log configuration of a connector.
//
// It differs from ManualAuditLogsConfiguration by carrying CustomCollectors,
// which is returned by the read endpoint and is not part of any accepted write
// body.
type AuditLogsRead struct {
	Enabled            bool                 `json:"enabled"`
	DataEvents         bool                 `json:"data_events"`
	CollectionMethod   string               `json:"collection_method"`
	IsControlTowerBYOB *bool                `json:"is_control_tower_byob,omitempty"`
	CustomCollectors   *AuditLogsCollectors `json:"custom_collectors,omitempty"`
}

// AuditLogsCollectors describes the custom audit-log collectors of a
// connector. Only the Azure Event Hub form has been observed; Namespace is
// spelled without the eventhub_ prefix that the write shape uses for the same
// value.
type AuditLogsCollectors struct {
	EventHubName              *string `json:"eventhub_name,omitempty"`
	EventHubResourceGroupName *string `json:"eventhub_resource_group_name,omitempty"`
	Namespace                 *string `json:"namespace,omitempty"`
}

// ScopeModificationsRead is the scope restriction of a connector as returned
// by the read endpoint.
type ScopeModificationsRead struct {
	Accounts        *ScopeModificationGeneric `json:"accounts,omitempty"`
	Projects        *ScopeModificationGeneric `json:"projects,omitempty"`
	Subscriptions   *ScopeModificationGeneric `json:"subscriptions,omitempty"`
	Regions         *ScopeModificationRegions `json:"regions,omitempty"`
	OnboardOnlyMode *bool                     `json:"onboard_only_mode,omitempty"`
}

// InstanceGCPWorkspaceRead is the GCP workspace configuration of a connector.
// The object is present in every captured reply but is empty for non-GCP
// connectors, so Enabled is a pointer.
//
// The contract describes this object as carrying customer_ids and enabled. Only
// enabled has been observed — and, oddly, on Azure connectors. CustomerIDs is
// modelled from the contract alone so that the value is not dropped if it does
// arrive; it has never appeared in captured traffic.
type InstanceGCPWorkspaceRead struct {
	Enabled     *bool    `json:"enabled,omitempty"`
	CustomerIDs []string `json:"customer_ids,omitempty"`
}

// ----------------------------------------------------------------------------
// Delete instance template
// ----------------------------------------------------------------------------

// DeleteInstanceTemplateRequest is the request for deleting an instance
// template.
type DeleteInstanceTemplateRequest struct {
	templateID string
}

// NewDeleteInstanceTemplateRequest creates a new DeleteInstanceTemplateRequest.
// templateID is the only field the endpoint accepts.
func NewDeleteInstanceTemplateRequest(templateID string) *DeleteInstanceTemplateRequest {
	return &DeleteInstanceTemplateRequest{templateID: templateID}
}

// MarshalJSON implements the json.Marshaler interface.
func (r *DeleteInstanceTemplateRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		TemplateID string `json:"template_id"`
	}

	return json.Marshal(&alias{TemplateID: r.templateID})
}
