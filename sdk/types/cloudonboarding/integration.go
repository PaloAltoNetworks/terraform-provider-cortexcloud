// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"fmt"
	"net/url"

	//"path"
	"regexp"

	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
)

// ----------------------------------------------------------------------------
// Cloud Integration Instance Management
// ----------------------------------------------------------------------------

type IntegrationInstance struct {
	ID                      string                  `json:"id"`
	Collector               string                  `json:"collector"`
	InstanceName            string                  `json:"instance_name,omitempty"`
	AccountName             string                  `json:"account_name,omitempty"`
	Accounts                int                     `json:"accounts,omitempty"`
	Scope                   string                  `json:"scope"`
	CustomResourcesTags     []Tag                   `json:"tags"`
	Scan                    Scan                    `json:"scan"`
	Status                  string                  `json:"status"`
	CloudProvider           string                  `json:"cloud_provider"`
	SecurityCapabilities    []SecurityCapability    `json:"security_capabilities"`
	CollectionConfiguration CollectionConfiguration `json:"collection_configuration"`
	AdditionalCapabilities  AdditionalCapabilities  `json:"additional_capabilities"`
	CreationTime            int64                   `json:"creation_time,omitempty"`
	ProvisioningMethod      string                  `json:"provisioning_method,omitempty"`
	UpdateStatus            string                  `json:"update_status,omitempty"`
	UpgradeAvailable        bool                    `json:"upgrade_available,omitempty"`
	IsPendingChanges        int                     `json:"is_pending_changes,omitempty"`
	OutpostID               string                  `json:"outpost_id,omitempty"`
}

type Tag struct {
	Key   string `json:"key" tfsdk:"key"`
	Value string `json:"value" tfsdk:"value"`
}

type Scan struct {
	StatusUI   int    `json:"status_ui,omitempty" tfsdk:"status_ui"`
	OutpostID  string `json:"outpost_id,omitempty" tfsdk:"outpost_id"`
	ScanMethod string `json:"scan_method" tfsdk:"scan_method"`
}

type SecurityCapability struct {
	Name             string            `json:"name" tfsdk:"name"`
	Description      string            `json:"description" tfsdk:"description"`
	Status           int               `json:"status" tfsdk:"status"`
	LastScanCoverage *LastScanCoverage `json:"last_scan_coverage,omitempty" tfsdk:"last_scan_coverage"`
}

type LastScanCoverage struct {
	Excluded    int `json:"excluded" tfsdk:"excluded"`
	Issues      int `json:"issues" tfsdk:"issues"`
	Pending     int `json:"pending" tfsdk:"pending"`
	Success     int `json:"success" tfsdk:"success"`
	Unsupported int `json:"unsupported" tfsdk:"unsupported"`
}

type AccountDetails struct {
	OrganizationID string `json:"organization_id,omitempty" tfsdk:"organization_id"`
}

type CollectionConfiguration struct {
	AuditLogs AuditLogsConfiguration `json:"audit_logs" tfsdk:"audit_logs"`
}

type AuditLogsConfiguration struct {
	Enabled          bool   `json:"enabled" tfsdk:"enabled"`
	CollectionMethod string `json:"collection_method,omitempty" tfsdk:"collection_method"`
	DataEvents       bool   `json:"data_events" tfsdk:"data_events"`
}

type ScopeModifications struct {
	Accounts      *ScopeModificationGeneric `json:"accounts,omitempty" tfsdk:"accounts"`
	Projects      *ScopeModificationGeneric `json:"projects,omitempty" tfsdk:"projects"`
	Subscriptions *ScopeModificationGeneric `json:"subscriptions,omitempty" tfsdk:"subscriptions"`
	Regions       *ScopeModificationRegions `json:"regions,omitempty" tfsdk:"regions"`
}

type ScopeModificationGeneric struct {
	Enabled         bool      `json:"enabled" tfsdk:"enabled"`
	Type            *string   `json:"type,omitempty" tfsdk:"type"`
	AccountIDs      *[]string `json:"account_ids,omitempty" tfsdk:"account_ids"`
	ProjectIDs      *[]string `json:"project_ids,omitempty" tfsdk:"project_ids"`
	SubscriptionIDs *[]string `json:"subscription_ids,omitempty" tfsdk:"subscription_ids"`
}

type ScopeModificationRegions struct {
	Enabled bool      `json:"enabled" tfsdk:"enabled"`
	Type    *string   `json:"type,omitempty" tfsdk:"type"`
	Regions *[]string `json:"regions,omitempty" tfsdk:"regions"`
}

type DefaultScanningScope struct {
	RegistryScanningScope      RegistryScanningScope      `json:"registry_scanning_scope"`
	AgentlessDiskScanningScope AgentlessDiskScanningScope `json:"agentless_disk_scanning_scope"`
}

type RegistryScanningScope struct {
	Enabled bool `json:"enabled"`
}

type AgentlessDiskScanningScope struct {
	Enabled bool `json:"enabled"`
}

type AdditionalCapabilities struct {
	XSIAMAnalytics                *bool                    `json:"xsiam_analytics" tfsdk:"xsiam_analytics"`
	DataSecurityPostureManagement *bool                    `json:"data_security_posture_management" tfsdk:"data_security_posture_management"`
	RegistryScanning              *bool                    `json:"registry_scanning" tfsdk:"registry_scanning"`
	RegistryScanningOptions       *RegistryScanningOptions `json:"registry_scanning_options,omitempty" tfsdk:"registry_scanning_options"`
	ServerlessScanning            *bool                    `json:"serverless_scanning" tfsdk:"serverless_scanning"`
	AgentlessDiskScanning         *bool                    `json:"agentless_disk_scanning" tfsdk:"agentless_disk_scanning"`
}

type RegistryScanningOptions struct {
	Type     string `json:"type" tfsdk:"type"`
	LastDays *int   `json:"last_days,omitempty" tfsdk:"last_days"`
}

type Automated struct {
	Link         *string `json:"link" tfsdk:"automated_deployment_link"`
	TrackingGUID *string `json:"tracking_guid" tfsdk:"tracking_guid"`
}

type Manual struct {
	TF  *string `json:"TF,omitempty" tfsdk:"terraform_module_url"`
	CF  *string `json:"CF,omitempty" tfsdk:"manual_deployment_url"`
	ARM *string `json:"ARM,omitempty" tfsdk:"manual_deployment_url"`
}

// CreateIntegrationTemplateRequest is the request for creating an integration template.
type CreateIntegrationTemplateRequest struct {
	accountDetails          *AccountDetails
	additionalCapabilities  AdditionalCapabilities
	cloudProvider           string
	collectionConfiguration CollectionConfiguration
	customResourcesTags     []Tag
	instanceName            *string
	outpostID               *string
	scanMode                string
	scope                   string
	scopeModifications      ScopeModifications
}

// CreateIntegrationTemplateRequestOption defines a functional option for CreateIntegrationTemplateRequest.
type CreateIntegrationTemplateRequestOption func(*CreateIntegrationTemplateRequest)

// NewCreateIntegrationTemplateRequest creates a new CreateIntegrationTemplateRequest.
func NewCreateIntegrationTemplateRequest(options ...CreateIntegrationTemplateRequestOption) *CreateIntegrationTemplateRequest {
	r := &CreateIntegrationTemplateRequest{}
	for _, option := range options {
		option(r)
	}
	return r
}

// WithAccountDetails sets the account details for the request.
func WithAccountDetails(accountDetails *AccountDetails) CreateIntegrationTemplateRequestOption {
	return func(r *CreateIntegrationTemplateRequest) {
		r.accountDetails = accountDetails
	}
}

// WithAdditionalCapabilities sets the additional capabilities for the request.
func WithAdditionalCapabilities(additionalCapabilities AdditionalCapabilities) CreateIntegrationTemplateRequestOption {
	return func(r *CreateIntegrationTemplateRequest) {
		r.additionalCapabilities = additionalCapabilities
	}
}

// WithCloudProvider sets the cloud provider for the request.
func WithCloudProvider(cloudProvider string) CreateIntegrationTemplateRequestOption {
	return func(r *CreateIntegrationTemplateRequest) {
		r.cloudProvider = cloudProvider
	}
}

// WithCollectionConfiguration sets the collection configuration for the request.
func WithCollectionConfiguration(collectionConfiguration CollectionConfiguration) CreateIntegrationTemplateRequestOption {
	return func(r *CreateIntegrationTemplateRequest) {
		r.collectionConfiguration = collectionConfiguration
	}
}

// WithCustomResourcesTags sets the custom resources tags for the request.
func WithCustomResourcesTags(customResourcesTags []Tag) CreateIntegrationTemplateRequestOption {
	return func(r *CreateIntegrationTemplateRequest) {
		r.customResourcesTags = customResourcesTags
	}
}

// WithInstanceName sets the instance name for the request.
func WithInstanceName(instanceName string) CreateIntegrationTemplateRequestOption {
	return func(r *CreateIntegrationTemplateRequest) {
		r.instanceName = &instanceName
	}
}

// WithOutpostID sets the outpost ID for the request.
func WithOutpostID(outpostID string) CreateIntegrationTemplateRequestOption {
	return func(r *CreateIntegrationTemplateRequest) {
		r.outpostID = &outpostID
	}
}

// WithScanMode sets the scan mode for the request.
func WithScanMode(scanMode string) CreateIntegrationTemplateRequestOption {
	return func(r *CreateIntegrationTemplateRequest) {
		r.scanMode = scanMode
	}
}

// WithScope sets the scope for the request.
func WithScope(scope string) CreateIntegrationTemplateRequestOption {
	return func(r *CreateIntegrationTemplateRequest) {
		r.scope = scope
	}
}

// WithScopeModifications sets the scope modifications for the request.
func WithScopeModifications(scopeModifications ScopeModifications) CreateIntegrationTemplateRequestOption {
	return func(r *CreateIntegrationTemplateRequest) {
		r.scopeModifications = scopeModifications
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (r *CreateIntegrationTemplateRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		AccountDetails          *AccountDetails         `json:"account_details,omitempty"`
		AdditionalCapabilities  AdditionalCapabilities  `json:"additional_capabilities"`
		CloudProvider           string                  `json:"cloud_provider"`
		CollectionConfiguration CollectionConfiguration `json:"collection_configuration"`
		CustomResourcesTags     []Tag                   `json:"custom_resources_tags"`
		InstanceName            *string                 `json:"instance_name,omitempty"`
		OutpostID               *string                 `json:"scan_env_id,omitempty"`
		ScanMode                string                  `json:"scan_mode"`
		Scope                   string                  `json:"scope"`
		ScopeModifications      ScopeModifications      `json:"scope_modifications"`
	}

	var accountDetails *AccountDetails
	if r.accountDetails != nil && r.accountDetails.OrganizationID != "" {
		accountDetails = r.accountDetails
	}

	resp, marshalErr := json.Marshal(&alias{
		AccountDetails:          accountDetails,
		AdditionalCapabilities:  r.additionalCapabilities,
		CloudProvider:           r.cloudProvider,
		CollectionConfiguration: r.collectionConfiguration,
		CustomResourcesTags:     r.customResourcesTags,
		InstanceName:            r.instanceName,
		OutpostID:               r.outpostID,
		ScanMode:                r.scanMode,
		Scope:                   r.scope,
		ScopeModifications:      r.scopeModifications,
	})

	return resp, marshalErr
}

// CreateTemplateOrEditIntegrationInstanceResponse is the response for creating or editing an integration instance.
type CreateTemplateOrEditIntegrationInstanceResponse struct {
	Automated Automated `json:"automated"`
	Manual    Manual    `json:"manual"`
}

// GetCloudFormationTemplateURL parses and returns the URL to the
// CloudFormation template generated by Cortex Cloud when creating an AWS
// cloud onboarding integration template.
func (r CreateTemplateOrEditIntegrationInstanceResponse) GetCloudFormationTemplateURL() (string, error) {
	if r.Automated.Link == nil || *r.Automated.Link == "" {
		return "", fmt.Errorf("failed to extract CloudFormation template URL: reply.automated.link is empty string")
	}

	// Parse the raw URL into a URL struct
	parsedURL, err := url.Parse(*r.Automated.Link)
	if err != nil {
		return "", fmt.Errorf("error parsing raw API response URL into struct during CloudFormation template URL extraction: %w", err)
	}

	// Parse the query values from the URL struct
	queryValues, err := url.ParseQuery(parsedURL.RawFragment)
	if err != nil {
		return "", fmt.Errorf("error parsing query parameters from API response URL during CloudFormation template URL extraction: %w", err)
	}

	// Return the query value associated with the `templateURL` key
	return queryValues.Get("/stacks/quickcreate?templateURL"), nil
}

// GetTrackingGUIDFromARMURL parses and returns the created/updated
// template's ID (referred to as the Tracking GUID in the API
// response/documentation) from the ARM template URL generated by Cortex Cloud
// when creating an Azure cloud onboarding integration template.
func (r CreateTemplateOrEditIntegrationInstanceResponse) GetTrackingGUIDFromARMURL() (string, error) {
	if r.Manual.ARM == nil || *r.Manual.ARM == "" {
		return "", fmt.Errorf("failed to extract ARM template GUID: reply.manual.ARM is empty string")
	}

	// Find the GUID in the response payloads's ARM field
	re := regexp.MustCompile(`arm-([a-f0-9]{32})-`)
	matches := re.FindStringSubmatch(*r.Manual.ARM)
	if len(matches) < 1 {
		return "", fmt.Errorf("failed to find GUID in ARM template filename: %s", *r.Manual.ARM)
	}

	return matches[1], nil
}

// GetTrackingGUIDFromTerraformURL parses and returns the created/updated
// template's ID (referred to as the Tracking GUID in the API
// response/documentation) from the Terraform module URL generated by Cortex
// Cloud when creating a cloud onboarding integration template.
func (r CreateTemplateOrEditIntegrationInstanceResponse) GetTrackingGUIDFromTerraformURL() (string, error) {
	if r.Manual.TF == nil || *r.Manual.TF == "" {
		return "", fmt.Errorf("failed to extract TF module GUID: reply.manual.TF is empty string")
	}

	// Find the GUID in the response payloads's ARM field
	re := regexp.MustCompile(`tf-([a-f0-9]{32})-`)
	matches := re.FindStringSubmatch(*r.Manual.TF)
	if len(matches) < 1 {
		return "", fmt.Errorf("failed to find GUID in ARM template filename: %s", *r.Manual.ARM)
	}

	return matches[1], nil
}

// GetIntegrationInstanceRequest is the request for getting integration instance details.
type GetIntegrationInstanceRequest struct {
	instanceID string
}

// NewGetIntegrationInstanceRequest creates a new GetIntegrationInstanceRequest.
func NewGetIntegrationInstanceRequest(instanceID string) *GetIntegrationInstanceRequest {
	return &GetIntegrationInstanceRequest{
		instanceID: instanceID,
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (r *GetIntegrationInstanceRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		InstanceID string `json:"id"`
	}

	return json.Marshal(&alias{
		InstanceID: r.instanceID,
	})
}

// GetIntegrationInstanceResponse is the response for getting integration instance details.
type GetIntegrationInstanceResponse struct {
	ID                      string               `json:"id"`
	Collector               string               `json:"collector"`
	InstanceName            string               `json:"instance_name"`
	Scope                   string               `json:"scope"`
	Tags                    []Tag                `json:"tags"`
	Scan                    Scan                 `json:"scan"`
	Status                  string               `json:"status"`
	CloudProvider           string               `json:"cloud_provider"`
	SecurityCapabilities    []SecurityCapability `json:"security_capabilities"`
	CollectionConfiguration string               `json:"collection_configuration"`
	AdditionalCapabilities  string               `json:"additional_capabilities"`
	UpgradeAvailable        bool                 `json:"upgrade_available,omitempty"`
}

func (r GetIntegrationInstanceResponse) Marshal() (IntegrationInstance, error) {
	var collectionConfiguration CollectionConfiguration
	err := json.Unmarshal([]byte(r.CollectionConfiguration), &collectionConfiguration)
	if err != nil {
		return IntegrationInstance{}, err
	}

	var additionalCapabilities AdditionalCapabilities
	err = json.Unmarshal([]byte(r.AdditionalCapabilities), &additionalCapabilities)
	if err != nil {
		return IntegrationInstance{}, err
	}

	marshalledResponse := IntegrationInstance{
		ID:                      r.ID,
		Collector:               r.Collector,
		InstanceName:            r.InstanceName,
		Scope:                   r.Scope,
		CustomResourcesTags:     r.Tags,
		Scan:                    r.Scan,
		UpgradeAvailable:        r.UpgradeAvailable,
		Status:                  r.Status,
		CloudProvider:           r.CloudProvider,
		SecurityCapabilities:    r.SecurityCapabilities,
		CollectionConfiguration: collectionConfiguration,
		AdditionalCapabilities:  additionalCapabilities,
	}

	return marshalledResponse, nil
}

// ListIntegrationInstancesRequest is the request for listing integration instances.
type ListIntegrationInstancesRequest struct {
	filterData filterTypes.FilterData
}

// ListIntegrationInstancesRequestOption defines a functional option for ListIntegrationInstancesRequest.
type ListIntegrationInstancesRequestOption func(*ListIntegrationInstancesRequest)

// NewListIntegrationInstancesRequest creates a new ListIntegrationInstancesRequest.
func NewListIntegrationInstancesRequest(options ...ListIntegrationInstancesRequestOption) *ListIntegrationInstancesRequest {
	r := &ListIntegrationInstancesRequest{}
	for _, option := range options {
		option(r)
	}
	return r
}

// WithIntegrationFilterData sets the filter data for the request.
func WithIntegrationFilterData(filterData filterTypes.FilterData) ListIntegrationInstancesRequestOption {
	return func(r *ListIntegrationInstancesRequest) {
		r.filterData = filterData
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (r *ListIntegrationInstancesRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		FilterData filterTypes.FilterData `json:"filter_data"`
	}

	return json.Marshal(&alias{
		FilterData: r.filterData,
	})
}

// ListIntegrationInstancesResponseWrapper is the response wrapper for listing integration instances.
type ListIntegrationInstancesResponseWrapper struct {
	Data []ListIntegrationInstancesResponse `json:"DATA"`
}

// ListIntegrationInstancesResponse is the response for listing integration instances.
type ListIntegrationInstancesResponse struct {
	InstanceName            string `json:"instance_name"`
	CloudProvider           string `json:"cloud_provider"`
	Accounts                int    `json:"accounts,omitempty"`
	AccountName             string `json:"account_name,omitempty"`
	Scope                   string `json:"scope"`
	ScanMode                string `json:"scan_mode"`
	CustomResourcesTags     string `json:"custom_resources_tags"`
	ProvisioningMethod      string `json:"provisioning_method"`
	CollectionConfiguration string `json:"collection_configuration"`
	AdditionalCapabilities  string `json:"additional_capabilities"`
	InstanceID              string `json:"instance_id"`
	Status                  string `json:"status"`
	DeletedAt               int64  `json:"deleted_at"`
	OutpostID               string `json:"outpost_id"`
	CreationTime            int64  `json:"creation_time,omitempty"`
	UpdateStatus            string `json:"update_status,omitempty"`
	IsPendingChanges        int    `json:"is_pending_changes,omitempty"`
}

func (r ListIntegrationInstancesResponseWrapper) Marshal() ([]IntegrationInstance, error) {
	marshalledResponse := []IntegrationInstance{}

	for _, data := range r.Data {
		var customResourcesTags []Tag
		if data.CustomResourcesTags != "" {
			err := json.Unmarshal([]byte(data.CustomResourcesTags), &customResourcesTags)
			if err != nil {
				return []IntegrationInstance{}, err
			}
		} else {
			customResourcesTags = []Tag{}
		}

		var collectionConfiguration CollectionConfiguration
		if data.CollectionConfiguration != "" {
			err := json.Unmarshal([]byte(data.CollectionConfiguration), &collectionConfiguration)
			if err != nil {
				return []IntegrationInstance{}, err
			}
		} else {
			collectionConfiguration = CollectionConfiguration{}
		}

		var additionalCapabilities AdditionalCapabilities
		if data.AdditionalCapabilities != "" {
			err := json.Unmarshal([]byte(data.AdditionalCapabilities), &additionalCapabilities)
			if err != nil {
				return []IntegrationInstance{}, err
			}
		} else {
			additionalCapabilities = AdditionalCapabilities{}
		}

		marshalledData := IntegrationInstance{
			ID:                      data.InstanceID,
			InstanceName:            data.InstanceName,
			Scope:                   data.Scope,
			CustomResourcesTags:     customResourcesTags,
			Scan:                    Scan{ScanMethod: data.ScanMode},
			Status:                  data.Status,
			CloudProvider:           data.CloudProvider,
			CollectionConfiguration: collectionConfiguration,
			AdditionalCapabilities:  additionalCapabilities,
			AccountName:             data.AccountName,
			Accounts:                data.Accounts,
			CreationTime:            data.CreationTime,
			ProvisioningMethod:      data.ProvisioningMethod,
			UpdateStatus:            data.UpdateStatus,
			IsPendingChanges:        data.IsPendingChanges,
			OutpostID:               data.OutpostID,
		}

		marshalledResponse = append(marshalledResponse, marshalledData)
	}

	return marshalledResponse, nil
}

// EditIntegrationInstanceRequest is the request for editing an integration instance.
type EditIntegrationInstanceRequest struct {
	additionalCapabilities  AdditionalCapabilities
	cloudProvider           string
	cloudPartition          string
	collectionConfiguration CollectionConfiguration
	customResourcesTags     []Tag
	instanceID              string
	instanceName            *string
	outpostID               *string
	scopeModifications      ScopeModifications
}

// EditIntegrationInstanceRequestOption defines a functional option for EditIntegrationInstanceRequest.
type EditIntegrationInstanceRequestOption func(*EditIntegrationInstanceRequest)

// NewEditIntegrationInstanceRequest creates a new EditIntegrationInstanceRequest.
func NewEditIntegrationInstanceRequest(instanceID string, options ...EditIntegrationInstanceRequestOption) *EditIntegrationInstanceRequest {
	r := &EditIntegrationInstanceRequest{
		instanceID: instanceID,
	}
	for _, option := range options {
		option(r)
	}
	return r
}

// WithEditOutpostID sets the outpost ID for the request.
func WithEditOutpostID(outpostID string) EditIntegrationInstanceRequestOption {
	return func(r *EditIntegrationInstanceRequest) {
		r.outpostID = &outpostID
	}
}

// WithEditInstanceName sets the instance name for the request.
func WithEditInstanceName(instanceName string) EditIntegrationInstanceRequestOption {
	return func(r *EditIntegrationInstanceRequest) {
		r.instanceName = &instanceName
	}
}

// WithEditAdditionalCapabilities sets the additional capabilities for the request.
func WithEditAdditionalCapabilities(additionalCapabilities AdditionalCapabilities) EditIntegrationInstanceRequestOption {
	return func(r *EditIntegrationInstanceRequest) {
		r.additionalCapabilities = additionalCapabilities
	}
}

// WithEditCloudProvider sets the cloud provider for the request.
func WithEditCloudProvider(cloudProvider string) EditIntegrationInstanceRequestOption {
	return func(r *EditIntegrationInstanceRequest) {
		r.cloudProvider = cloudProvider
	}
}

// WithEditCloudPartition sets the cloud partition for the request.
func WithEditCloudPartition(cloudPartition string) EditIntegrationInstanceRequestOption {
	return func(r *EditIntegrationInstanceRequest) {
		r.cloudPartition = cloudPartition
	}
}

// WithEditCustomResourcesTags sets the custom resources tags for the request.
func WithEditCustomResourcesTags(customResourcesTags []Tag) EditIntegrationInstanceRequestOption {
	return func(r *EditIntegrationInstanceRequest) {
		r.customResourcesTags = customResourcesTags
	}
}

// WithEditCollectionConfiguration sets the collection configuration for the request.
func WithEditCollectionConfiguration(collectionConfiguration CollectionConfiguration) EditIntegrationInstanceRequestOption {
	return func(r *EditIntegrationInstanceRequest) {
		r.collectionConfiguration = collectionConfiguration
	}
}

// WithEditScopeModifications sets the scope modifications for the request.
func WithEditScopeModifications(scopeModifications ScopeModifications) EditIntegrationInstanceRequestOption {
	return func(r *EditIntegrationInstanceRequest) {
		r.scopeModifications = scopeModifications
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (r *EditIntegrationInstanceRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		InstanceID              string                  `json:"id"`
		OutpostID               *string                 `json:"scan_env_id,omitempty"`
		InstanceName            *string                 `json:"instance_name,omitempty"`
		AdditionalCapabilities  AdditionalCapabilities  `json:"additional_capabilities"`
		CloudProvider           string                  `json:"cloud_provider"`
		CloudPartition          string                  `json:"cloud_partition,omitempty"`
		CustomResourcesTags     []Tag                   `json:"custom_resources_tags"`
		CollectionConfiguration CollectionConfiguration `json:"collection_configuration"`
		ScopeModifications      ScopeModifications      `json:"scope_modifications"`
	}

	return json.Marshal(&alias{
		InstanceID:              r.instanceID,
		OutpostID:               r.outpostID,
		InstanceName:            r.instanceName,
		AdditionalCapabilities:  r.additionalCapabilities,
		CloudProvider:           r.cloudProvider,
		CloudPartition:          r.cloudPartition,
		CustomResourcesTags:     r.customResourcesTags,
		CollectionConfiguration: r.collectionConfiguration,
		ScopeModifications:      r.scopeModifications,
	})
}

// EnableOrDisableIntegrationInstancesRequest is the request for enabling or disabling integration instances.
type EnableOrDisableIntegrationInstancesRequest struct {
	ids    []string
	enable bool
}

// NewEnableOrDisableIntegrationInstancesRequest creates a new EnableOrDisableIntegrationInstancesRequest.
func NewEnableOrDisableIntegrationInstancesRequest(ids []string, enable bool) *EnableOrDisableIntegrationInstancesRequest {
	return &EnableOrDisableIntegrationInstancesRequest{
		ids:    ids,
		enable: enable,
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (r *EnableOrDisableIntegrationInstancesRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		IDs    []string `json:"ids"`
		Enable bool     `json:"enable"`
	}

	return json.Marshal(&alias{
		IDs:    r.ids,
		Enable: r.enable,
	})
}

// DeleteIntegrationInstanceRequest is the request for deleting integration instances.
type DeleteIntegrationInstanceRequest struct {
	ids []string
}

// NewDeleteIntegrationInstanceRequest creates a new DeleteIntegrationInstanceRequest.
func NewDeleteIntegrationInstanceRequest(ids []string) *DeleteIntegrationInstanceRequest {
	return &DeleteIntegrationInstanceRequest{
		ids: ids,
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (r *DeleteIntegrationInstanceRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		IDs []string `json:"ids"`
	}

	return json.Marshal(&alias{
		IDs: r.ids,
	})
}
