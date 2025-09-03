// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// ---------------------------
// Shared structs
// ---------------------------

type IntegrationInstance struct {
	Id                      string                  `json:"id" tfsdk:"id"`
	Collector               string                  `json:"collector" tfsdk:"collector"`
	InstanceName            string                  `json:"instance_name" tfsdk:"instance_name"`
	Scope                   string                  `json:"scope" tfsdk:"scope"`
	CustomResourcesTags     []Tag                   `json:"tags" tfsdk:"custom_resource_tags"`
	Scan                    Scan                    `json:"scan" tfsdk:"scan"`
	Status                  string                  `json:"status" tfsdk:"status"`
	CloudProvider           string                  `json:"cloud_provider" tfsdk:"cloud_provider"`
	SecurityCapabilities    []SecurityCapability    `json:"security_capabilities" tfsdk:"security_capabilities"`
	CollectionConfiguration CollectionConfiguration `json:"collection_configuration"`
	AdditionalCapabilities  AdditionalCapabilities  `json:"additional_capabilities"`
}

type Tag struct {
	Key   string `json:"key" tfsdk:"key"`
	Value string `json:"value" tfsdk:"value"`
}

type Scan struct {
	ScanMethod string `json:"scan_method" tfsdk:"scan_method"`
}

type SecurityCapability struct {
	Name        string `json:"name" tfsdk:"name"`
	Description string `json:"description" tfsdk:"description"`
	Status      int    `json:"status" tfsdk:"status"`
}

type AccountDetails struct {
	OrganizationId *string `json:"organization_id,omitempty"`
}

type CollectionConfiguration struct {
	AuditLogs AuditLogsConfiguration `json:"audit_logs" tfsdk:"audit_logs"`
}

type AuditLogsConfiguration struct {
	Enabled bool `json:"enabled" tfsdk:"enabled"`
}

type ScopeModifications struct {
	Accounts      *ScopeModificationsOptionsGeneric `json:"accounts,omitempty" tfsdk:"accounts"`
	Projects      *ScopeModificationsOptionsGeneric `json:"projects,omitempty" tfsdk:"projects"`
	Subscriptions *ScopeModificationsOptionsGeneric `json:"subscriptions,omitempty" tfsdk:"subscriptions"`
	Regions       *ScopeModificationsOptionsRegions `json:"regions,omitempty" tfsdk:"regions"`
}

type ScopeModificationsOptionsGeneric struct {
	Enabled         bool      `json:"enabled" tfsdk:"enabled"`
	Type            string    `json:"type" tfsdk:"type"`
	AccountIds      *[]string `json:"account_ids,omitempty" tfsdk:"account_ids"`
	ProjectIds      *[]string `json:"project_ids,omitempty" tfsdk:"project_ids"`
	SubscriptionIds *[]string `json:"subscription_ids,omitempty" tfsdk:"subscription_ids"`
}

type ScopeModificationsOptionsRegions struct {
	Enabled bool      `json:"enabled" tfsdk:"enabled"`
	Type    *string   `json:"type,omitempty" tfsdk:"type"`
	Regions *[]string `json:"regions,omitempty" tfsdk:"regions"`
}

type DefaultScanningScope struct {
	RegistryScanningScope      RegistryScanningScope      `json:"registry_scanning_scope"`
	AgentlessDiskScanningScope AgentlessDiskScanningScope `json:"agentless_disk_scanning_scope"`
	// TODO: DataAssetsClassificationOptions
}

type RegistryScanningScope struct {
	Enabled bool `json:"enabled"`
}

type AgentlessDiskScanningScope struct {
	Enabled bool `json:"enabled"`
}

type AdditionalCapabilities struct {
	XsiamAnalytics                bool                    `json:"xsiam_analytics" tfsdk:"xsiam_analytics"`
	DataSecurityPostureManagement bool                    `json:"data_security_posture_management" tfsdk:"data_security_posture_management"`
	RegistryScanning              bool                    `json:"registry_scanning" tfsdk:"registry_scanning"`
	RegistryScanningOptions       RegistryScanningOptions `json:"registry_scanning_options" tfsdk:"registry_scanning_options"`
}

type RegistryScanningOptions struct {
	Type string `json:"type" tfsdk:"type"`
}

type Automated struct {
	Link         string `json:"link" tfsdk:"automated_deployment_link"`
	TrackingGuid string `json:"tracking_guid" tfsdk:"tracking_guid"`
}

type Manual struct {
	TF_ARM string `json:"TF/ARM" tfsdk:"manual_deployment_link"`
}

// ---------------------------
// Request/Response structs
// ---------------------------

// Create Integration Template

type CreateIntegrationTemplateRequest struct {
	Data CreateIntegrationTemplateRequestData `json:"request_data"`
}

type CreateIntegrationTemplateRequestData struct {
	AccountDetails          *AccountDetails         `json:"account_details,omitempty"`
	AdditionalCapabilities  AdditionalCapabilities  `json:"additional_capabilities"`
	CloudProvider           string                  `json:"cloud_provider"`
	CollectionConfiguration CollectionConfiguration `json:"collection_configuration"`
	CustomResourcesTags     []Tag                   `json:"custom_resources_tags"`
	InstanceName            string                  `json:"instance_name"`
	ScanMode                string                  `json:"scan_mode"`
	Scope                   string                  `json:"scope"`
	ScopeModifications      ScopeModifications      `json:"scope_modifications"`
}

type CreateTemplateOrEditIntegrationInstanceResponse struct {
	Reply CreateTemplateOrEditIntegrationInstanceResponseReply `json:"reply"`
}

type CreateTemplateOrEditIntegrationInstanceResponseReply struct {
	Automated Automated `json:"automated"`
	Manual    Manual    `json:"manual"`
}

func (r CreateTemplateOrEditIntegrationInstanceResponse) GetTemplateUrl() (string, error) {
	if r.Reply.Automated.Link == "" {
		return "", fmt.Errorf("Failed to retrieve template URL: reply.automated.link is empty string")
	}

	parsedUrl, err := url.Parse(r.Reply.Automated.Link)
	if err != nil {
		return "", err
	}

	queryValues, err := url.ParseQuery(parsedUrl.RawFragment)
	if err != nil {
		return "", err
	}

	templateUrl := queryValues.Get("/stacks/quickcreate?templateURL")

	return templateUrl, nil
}

// Get Integration Instance Details

type GetIntegrationInstanceRequest struct {
	RequestData GetIntegrationInstanceRequestData `json:"request_data"`
}

type GetIntegrationInstanceRequestData struct {
	InstanceId string `json:"id"`
}

type GetIntegrationInstanceResponse struct {
	Reply GetIntegrationInstanceResponseReply `json:"reply"`
}

type GetIntegrationInstanceResponseReply struct {
	Id                      string               `json:"id"`
	Collector               string               `json:"collector"`
	InstanceName            string               `json:"instance_name"`
	Scope                   string               `json:"scope"`
	CustomResourcesTags     []Tag                `json:"tags"`
	Scan                    Scan                 `json:"scan"`
	Status                  string               `json:"status"`
	CloudProvider           string               `json:"cloud_provider"`
	SecurityCapabilities    []SecurityCapability `json:"security_capabilities"`
	CollectionConfiguration string               `json:"collection_configuration"`
	AdditionalCapabilities  string               `json:"additional_capabilities"`
}

func (r GetIntegrationInstanceResponse) Marshal() (IntegrationInstance, error) {
	var collectionConfiguration CollectionConfiguration
	err := json.Unmarshal([]byte(r.Reply.CollectionConfiguration), &collectionConfiguration)
	if err != nil {
		return IntegrationInstance{}, err
	}

	var additionalCapabilities AdditionalCapabilities
	err = json.Unmarshal([]byte(r.Reply.AdditionalCapabilities), &additionalCapabilities)
	if err != nil {
		return IntegrationInstance{}, err
	}

	marshalledResponse := IntegrationInstance{
		Id:                      r.Reply.Id,
		Collector:               r.Reply.Collector,
		InstanceName:            r.Reply.InstanceName,
		Scope:                   r.Reply.Scope,
		CustomResourcesTags:     r.Reply.CustomResourcesTags,
		Scan:                    r.Reply.Scan,
		Status:                  r.Reply.Status,
		CloudProvider:           r.Reply.CloudProvider,
		SecurityCapabilities:    r.Reply.SecurityCapabilities,
		CollectionConfiguration: collectionConfiguration,
		AdditionalCapabilities:  additionalCapabilities,
	}

	return marshalledResponse, nil
}

// List Integration Instances

type ListIntegrationInstancesRequest struct {
	RequestData ListIntegrationInstancesRequestData `json:"request_data"`
}

type ListIntegrationInstancesRequestData struct {
	FilterData FilterData `json:"filter_data"`
}

type ListIntegrationInstancesResponse struct {
	Reply ListIntegrationInstancesResponseReply `json:"reply"`
}

type ListIntegrationInstancesResponseReply struct {
	Data []ListIntegrationInstanceResponseData `json:"DATA"`
}

type ListIntegrationInstanceResponseData struct {
	InstanceName            string               `json:"instance_name"`
	CloudProvider           string               `json:"cloud_provider"`
	Scope                   string               `json:"scope"`
	ScanMode                string               `json:"scan_mode"`
	CustomResourcesTags     string               `json:"custom_resources_tags"`
	ProvisioningMethod      string               `json:"provisioning_method"`
	AccountDetails          AccountDetails       `json:"account_details"`
	ScopeModifications      ScopeModifications   `json:"scope_modifications"`
	CollectionConfiguration string               `json:"collection_configuration"`
	AdditionalCapabilities  string               `json:"additional_capabilities"`
	InstanceId              string               `json:"instance_id"`
	Status                  string               `json:"status"`
	CloudPartition          string               `json:"cloud_partition"`
	CreatedAt               int                  `json:"created_at"`
	ModifiedAt              int                  `json:"modified_at"`
	DeletedAt               int                  `json:"deleted_at"`
	DefaultScanningScope    DefaultScanningScope `json:"default_scanning_scope"`
	OutpostId               string               `json:"outpost_id"`
}

func (r ListIntegrationInstancesResponse) Marshal() ([]IntegrationInstance, error) {
	marshalledResponse := []IntegrationInstance{}

	for _, data := range r.Reply.Data {
		var customResourcesTags []Tag
		if data.CustomResourcesTags != "" {
			err := json.Unmarshal([]byte(data.CustomResourcesTags), &customResourcesTags)
			if err != nil {
				return []IntegrationInstance{}, err
			}
		} else {
			customResourcesTags = []Tag{}
		}

		// TODO: verify this behavior
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
			Id:                      data.InstanceId,
			InstanceName:            data.InstanceName,
			Scope:                   data.Scope,
			CustomResourcesTags:     customResourcesTags,
			Scan:                    Scan{ScanMethod: data.ScanMode},
			Status:                  data.Status,
			CloudProvider:           data.CloudProvider,
			CollectionConfiguration: collectionConfiguration,
			AdditionalCapabilities:  additionalCapabilities,
		}

		marshalledResponse = append(marshalledResponse, marshalledData)
	}

	return marshalledResponse, nil
}

// Edit Integration Instance

type EditIntegrationInstanceRequest struct {
	RequestData EditIntegrationInstanceRequestData `json:"request_data"`
}

type EditIntegrationInstanceRequestData struct {
	InstanceId              string                  `json:"id"`
	ScanEnvId               string                  `json:"scan_env_id"`
	InstanceName            string                  `json:"instance_name"`
	AdditionalCapabilities  AdditionalCapabilities  `json:"additional_capabilities"`
	CloudProvider           string                  `json:"cloud_provider"`
	CustomResourcesTags     []Tag                   `json:"custom_resources_tags"`
	CollectionConfiguration CollectionConfiguration `json:"collection_configuration"`
	ScopeModifications      ScopeModifications      `json:"scope_modifications"`
}

// Enable Or Disable Instances

type EnableOrDisableInstancesRequest struct {
	Data EnableOrDisableInstancesRequestData `json:"request_data"`
}

type EnableOrDisableInstancesRequestData struct {
	Ids    []string `json:"ids"`
	Enable bool     `json:"enable"`
}

// Delete Instances

type DeleteInstanceRequest struct {
	Data DeleteInstanceRequestData `json:"request_data"`
}

type DeleteInstanceRequestData struct {
	Ids []string `json:"ids"`
}

// ---------------------------
// Request functions
// ---------------------------

// CreateTemplate creates a new Cloud Onboarding Integration Template.
//
// TODO: details
func (c *Client) CreateTemplate(ctx context.Context, input CreateIntegrationTemplateRequest) (CreateTemplateOrEditIntegrationInstanceResponse, error) {
	var ans CreateTemplateOrEditIntegrationInstanceResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, CreateInstanceTemplateEndpoint, nil, nil, input, &ans)

	return ans, err
}

// GetDetails returns the configuration details of the specified integration instance.
func (c *Client) GetInstanceDetails(ctx context.Context, input GetIntegrationInstanceRequest) (GetIntegrationInstanceResponse, error) {
	var ans GetIntegrationInstanceResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, GetIntegrationInstanceDetailsEndpoint, nil, nil, input, &ans)

	return ans, err
}

func (c *Client) ListInstances(ctx context.Context, input ListIntegrationInstancesRequest) (ListIntegrationInstancesResponse, error) {
	var ans ListIntegrationInstancesResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListIntegrationInstancesEndpoint, nil, nil, input, &ans)

	return ans, err
}

func (c *Client) EditInstance(ctx context.Context, input EditIntegrationInstanceRequest) (CreateTemplateOrEditIntegrationInstanceResponse, error) {
	var ans CreateTemplateOrEditIntegrationInstanceResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, EditIntegrationInstanceEndpoint, nil, nil, input, &ans)

	return ans, err
}

func (c *Client) EnableInstances(ctx context.Context, instanceIds []string) error {
	body := EnableOrDisableInstancesRequest{
		Data: EnableOrDisableInstancesRequestData{
			Ids:    instanceIds,
			Enable: true,
		},
	}

	_, err := c.internalClient.Do(ctx, http.MethodPost, EnableOrDisableIntegrationInstancesEndpoint, nil, nil, body, nil)

	return err
}

func (c *Client) DisableInstances(ctx context.Context, instanceIds []string) error {
	body := EnableOrDisableInstancesRequest{
		Data: EnableOrDisableInstancesRequestData{
			Ids:    instanceIds,
			Enable: false,
		},
	}

	_, err := c.internalClient.Do(ctx, http.MethodPost, EnableOrDisableIntegrationInstancesEndpoint, nil, nil, body, nil)

	return err
}

func (c *Client) DeleteInstances(ctx context.Context, instanceIds []string) error {
	body := DeleteInstanceRequest{
		Data: DeleteInstanceRequestData{
			Ids: instanceIds,
		},
	}

	_, err := c.internalClient.Do(ctx, http.MethodPost, DeleteIntegrationInstancesEndpoint, nil, nil, body, nil)

	return err
}
