// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
)

// RegistryConnector is a third-party container registry connector managed by
// the CWP Registry Onboarding API
// (public_api/v1/cwp/registry_onboarding/instances).
//
// The same shape is used as the POST/PUT request body
// (UnmanagedRegistryConnectorPublicAPIObject) and the GET response body
// (GetUnmanagedRegistryConnectorResponse); the two schemas are identical.
//
// Fields the API lists as required on create/update have no omitempty so an
// empty value is still transmitted: vendor, name, url, username, password,
// auth_token, scanning_mode, region, insecure_pull and
// initial_scan_configuration. PUT is a full replacement, so callers must always
// send the complete object.
type RegistryConnector struct {
	ConnectorID string `json:"connector_id,omitempty"`
	Vendor      string `json:"vendor"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`

	Username  string `json:"username"`
	Password  string `json:"password"`
	AuthToken string `json:"auth_token"`

	ScanningMode  string `json:"scanning_mode"`
	CloudProvider string `json:"cloud_provider,omitempty"`
	Region        string `json:"region"`
	OutpostID     string `json:"outpost_id,omitempty"`
	BrokerType    string `json:"broker_type,omitempty"`
	BrokerID      string `json:"broker_id,omitempty"`

	InsecurePull   bool   `json:"insecure_pull"`
	CACertificate  string `json:"ca_certificate,omitempty"`
	Repository     string `json:"repository,omitempty"`
	AllowStaticIPs *bool  `json:"allow_static_ips,omitempty"`
	IPIdentifier   string `json:"ip_identifier,omitempty"`
	RegistryType   string `json:"registry_type,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`

	InitialScanConfiguration InitialScanConfiguration `json:"initial_scan_configuration"`

	AssetScopeFilters *filterTypes.FilterRoot `json:"asset_scope_filters,omitempty"`
	FilterType        string                  `json:"filter_type,omitempty"`

	VendorSpecificConfiguration *VendorSpecificConfig `json:"vendor_specific_configuration,omitempty"`
}

// InitialScanConfiguration controls which images are scanned when the
// connector is first onboarded.
//
// Note: the API uses camelCase "numDays" here while every other field is
// snake_case. The tag must match the spec exactly.
type InitialScanConfiguration struct {
	Mode    string `json:"mode"`
	NumDays *int   `json:"numDays,omitempty"`
}

// VendorSpecificConfig carries vendor-specific scanning options.
//
// The API models this as a oneOf of GitLab, Docker Hub and OpenShift shapes
// without a discriminator. The three shapes have disjoint property names, so a
// single flat struct with omitempty on every field marshals to exactly the
// variant that was populated and decodes any variant the API returns.
type VendorSpecificConfig struct {
	// GitLab
	GroupIDs      string `json:"group_ids,omitempty"`
	ProjectIDs    string `json:"project_ids,omitempty"`
	APIDomainName string `json:"api_domain_name,omitempty"`

	// Docker Hub
	Repository string `json:"repository,omitempty"`

	// OpenShift
	ClusterID          string `json:"cluster_id,omitempty"`
	ClusterName        string `json:"cluster_name,omitempty"`
	ClusterAssetID     string `json:"cluster_asset_id,omitempty"`
	ClusterAssetTypeID string `json:"cluster_asset_type_id,omitempty"`
	ClusterRealm       string `json:"cluster_realm,omitempty"`
}

// CreateRegistryConnectorResponse is the body returned by a successful create.
type CreateRegistryConnectorResponse struct {
	ConnectorID string `json:"connector_id"`
}
