// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	shared "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/shared"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	cwpTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cwp"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ContainerRegistryModel is the Terraform model for the
// cortexcloud_container_registry resource and data source.
type ContainerRegistryModel struct {
	ID       types.String `tfsdk:"id"`
	Vendor   types.String `tfsdk:"vendor"`
	Name     types.String `tfsdk:"name"`
	Enabled  types.Bool   `tfsdk:"enabled"`
	URL      types.String `tfsdk:"url"`
	TenantID types.String `tfsdk:"tenant_id"`

	Username  types.String `tfsdk:"username"`
	Password  types.String `tfsdk:"password"`
	AuthToken types.String `tfsdk:"auth_token"`

	ScanningMode  types.String `tfsdk:"scanning_mode"`
	CloudProvider types.String `tfsdk:"cloud_provider"`
	Region        types.String `tfsdk:"region"`
	OutpostID     types.String `tfsdk:"outpost_id"`
	BrokerType    types.String `tfsdk:"broker_type"`
	BrokerID      types.String `tfsdk:"broker_id"`

	RegistryType   types.String `tfsdk:"registry_type"`
	InsecurePull   types.Bool   `tfsdk:"insecure_pull"`
	CACertificate  types.String `tfsdk:"ca_certificate"`
	Repository     types.String `tfsdk:"repository"`
	AllowStaticIPs types.Bool   `tfsdk:"allow_static_ips"`
	IPIdentifier   types.String `tfsdk:"ip_identifier"`

	InitialScanConfiguration *InitialScanConfigurationModel `tfsdk:"initial_scan_configuration"`

	AssetScopeFilters *shared.RootFilterModel `tfsdk:"asset_scope_filters"`
	FilterType        types.String            `tfsdk:"filter_type"`

	GitLab    *GitLabConfigModel    `tfsdk:"gitlab"`
	DockerHub *DockerHubConfigModel `tfsdk:"docker_hub"`
	OpenShift *OpenShiftConfigModel `tfsdk:"openshift"`
}

// InitialScanConfigurationModel is the initial_scan_configuration block.
type InitialScanConfigurationModel struct {
	Mode    types.String `tfsdk:"mode"`
	NumDays types.Int64  `tfsdk:"num_days"`
}

// GitLabConfigModel is the gitlab vendor-specific block.
type GitLabConfigModel struct {
	GroupIDs      types.String `tfsdk:"group_ids"`
	ProjectIDs    types.String `tfsdk:"project_ids"`
	APIDomainName types.String `tfsdk:"api_domain_name"`
}

// DockerHubConfigModel is the docker_hub vendor-specific block.
type DockerHubConfigModel struct {
	Repository types.String `tfsdk:"repository"`
}

// OpenShiftConfigModel is the openshift vendor-specific block.
type OpenShiftConfigModel struct {
	ClusterID          types.String `tfsdk:"cluster_id"`
	ClusterName        types.String `tfsdk:"cluster_name"`
	ClusterAssetID     types.String `tfsdk:"cluster_asset_id"`
	ClusterAssetTypeID types.String `tfsdk:"cluster_asset_type_id"`
	ClusterRealm       types.String `tfsdk:"cluster_realm"`
}

// ToRequest converts the model to the SDK request body.
//
// The same body is used for create and update. Update is a full replacement,
// so every configured field, including credentials, is always sent. Unknown
// values (Optional+Computed attributes not set in config) are treated as unset.
func (m *ContainerRegistryModel) ToRequest(ctx context.Context, diags *diag.Diagnostics) cwpTypes.RegistryConnector {
	tflog.Debug(ctx, "Converting container registry model to request")

	req := cwpTypes.RegistryConnector{
		Vendor:        m.Vendor.ValueString(),
		Name:          m.Name.ValueString(),
		Enabled:       boolOr(m.Enabled, true),
		URL:           m.URL.ValueString(),
		Username:      stringOrEmpty(m.Username),
		Password:      stringOrEmpty(m.Password),
		AuthToken:     stringOrEmpty(m.AuthToken),
		ScanningMode:  m.ScanningMode.ValueString(),
		CloudProvider: stringOrEmpty(m.CloudProvider),
		Region:        stringOrEmpty(m.Region),
		OutpostID:     stringOrEmpty(m.OutpostID),
		BrokerType:    stringOrEmpty(m.BrokerType),
		BrokerID:      stringOrEmpty(m.BrokerID),
		RegistryType:  stringOrEmpty(m.RegistryType),
		InsecurePull:  boolOr(m.InsecurePull, false),
		CACertificate: stringOrEmpty(m.CACertificate),
		Repository:    stringOrEmpty(m.Repository),
		IPIdentifier:  stringOrEmpty(m.IPIdentifier),
		FilterType:    stringOrEmpty(m.FilterType),
	}

	if known(m.AllowStaticIPs) {
		v := m.AllowStaticIPs.ValueBool()
		req.AllowStaticIPs = &v
	}

	if m.InitialScanConfiguration != nil {
		req.InitialScanConfiguration.Mode = stringOrEmpty(m.InitialScanConfiguration.Mode)
		if known(m.InitialScanConfiguration.NumDays) {
			n := int(m.InitialScanConfiguration.NumDays.ValueInt64())
			req.InitialScanConfiguration.NumDays = &n
		}
	}
	if req.InitialScanConfiguration.Mode == "" {
		req.InitialScanConfiguration.Mode = enums.RegistryScanningTypeAll.String()
	}

	if m.AssetScopeFilters != nil && (len(m.AssetScopeFilters.And) > 0 || len(m.AssetScopeFilters.Or) > 0) {
		root := shared.RootModelToSDKFilter(ctx, m.AssetScopeFilters)
		req.AssetScopeFilters = &root
	}

	req.VendorSpecificConfiguration = m.vendorConfigToSDK()

	return req
}

func (m *ContainerRegistryModel) vendorConfigToSDK() *cwpTypes.VendorSpecificConfig {
	switch {
	case m.GitLab != nil:
		return &cwpTypes.VendorSpecificConfig{
			GroupIDs:      stringOrEmpty(m.GitLab.GroupIDs),
			ProjectIDs:    stringOrEmpty(m.GitLab.ProjectIDs),
			APIDomainName: stringOrEmpty(m.GitLab.APIDomainName),
		}
	case m.DockerHub != nil:
		return &cwpTypes.VendorSpecificConfig{
			Repository: stringOrEmpty(m.DockerHub.Repository),
		}
	case m.OpenShift != nil:
		return &cwpTypes.VendorSpecificConfig{
			ClusterID:          stringOrEmpty(m.OpenShift.ClusterID),
			ClusterName:        stringOrEmpty(m.OpenShift.ClusterName),
			ClusterAssetID:     stringOrEmpty(m.OpenShift.ClusterAssetID),
			ClusterAssetTypeID: stringOrEmpty(m.OpenShift.ClusterAssetTypeID),
			ClusterRealm:       stringOrEmpty(m.OpenShift.ClusterRealm),
		}
	}
	return nil
}

// RefreshFromRemote updates the model from an API response.
//
// password and auth_token are never read from the API: the response may omit
// or mask them, and writing that back would either leak a secret into state or
// cause a permanent diff. They always keep the value already in the model
// (from plan on create/update, from prior state on read, null after import).
//
// Optional string attributes map an empty remote value to null so that
// attributes omitted from configuration do not produce a diff.
func (m *ContainerRegistryModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *cwpTypes.RegistryConnector) {
	tflog.Debug(ctx, "Refreshing container registry model from remote")

	if remote.ConnectorID != "" {
		m.ID = types.StringValue(remote.ConnectorID)
	}
	m.Vendor = types.StringValue(remote.Vendor)
	m.Name = types.StringValue(remote.Name)
	m.Enabled = types.BoolValue(remote.Enabled)
	m.URL = types.StringValue(remote.URL)
	m.TenantID = nullIfEmpty(remote.TenantID)

	m.Username = nullIfEmpty(remote.Username)
	m.Password = nullIfUnknown(m.Password)
	m.AuthToken = nullIfUnknown(m.AuthToken)

	m.ScanningMode = types.StringValue(remote.ScanningMode)
	m.CloudProvider = nullIfEmpty(remote.CloudProvider)
	m.Region = nullIfEmpty(remote.Region)
	m.OutpostID = nullIfEmpty(remote.OutpostID)
	m.BrokerType = nullIfEmpty(remote.BrokerType)
	m.BrokerID = nullIfEmpty(remote.BrokerID)

	m.RegistryType = nullIfEmpty(remote.RegistryType)
	m.InsecurePull = types.BoolValue(remote.InsecurePull)
	m.CACertificate = nullIfEmpty(remote.CACertificate)
	m.Repository = nullIfEmpty(remote.Repository)
	if remote.AllowStaticIPs != nil {
		m.AllowStaticIPs = types.BoolValue(*remote.AllowStaticIPs)
	} else {
		m.AllowStaticIPs = types.BoolValue(false)
	}
	m.IPIdentifier = nullIfEmpty(remote.IPIdentifier)

	isc := &InitialScanConfigurationModel{
		Mode:    types.StringValue(remote.InitialScanConfiguration.Mode),
		NumDays: types.Int64Null(),
	}
	if remote.InitialScanConfiguration.Mode == "" {
		isc.Mode = types.StringValue(enums.RegistryScanningTypeAll.String())
	}
	if remote.InitialScanConfiguration.NumDays != nil {
		isc.NumDays = types.Int64Value(int64(*remote.InitialScanConfiguration.NumDays))
	}
	m.InitialScanConfiguration = isc

	m.AssetScopeFilters = nil
	if remote.AssetScopeFilters != nil {
		if model := shared.SDKToModel(ctx, *remote.AssetScopeFilters); model != nil && (len(model.And) > 0 || len(model.Or) > 0) {
			m.AssetScopeFilters = model
		}
	}
	if remote.FilterType != "" {
		m.FilterType = types.StringValue(remote.FilterType)
	} else {
		m.FilterType = types.StringValue(enums.RegistryFilterTypeInclude.String())
	}

	m.refreshVendorConfig(remote)
}

// refreshVendorConfig populates exactly one vendor block, chosen by vendor.
// A block whose fields are all empty is recorded as absent.
func (m *ContainerRegistryModel) refreshVendorConfig(remote *cwpTypes.RegistryConnector) {
	m.GitLab, m.DockerHub, m.OpenShift = nil, nil, nil

	v := remote.VendorSpecificConfiguration
	if v == nil {
		return
	}

	switch enums.RegistryVendor(remote.Vendor) {
	case enums.RegistryVendorGitLabContainerRegistry:
		if v.GroupIDs != "" || v.ProjectIDs != "" || v.APIDomainName != "" {
			m.GitLab = &GitLabConfigModel{
				GroupIDs:      nullIfEmpty(v.GroupIDs),
				ProjectIDs:    nullIfEmpty(v.ProjectIDs),
				APIDomainName: nullIfEmpty(v.APIDomainName),
			}
		}
	case enums.RegistryVendorDockerHub:
		if v.Repository != "" {
			m.DockerHub = &DockerHubConfigModel{Repository: types.StringValue(v.Repository)}
		}
	case enums.RegistryVendorOpenShift:
		if v.ClusterID != "" || v.ClusterName != "" || v.ClusterAssetID != "" || v.ClusterAssetTypeID != "" || v.ClusterRealm != "" {
			m.OpenShift = &OpenShiftConfigModel{
				ClusterID:          nullIfEmpty(v.ClusterID),
				ClusterName:        nullIfEmpty(v.ClusterName),
				ClusterAssetID:     nullIfEmpty(v.ClusterAssetID),
				ClusterAssetTypeID: nullIfEmpty(v.ClusterAssetTypeID),
				ClusterRealm:       nullIfEmpty(v.ClusterRealm),
			}
		}
	}
}

type knowable interface {
	IsNull() bool
	IsUnknown() bool
}

func known(v knowable) bool { return !v.IsNull() && !v.IsUnknown() }

func stringOrEmpty(v types.String) string {
	if !known(v) {
		return ""
	}
	return v.ValueString()
}

func boolOr(v types.Bool, fallback bool) bool {
	if !known(v) {
		return fallback
	}
	return v.ValueBool()
}

func nullIfEmpty(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

func nullIfUnknown(v types.String) types.String {
	if v.IsUnknown() {
		return types.StringNull()
	}
	return v
}
