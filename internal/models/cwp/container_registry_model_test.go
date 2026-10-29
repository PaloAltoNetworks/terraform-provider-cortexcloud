// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"testing"

	shared "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/shared"
	cwpTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cwp"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func baseRegistryModel() ContainerRegistryModel {
	return ContainerRegistryModel{
		ID:             types.StringUnknown(),
		Vendor:         types.StringValue("HARBOR"),
		Name:           types.StringValue("harbor"),
		Enabled:        types.BoolUnknown(),
		URL:            types.StringValue("https://harbor.example.com"),
		TenantID:       types.StringUnknown(),
		Username:       types.StringValue("svc"),
		Password:       types.StringValue("s3cret"),
		AuthToken:      types.StringNull(),
		ScanningMode:   types.StringValue("OUTPOST"),
		CloudProvider:  types.StringNull(),
		Region:         types.StringNull(),
		OutpostID:      types.StringValue("op-1"),
		BrokerType:     types.StringNull(),
		BrokerID:       types.StringNull(),
		RegistryType:   types.StringNull(),
		InsecurePull:   types.BoolUnknown(),
		CACertificate:  types.StringNull(),
		Repository:     types.StringNull(),
		AllowStaticIPs: types.BoolUnknown(),
		IPIdentifier:   types.StringNull(),
		InitialScanConfiguration: &InitialScanConfigurationModel{
			Mode:    types.StringValue("ALL"),
			NumDays: types.Int64Null(),
		},
		FilterType: types.StringUnknown(),
	}
}

func requestJSON(t *testing.T, req cwpTypes.RegistryConnector) map[string]any {
	t.Helper()
	raw, err := json.Marshal(req)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestContainerRegistryToRequest_Defaults(t *testing.T) {
	m := baseRegistryModel()
	var diags diag.Diagnostics
	req := m.ToRequest(context.Background(), &diags)
	require.False(t, diags.HasError())

	// Unknown Optional+Computed values fall back to the API defaults, and
	// unset Optional values are omitted.
	assert.True(t, req.Enabled, "enabled defaults to true")
	assert.False(t, req.InsecurePull)
	assert.Nil(t, req.AllowStaticIPs, "unknown allow_static_ips must be omitted")
	assert.Equal(t, "", req.RegistryType)
	assert.Equal(t, "", req.FilterType)
	assert.Equal(t, "", req.ConnectorID)
	assert.Nil(t, req.AssetScopeFilters)
	assert.Nil(t, req.VendorSpecificConfiguration)

	body := requestJSON(t, req)
	isc := body["initial_scan_configuration"].(map[string]any)
	assert.Equal(t, "ALL", isc["mode"])
	_, hasDays := isc["numDays"]
	assert.False(t, hasDays)
}

func TestContainerRegistryToRequest_TagsModifiedDays(t *testing.T) {
	m := baseRegistryModel()
	m.InitialScanConfiguration = &InitialScanConfigurationModel{
		Mode:    types.StringValue("TAGS_MODIFIED_DAYS"),
		NumDays: types.Int64Value(30),
	}
	var diags diag.Diagnostics
	req := m.ToRequest(context.Background(), &diags)
	require.NotNil(t, req.InitialScanConfiguration.NumDays)
	assert.Equal(t, 30, *req.InitialScanConfiguration.NumDays)
	assert.Equal(t, float64(30), requestJSON(t, req)["initial_scan_configuration"].(map[string]any)["numDays"])
}

func TestContainerRegistryToRequest_VendorBlocks(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ContainerRegistryModel)
		want   map[string]any
	}{
		{
			name: "gitlab",
			mutate: func(m *ContainerRegistryModel) {
				m.Vendor = types.StringValue("GITLAB_CONTAINER_REGISTRY")
				m.GitLab = &GitLabConfigModel{
					GroupIDs:      types.StringValue("1,2"),
					ProjectIDs:    types.StringNull(),
					APIDomainName: types.StringValue("gitlab.example.com"),
				}
			},
			want: map[string]any{"group_ids": "1,2", "api_domain_name": "gitlab.example.com"},
		},
		{
			name: "docker_hub",
			mutate: func(m *ContainerRegistryModel) {
				m.Vendor = types.StringValue("DOCKER_HUB")
				m.DockerHub = &DockerHubConfigModel{Repository: types.StringValue("my-repo")}
			},
			want: map[string]any{"repository": "my-repo"},
		},
		{
			name: "openshift",
			mutate: func(m *ContainerRegistryModel) {
				m.Vendor = types.StringValue("OPENSHIFT")
				m.OpenShift = &OpenShiftConfigModel{
					ClusterID:          types.StringValue("c-1"),
					ClusterName:        types.StringValue("prod"),
					ClusterAssetID:     types.StringNull(),
					ClusterAssetTypeID: types.StringNull(),
					ClusterRealm:       types.StringValue("aws"),
				}
			},
			want: map[string]any{"cluster_id": "c-1", "cluster_name": "prod", "cluster_realm": "aws"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := baseRegistryModel()
			tc.mutate(&m)
			var diags diag.Diagnostics
			body := requestJSON(t, m.ToRequest(context.Background(), &diags))
			assert.Equal(t, tc.want, body["vendor_specific_configuration"])
		})
	}
}

func TestContainerRegistryToRequest_AssetScopeFilters(t *testing.T) {
	m := baseRegistryModel()
	m.FilterType = types.StringValue("EXCLUDE")
	m.AssetScopeFilters = &shared.RootFilterModel{
		And: []shared.NestedFilterModel{{
			SearchField: types.StringValue("Registry"),
			SearchType:  types.StringValue("EQ"),
			SearchValue: types.StringValue("library/ubuntu"),
		}},
	}
	var diags diag.Diagnostics
	body := requestJSON(t, m.ToRequest(context.Background(), &diags))
	assert.Equal(t, "EXCLUDE", body["filter_type"])
	filters := body["asset_scope_filters"].(map[string]any)
	and := filters["AND"].([]any)
	require.Len(t, and, 1)
	assert.Equal(t, "Registry", and[0].(map[string]any)["SEARCH_FIELD"])
}

func TestContainerRegistryToRequest_EmptyFilterRootOmitted(t *testing.T) {
	m := baseRegistryModel()
	m.AssetScopeFilters = &shared.RootFilterModel{}
	var diags diag.Diagnostics
	req := m.ToRequest(context.Background(), &diags)
	assert.Nil(t, req.AssetScopeFilters)
}

func remoteConnector() *cwpTypes.RegistryConnector {
	return &cwpTypes.RegistryConnector{
		ConnectorID:  "conn-1",
		Vendor:       "HARBOR",
		Name:         "harbor",
		Enabled:      true,
		URL:          "https://harbor.example.com",
		Username:     "svc",
		Password:     "********",
		AuthToken:    "",
		ScanningMode: "OUTPOST",
		OutpostID:    "op-1",
		InitialScanConfiguration: cwpTypes.InitialScanConfiguration{
			Mode: "ALL",
		},
		TenantID: "t-1",
	}
}

func TestContainerRegistryRefreshFromRemote_PreservesCredentials(t *testing.T) {
	m := baseRegistryModel()
	var diags diag.Diagnostics
	m.RefreshFromRemote(context.Background(), &diags, remoteConnector())

	// The masked remote password must never overwrite the configured value.
	assert.Equal(t, "s3cret", m.Password.ValueString())
	assert.True(t, m.AuthToken.IsNull())
	assert.Equal(t, "svc", m.Username.ValueString())
}

func TestContainerRegistryRefreshFromRemote_ImportLeavesSecretsNull(t *testing.T) {
	// After import the model only has an ID; secrets are unknown to Terraform.
	m := ContainerRegistryModel{
		ID:        types.StringValue("conn-1"),
		Password:  types.StringNull(),
		AuthToken: types.StringNull(),
	}
	var diags diag.Diagnostics
	m.RefreshFromRemote(context.Background(), &diags, remoteConnector())
	assert.True(t, m.Password.IsNull(), "password must not be populated from the API")
	assert.True(t, m.AuthToken.IsNull())
}

func TestContainerRegistryRefreshFromRemote_ResolvesUnknownsAndNulls(t *testing.T) {
	m := baseRegistryModel()
	var diags diag.Diagnostics
	m.RefreshFromRemote(context.Background(), &diags, remoteConnector())

	assert.Equal(t, "conn-1", m.ID.ValueString())
	assert.Equal(t, "t-1", m.TenantID.ValueString())
	assert.True(t, m.Enabled.ValueBool())
	assert.False(t, m.InsecurePull.ValueBool())
	assert.False(t, m.AllowStaticIPs.IsUnknown())
	assert.False(t, m.AllowStaticIPs.ValueBool())
	assert.Equal(t, "INCLUDE", m.FilterType.ValueString(), "filter_type defaults to INCLUDE")
	assert.True(t, m.RegistryType.IsNull())

	// Empty remote strings for unset optional attributes map to null, not "".
	for name, v := range map[string]types.String{
		"cloud_provider": m.CloudProvider,
		"region":         m.Region,
		"broker_type":    m.BrokerType,
		"broker_id":      m.BrokerID,
		"ca_certificate": m.CACertificate,
		"repository":     m.Repository,
		"ip_identifier":  m.IPIdentifier,
	} {
		assert.Truef(t, v.IsNull(), "%s should be null, got %v", name, v)
	}

	require.NotNil(t, m.InitialScanConfiguration)
	assert.Equal(t, "ALL", m.InitialScanConfiguration.Mode.ValueString())
	assert.True(t, m.InitialScanConfiguration.NumDays.IsNull())
	assert.Nil(t, m.AssetScopeFilters)
	assert.Nil(t, m.GitLab)
	assert.Nil(t, m.DockerHub)
	assert.Nil(t, m.OpenShift)
}

func TestContainerRegistryRefreshFromRemote_VendorBlockChosenByVendor(t *testing.T) {
	remote := remoteConnector()
	remote.Vendor = "DOCKER_HUB"
	remote.VendorSpecificConfiguration = &cwpTypes.VendorSpecificConfig{Repository: "my-repo"}

	m := baseRegistryModel()
	var diags diag.Diagnostics
	m.RefreshFromRemote(context.Background(), &diags, remote)
	require.NotNil(t, m.DockerHub)
	assert.Equal(t, "my-repo", m.DockerHub.Repository.ValueString())
	assert.Nil(t, m.GitLab)
	assert.Nil(t, m.OpenShift)

	// An all-empty vendor block is treated as absent.
	remote.VendorSpecificConfiguration = &cwpTypes.VendorSpecificConfig{}
	m.RefreshFromRemote(context.Background(), &diags, remote)
	assert.Nil(t, m.DockerHub)
}

func TestContainerRegistryRoundTrip(t *testing.T) {
	m := baseRegistryModel()
	m.Vendor = types.StringValue("GITLAB_CONTAINER_REGISTRY")
	m.GitLab = &GitLabConfigModel{
		GroupIDs:      types.StringValue("7"),
		ProjectIDs:    types.StringNull(),
		APIDomainName: types.StringNull(),
	}
	m.InitialScanConfiguration = &InitialScanConfigurationModel{
		Mode:    types.StringValue("TAGS_MODIFIED_DAYS"),
		NumDays: types.Int64Value(14),
	}
	m.AssetScopeFilters = &shared.RootFilterModel{
		Or: []shared.NestedFilterModel{{
			SearchField: types.StringValue("Registry"),
			SearchType:  types.StringValue("EQ"),
			SearchValue: types.StringValue("team/app"),
		}},
	}

	var diags diag.Diagnostics
	req := m.ToRequest(context.Background(), &diags)

	// Simulate the API echoing the request back via JSON.
	raw, err := json.Marshal(req)
	require.NoError(t, err)
	var remote cwpTypes.RegistryConnector
	require.NoError(t, json.Unmarshal(raw, &remote))
	remote.ConnectorID = "conn-9"
	remote.Password = "" // API does not return the secret

	got := m
	got.RefreshFromRemote(context.Background(), &diags, &remote)
	require.False(t, diags.HasError())

	assert.Equal(t, "conn-9", got.ID.ValueString())
	assert.Equal(t, "s3cret", got.Password.ValueString())
	assert.Equal(t, int64(14), got.InitialScanConfiguration.NumDays.ValueInt64())
	require.NotNil(t, got.GitLab)
	assert.Equal(t, "7", got.GitLab.GroupIDs.ValueString())
	assert.True(t, got.GitLab.ProjectIDs.IsNull())
	require.NotNil(t, got.AssetScopeFilters)
	require.Len(t, got.AssetScopeFilters.Or, 1)
	assert.Equal(t, "team/app", got.AssetScopeFilters.Or[0].SearchValue.ValueString())
}
