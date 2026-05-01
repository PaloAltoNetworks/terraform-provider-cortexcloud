// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	shared "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// AssetGroupModel is the model for the asset_group resource.
type AssetGroupModel struct {
	ID                  types.Int64             `tfsdk:"id"`
	Name                types.String            `tfsdk:"name"`
	Type                types.String            `tfsdk:"type"`
	Description         types.String            `tfsdk:"description"`
	MembershipPredicate *shared.RootFilterModel `tfsdk:"membership_predicate"`
	CreationTime        types.Int64             `tfsdk:"creation_time"`
	CreatedBy           types.String            `tfsdk:"created_by"`
	LastUpdateTime      types.Int64             `tfsdk:"last_update_time"`
	ModifiedBy          types.String            `tfsdk:"modified_by"`
}

// RefreshFromRemote refreshes the model from the remote API response.
func (m *AssetGroupModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *platformTypes.AssetGroup) {
	tflog.Debug(ctx, "Refreshing asset group model from remote")

	tflog.Trace(ctx, "Setting asset group attributes")
	m.ID = types.Int64Value(int64(remote.ID))
	m.Name = types.StringValue(remote.Name)
	m.Type = types.StringValue(remote.Type)
	m.Description = types.StringValue(remote.Description)
	m.CreationTime = types.Int64Value(remote.CreationTime)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.LastUpdateTime = types.Int64Value(remote.LastUpdateTime)
	m.ModifiedBy = types.StringValue(remote.ModifiedBy)
	m.MembershipPredicate = shared.SDKToModel(ctx, remote.MembershipPredicate)
}
