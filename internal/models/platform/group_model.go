// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

//import (
//	"context"
//
//	cortexTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types"
//	"github.com/hashicorp/terraform-plugin-framework/diag"
//	"github.com/hashicorp/terraform-plugin-framework/types"
//	"github.com/hashicorp/terraform-plugin-log/tflog"
//)
//
//// GroupModel is the model for the Group data source.
//type GroupModel struct {
//	Name         types.String `tfsdk:"name"`
//	Description  types.String `tfsdk:"description"`
//	UserCount    types.Int64  `tfsdk:"user_count"`
//	IsDefault    types.Bool   `tfsdk:"is_default"`
//	CreationTime types.Int64  `tfsdk:"creation_time"`
//	LastModified types.Int64  `tfsdk:"last_modified"`
//}
//
//// RefreshFromRemote refreshes the GroupModel with the response from the API.
//func (m *GroupModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *cortexTypes.UserGroup) {
//	tflog.Debug(ctx, "Refreshing group model from remote")
//
//	tflog.Trace(ctx, "Setting group attributes")
//	m.Name = types.StringValue(remote.Name)
//	m.Description = types.StringValue(remote.Description)
//	m.UserCount = types.Int64Value(int64(remote.UserCount))
//	m.IsDefault = types.BoolValue(remote.IsDefault)
//	m.CreationTime = types.Int64Value(remote.CreationTime)
//	m.LastModified = types.Int64Value(remote.LastModified)
//}
