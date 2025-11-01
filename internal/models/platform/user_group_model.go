// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// NestedGroupModel is the model for a nested user group.
type NestedGroupModel struct {
	GroupID   types.String `tfsdk:"group_id"`
	GroupName types.String `tfsdk:"group_name"`
}

// UserGroupModel is the model for the user_group resource.
type UserGroupModel struct {
	ID             types.String       `tfsdk:"id"`
	Name           types.String       `tfsdk:"name"`
	Description    types.String       `tfsdk:"description"`
	RoleName       types.String       `tfsdk:"role_name"`
	PrettyRoleName types.String       `tfsdk:"pretty_role_name"`
	CreatedBy      types.String       `tfsdk:"created_by"`
	UpdatedBy      types.String       `tfsdk:"updated_by"`
	CreatedTS      types.Int64        `tfsdk:"created_ts"`
	UpdatedTS      types.Int64        `tfsdk:"updated_ts"`
	Users          []string           `tfsdk:"users"`
	GroupType      types.String       `tfsdk:"group_type"`
	NestedGroups   []NestedGroupModel `tfsdk:"nested_groups"`
	IDPGroups      []string           `tfsdk:"idp_groups"`
}

// ToCreateRequest converts the model to a CreateUserGroup request for the SDK.
func (m *UserGroupModel) ToCreateRequest() platformTypes.UserGroup {
	return platformTypes.UserGroup{
		GroupName:   m.Name.ValueString(),
		Description: m.Description.ValueString(),
		RoleName:    m.RoleName.ValueString(),
		Users:       m.Users,
		IDPGroups:   m.IDPGroups,
	}
}

// ToEditRequest converts the model to an UserGroupEditRequest for the SDK.
func (m *UserGroupModel) ToEditRequest() platformTypes.UserGroup {
	return platformTypes.UserGroup{
		GroupName:   m.Name.ValueString(),
		Description: m.Description.ValueString(),
		RoleName:    m.RoleName.ValueString(),
		Users:       m.Users,
		IDPGroups:   m.IDPGroups,
		UpdatedBy:   m.UpdatedBy.ValueString(),
	}
}

// RefreshFromRemote populates the model from the SDK's UserGroup object.
func (m *UserGroupModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *platformTypes.UserGroup) {
	if remote == nil {
		diags.AddError("User Group not found", "The requested user group does not exist.")
		return
	}
	m.ID = types.StringValue(remote.GroupID)
	m.Name = types.StringValue(remote.GroupName)
	m.Description = types.StringValue(remote.Description)
	m.RoleName = types.StringValue(remote.RoleName)
	m.PrettyRoleName = types.StringValue(remote.PrettyRoleName)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.UpdatedBy = types.StringValue(remote.UpdatedBy)
	m.CreatedTS = types.Int64Value(remote.CreatedTS)
	m.UpdatedTS = types.Int64Value(remote.UpdatedTS)
	m.Users = remote.Users
	m.GroupType = types.StringValue(remote.GroupType)
	m.IDPGroups = remote.IDPGroups

	m.NestedGroups = make([]NestedGroupModel, len(remote.NestedGroups))
	for i, ng := range remote.NestedGroups {
		m.NestedGroups[i] = NestedGroupModel{
			GroupID:   types.StringValue(ng.GroupID),
			GroupName: types.StringValue(ng.GroupName),
		}
	}
}
