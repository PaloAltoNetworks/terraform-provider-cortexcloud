// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	platformtypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
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
	GroupName      types.String       `tfsdk:"group_name"`
	Description    types.String       `tfsdk:"description"`
	RoleID         types.String       `tfsdk:"role_id"`
	PrettyRoleName types.String       `tfsdk:"pretty_role_name"`
	CreatedBy      types.String       `tfsdk:"created_by"`
	CreatedTS      types.Int64        `tfsdk:"created_ts"`
	UpdatedTS      types.Int64        `tfsdk:"updated_ts"`
	Users          types.Set          `tfsdk:"users"`
	AllUsers       types.Set          `tfsdk:"all_users"`
	GroupType      types.String       `tfsdk:"group_type"`
	NestedGroups   []NestedGroupModel `tfsdk:"nested_groups"` // read-only objects (from list)
	IDPGroups      types.Set          `tfsdk:"idp_groups"`
}

// ToCreateRequest converts the model to a CreateUserGroup request for the SDK.
func (m *UserGroupModel) ToCreateRequest(ctx context.Context, diagnostics *diag.Diagnostics) platformtypes.UserGroupCreateRequest {
	var nestedGroupIDs []string
	for _, ng := range m.NestedGroups {
		if !ng.GroupID.IsNull() && !ng.GroupID.IsUnknown() {
			nestedGroupIDs = append(nestedGroupIDs, ng.GroupID.ValueString())
		}
	}

	users := make([]string, len(m.Users.Elements()))
	diagnostics.Append(m.Users.ElementsAs(ctx, &users, false)...)

	idpGroups := make([]string, len(m.IDPGroups.Elements()))
	diagnostics.Append(m.IDPGroups.ElementsAs(ctx, &idpGroups, false)...)

	if diagnostics.HasError() {
		return platformtypes.UserGroupCreateRequest{}
	}

	return platformtypes.UserGroupCreateRequest{
		GroupName:    m.GroupName.ValueString(),
		Description:  m.Description.ValueString(),
		RoleName:     m.RoleID.ValueString(),
		Users:        users,
		NestedGroups: nestedGroupIDs,
		IDPGroups:    idpGroups,
	}
}

// ToEditRequest converts the model to an UserGroupEditRequest for the SDK.
func (m *UserGroupModel) ToEditRequest(ctx context.Context, diagnostics *diag.Diagnostics) platformtypes.UserGroupEditRequest {
	var nestedGroupIDs []string
	for _, ng := range m.NestedGroups {
		if !ng.GroupID.IsNull() && !ng.GroupID.IsUnknown() {
			nestedGroupIDs = append(nestedGroupIDs, ng.GroupID.ValueString())
		}
	}

	users := make([]string, len(m.Users.Elements()))
	diagnostics.Append(m.Users.ElementsAs(ctx, &users, false)...)

	idpGroups := make([]string, len(m.IDPGroups.Elements()))
	diagnostics.Append(m.IDPGroups.ElementsAs(ctx, &idpGroups, false)...)

	if diagnostics.HasError() {
		return platformtypes.UserGroupEditRequest{}
	}

	return platformtypes.UserGroupEditRequest{
		GroupName:      m.GroupName.ValueString(),
		Description:    m.Description.ValueString(),
		RoleName:       m.RoleID.ValueString(),
		Users:          users,
		NestedGroupIDs: nestedGroupIDs,
		IDPGroups:      idpGroups,
	}
}

// RefreshFromRemote populates the model from the SDK's UserGroup object.
func (m *UserGroupModel) RefreshFromRemote(ctx context.Context, diagnostics *diag.Diagnostics, remote *platformtypes.UserGroup) {
	if remote == nil {
		diagnostics.AddError("User Group not found", "The requested user group does not exist.")
		return
	}

	// Convert users (directly configured)
	//if len(m.Users.Elements()) == 0 {
	//	m.Users = types.SetNull(types.StringType)
	//} else {
	//	users, diags := types.SetValueFrom(ctx, types.StringType, remote.Users)
	//	diagnostics.Append(diags...)
	//	m.Users = users
	//}

	// Populate all users (returned from API)
	allUsers, diags := types.SetValueFrom(ctx, types.StringType, remote.Users)
	diagnostics.Append(diags...)
	m.AllUsers = allUsers

	// Convert IDP groups
	if len(remote.IDPGroups) == 0 {
		m.IDPGroups = types.SetNull(types.StringType)
	} else {
		idpGroups, diags := types.SetValueFrom(ctx, types.StringType, remote.IDPGroups)
		diagnostics.Append(diags...)
		m.IDPGroups = idpGroups
	}

	m.ID = types.StringValue(remote.GroupID)
	m.GroupName = types.StringValue(remote.GroupName)
	m.Description = types.StringValue(remote.Description)
	if remote.RoleName == "" {
		m.RoleID = types.StringNull()
	} else {
		m.RoleID = types.StringValue(remote.RoleName)
	}
	m.PrettyRoleName = types.StringValue(remote.PrettyRoleName)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.CreatedTS = types.Int64Value(remote.CreatedTS)
	m.UpdatedTS = types.Int64Value(remote.UpdatedTS)
	m.GroupType = types.StringValue(remote.GroupType)

	if len(remote.NestedGroups) == 0 {
		m.NestedGroups = nil
	} else {
		m.NestedGroups = make([]NestedGroupModel, len(remote.NestedGroups))
		for i, ng := range remote.NestedGroups {
			m.NestedGroups[i] = NestedGroupModel{
				GroupID:   types.StringValue(ng.GroupID),
				GroupName: types.StringValue(ng.GroupName),
			}
		}
	}
}
