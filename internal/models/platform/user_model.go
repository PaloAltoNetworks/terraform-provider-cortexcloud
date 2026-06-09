// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	platformtypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// UserModel is the model for the user resource.
type UserModel struct {
	Email        types.String `tfsdk:"user_email"`
	FirstName    types.String `tfsdk:"user_first_name"`
	LastName     types.String `tfsdk:"user_last_name"`
	PhoneNumber  types.String `tfsdk:"phone_number"`
	Status       types.String `tfsdk:"status"`
	RoleName     types.String `tfsdk:"role_name"`
	LastLoggedIn types.Int64  `tfsdk:"last_logged_in"`
	Hidden       types.Bool   `tfsdk:"hidden"`
	UserType     types.String `tfsdk:"user_type"`
	GroupIDs     types.List   `tfsdk:"group_ids"` // write intent
	Groups       types.List   `tfsdk:"groups"`    // read-only echo
}

// ToEditRequest converts the model to an IamUserEditRequest for the SDK.
func (m *UserModel) ToEditRequest() platformtypes.IamUserEditRequest {
	var groups []string
	if !m.GroupIDs.IsNull() && !m.GroupIDs.IsUnknown() {
		var ids []types.String
		diags := m.GroupIDs.ElementsAs(context.Background(), &ids, false)
		_ = diags

		for _, id := range ids {
			if !id.IsNull() && !id.IsUnknown() {
				groups = append(groups, id.ValueString())
			}
		}
	}

	return platformtypes.IamUserEditRequest{
		FirstName:   m.FirstName.ValueStringPointer(),
		LastName:    m.LastName.ValueStringPointer(),
		RoleId:      m.RoleName.ValueStringPointer(),
		PhoneNumber: m.PhoneNumber.ValueStringPointer(),
		Status:      m.Status.ValueStringPointer(),
		Hidden:      m.Hidden.ValueBoolPointer(),
		UserGroups:  groups,
	}
}

// RefreshFromRemote populates the model from the SDK's IamUser object.
func (m *UserModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *platformtypes.IamUser) {
	if remote == nil {
		diags.AddError("User not found", "The requested user does not exist.")
		return
	}
	m.Email = types.StringValue(remote.Email)
	m.FirstName = types.StringValue(remote.FirstName)
	m.LastName = types.StringValue(remote.LastName)
	m.PhoneNumber = types.StringValue(remote.PhoneNumber)
	m.Status = types.StringValue(remote.Status)
	m.RoleName = types.StringValue(remote.RoleName)
	m.LastLoggedIn = types.Int64Value(remote.LastLoggedIn)
	m.Hidden = types.BoolValue(remote.Hidden)
	m.UserType = types.StringValue(remote.UserType)

	objType := types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"group_id":   types.StringType,
			"group_name": types.StringType,
		},
	}

	if len(remote.Groups) == 0 {
		m.Groups = types.ListNull(objType)
		return
	}

	elems := make([]attr.Value, 0, len(remote.Groups))
	for _, g := range remote.Groups {
		ov, d := types.ObjectValue(
			objType.AttrTypes,
			map[string]attr.Value{
				"group_id":   types.StringValue(g.GroupID),
				"group_name": types.StringValue(g.GroupName),
			},
		)
		diags.Append(d...)
		elems = append(elems, ov)
	}

	lv, d := types.ListValue(objType, elems)
	diags.Append(d...)
	m.Groups = lv

}
