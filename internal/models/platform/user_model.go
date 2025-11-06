// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	platformtypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// UserModel is the model for the user resource.
type UserModel struct {
	Email        types.String       `tfsdk:"user_email"`
	FirstName    types.String       `tfsdk:"user_first_name"`
	LastName     types.String       `tfsdk:"user_last_name"`
	PhoneNumber  types.String       `tfsdk:"phone_number"`
	Status       types.String       `tfsdk:"status"`
	RoleName     types.String       `tfsdk:"role_name"`
	LastLoggedIn types.Int64        `tfsdk:"last_logged_in"`
	Hidden       types.Bool         `tfsdk:"hidden"`
	UserType     types.String       `tfsdk:"user_type"`
	Groups       []NestedGroupModel `tfsdk:"groups"`
}

// ToEditRequest converts the model to an IamUserEditRequest for the SDK.
func (m *UserModel) ToEditRequest() platformtypes.IamUserEditRequest {
	var groups []string
	for _, g := range m.Groups {
		if !g.GroupID.IsNull() && !g.GroupID.IsUnknown() {
			groups = append(groups, g.GroupID.ValueString())
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

	if len(remote.Groups) == 0 {
		m.Groups = nil
	} else {
		m.Groups = make([]NestedGroupModel, len(remote.Groups))
		for i, g := range remote.Groups {
			m.Groups[i] = NestedGroupModel{
				GroupID:   types.StringValue(g.GroupID),
				GroupName: types.StringValue(g.GroupName),
			}
		}
	}
}
