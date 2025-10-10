// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// UserModel is the model for the User data source.
type UserModel struct {
	Email        types.String `tfsdk:"email"`
	FirstName    types.String `tfsdk:"first_name"`
	LastName     types.String `tfsdk:"last_name"`
	RoleName     types.String `tfsdk:"role_name"`
	LastLoggedIn types.Int64  `tfsdk:"last_logged_in"`
	UserType     types.String `tfsdk:"user_type"`
	Groups       types.List   `tfsdk:"groups"`
	Scope        *ScopeModel  `tfsdk:"scope"`
}

// ScopeModel is the model for the Scope object.
type ScopeModel struct {
	Endpoints   *EndpointsModel   `tfsdk:"endpoints"`
	CasesIssues *CasesIssuesModel `tfsdk:"cases_issues"`
}

// EndpointsModel is the model for the Endpoints object.
type EndpointsModel struct {
	EndpointGroups *EndpointGroupsModel `tfsdk:"endpoint_groups"`
	EndpointTags   *EndpointTagsModel   `tfsdk:"endpoint_tags"`
	Mode           types.String         `tfsdk:"mode"`
}

// EndpointGroupsModel is the model for the EndpointGroups object.
type EndpointGroupsModel struct {
	IDs  types.List   `tfsdk:"ids"`
	Mode types.String `tfsdk:"mode"`
}

// EndpointTagsModel is the model for the EndpointTags object.
type EndpointTagsModel struct {
	IDs  types.List   `tfsdk:"ids"`
	Mode types.String `tfsdk:"mode"`
}

// CasesIssuesModel is the model for the CasesIssues object.
type CasesIssuesModel struct {
	IDs  types.List   `tfsdk:"ids"`
	Mode types.String `tfsdk:"mode"`
}

// ToGetRequest converts the UserModel to a GetUserRequest.
func (m *UserModel) ToGetRequest(ctx context.Context, diags *diag.Diagnostics) *platformTypes.GetUserRequest {
	return &platformTypes.GetUserRequest{
		Email: m.Email.ValueString(),
	}
}

// RefreshFromRemote refreshes the UserModel with the response from the API.
func (m *UserModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, resp *platformTypes.User) {
	tflog.Debug(ctx, "Refreshing user model from remote")
	m.Email = types.StringValue(resp.Email)
	m.FirstName = types.StringValue(resp.FirstName)
	m.LastName = types.StringValue(resp.LastName)
	m.RoleName = types.StringValue(resp.RoleName)
	m.LastLoggedIn = types.Int64Value(int64(resp.LastLoggedIn))
	m.UserType = types.StringValue(resp.UserType)

	tflog.Trace(ctx, "Converting groups to Terraform type")
	groups, d := types.ListValueFrom(ctx, types.StringType, resp.Groups)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	m.Groups = groups

	tflog.Trace(ctx, "Initializing scope models if nil")
	if m.Scope == nil {
		m.Scope = &ScopeModel{}
	}
	if m.Scope.Endpoints == nil {
		m.Scope.Endpoints = &EndpointsModel{}
	}
	if m.Scope.Endpoints.EndpointGroups == nil {
		m.Scope.Endpoints.EndpointGroups = &EndpointGroupsModel{}
	}
	if m.Scope.Endpoints.EndpointTags == nil {
		m.Scope.Endpoints.EndpointTags = &EndpointTagsModel{}
	}
	if m.Scope.CasesIssues == nil {
		m.Scope.CasesIssues = &CasesIssuesModel{}
	}

	tflog.Trace(ctx, "Converting endpoint group IDs to Terraform type")
	if resp.Scope.Endpoints.EndpointGroups.IDs != nil {
		endpointGroupsIDs, d := types.ListValueFrom(ctx, types.StringType, resp.Scope.Endpoints.EndpointGroups.IDs)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		m.Scope.Endpoints.EndpointGroups.IDs = endpointGroupsIDs
	} else {
		m.Scope.Endpoints.EndpointGroups.IDs = types.ListNull(types.StringType)
	}
	m.Scope.Endpoints.EndpointGroups.Mode = types.StringValue(resp.Scope.Endpoints.EndpointGroups.Mode)

	tflog.Trace(ctx, "Converting endpoint tag IDs to Terraform type")
	if resp.Scope.Endpoints.EndpointTags.IDs != nil {
		endpointTagsIDs, d := types.ListValueFrom(ctx, types.StringType, resp.Scope.Endpoints.EndpointTags.IDs)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		m.Scope.Endpoints.EndpointTags.IDs = endpointTagsIDs
	} else {
		m.Scope.Endpoints.EndpointTags.IDs = types.ListNull(types.StringType)
	}
	m.Scope.Endpoints.EndpointTags.Mode = types.StringValue(resp.Scope.Endpoints.EndpointTags.Mode)
	m.Scope.Endpoints.Mode = types.StringValue(resp.Scope.Endpoints.Mode)

	tflog.Trace(ctx, "Converting cases/issues IDs to Terraform type")
	if resp.Scope.CasesIssues.IDs != nil {
		casesIssuesIDs, d := types.ListValueFrom(ctx, types.StringType, resp.Scope.CasesIssues.IDs)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		m.Scope.CasesIssues.IDs = casesIssuesIDs
	} else {
		m.Scope.CasesIssues.IDs = types.ListNull(types.StringType)
	}
	m.Scope.CasesIssues.Mode = types.StringValue(resp.Scope.CasesIssues.Mode)
}
