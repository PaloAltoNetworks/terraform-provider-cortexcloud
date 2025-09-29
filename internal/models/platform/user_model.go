// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cortexTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
func (m *UserModel) ToGetRequest(ctx context.Context, diags *diag.Diagnostics) *cortexTypes.GetUserRequest {
	return &cortexTypes.GetUserRequest{
		Email: m.Email.ValueString(),
	}
}

// RefreshPropertyValues refreshes the UserModel with the response from the API.
func (m *UserModel) RefreshPropertyValues(ctx context.Context, diags *diag.Diagnostics, resp *cortexTypes.User) {
	m.Email = types.StringValue(resp.UserEmail)
	m.FirstName = types.StringValue(resp.UserFirstName)
	m.LastName = types.StringValue(resp.UserLastName)
	m.RoleName = types.StringValue(resp.RoleName)
	m.LastLoggedIn = types.Int64Value(int64(resp.LastLoggedIn))
	m.UserType = types.StringValue(resp.UserType)

	groups, d := types.ListValueFrom(ctx, types.StringType, resp.Groups)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	m.Groups = groups

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
