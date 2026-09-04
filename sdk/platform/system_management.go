// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
)

// GetUser retrieves the specified user in your environment.
func (c *Client) GetUser(ctx context.Context, userEmail string) (types.User, error) {
	var ans types.User
	resp, err := c.ListUsers(ctx)
	if err != nil {
		return ans, mapError(err)
	}
	for _, user := range resp {
		if user.Email == userEmail {
			ans = user
			return ans, nil
		}
	}
	return ans, fmt.Errorf("no user found with email \"%s\"", userEmail)
}

// ListUsers retrieves a list of the current users in your environment.
func (c *Client) ListUsers(ctx context.Context) ([]types.User, error) {
	var ans []types.User
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListUsersEndpoint, nil, nil, nil, &ans, &client.DoOptions{
		ResponseWrapperKeys: []string{"reply"},
	})
	return ans, mapError(err)
}

func (c *Client) ListAllRoles(ctx context.Context) (*types.ListRolesResponse, error) {
	var resp types.ListRolesResponse
	_, err := c.internalClient.Do(ctx, http.MethodGet, RoleEndpoint, nil, nil, nil, &resp, &client.DoOptions{})
	return &resp, mapError(err)
}

func (c *Client) CreateRole(ctx context.Context, req types.RoleCreateRequest) (*types.RoleCreateResponse, error) {
	var raw struct {
		Data struct {
			Message string `json:"message"`
		} `json:"data"`
	}
	_, err := c.internalClient.Do(ctx, http.MethodPost, RoleEndpoint, nil, nil, req.RequestData, &raw,
		&client.DoOptions{
			RequestWrapperKeys: []string{"request_data"},
		},
	)
	if err != nil {
		return nil, mapError(err)
	}

	roleID := ""
	if raw.Data.Message != "" {
		re := regexp.MustCompile(`(?i)\brole_id\s+([^\s]+)\s+created`)
		if m := re.FindStringSubmatch(raw.Data.Message); len(m) == 2 {
			roleID = m[1]
		}
	}

	return &types.RoleCreateResponse{
		RoleID: roleID,
	}, nil
}

func (c *Client) DeleteRole(ctx context.Context, roleID string) error {
	_, err := c.internalClient.Do(ctx, http.MethodDelete, RoleEndpoint, &[]string{roleID}, nil, nil, nil, &client.DoOptions{})
	return mapError(err)
}

func (c *Client) ListPermissionConfigs(ctx context.Context) (*types.ListPermissionConfigsResponse, error) {
	var resp types.ListPermissionConfigsResponse
	_, err := c.internalClient.Do(ctx, http.MethodGet, PermissionConfigEndpoint, nil, nil, nil, &resp, &client.DoOptions{})
	return &resp, mapError(err)
}

// SetRole adds or removes one or more users from a role.
//
// If no RoleId is provided in the SetRoleRequest, the user is removed from a role.
func (c *Client) SetRole(ctx context.Context, input types.SetRoleRequest) (types.SetRoleResponse, error) {
	var ans types.SetRoleResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, SetUserRoleEndpoint, nil, nil, input, &ans, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return ans, mapError(err)
}

// GetRiskScore retrieves the risk score of a specific user or endpoint in your environment,
// along with the reason for the score.
func (c *Client) GetRiskScore(ctx context.Context, req types.GetRiskScoreRequest) (types.GetRiskScoreResponse, error) {
	var ans types.GetRiskScoreResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, GetRiskScoreEndpoint, nil, nil, req, &ans, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})

	return ans, mapError(err)
}

// ListRiskyUsers retrieves a list of users with the highest risk score in your environment
// along with the reason affecting each score.
func (c *Client) ListRiskyUsers(ctx context.Context) ([]types.ListRiskyUsersResponse, error) {
	var ans []types.ListRiskyUsersResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListRiskyUsersEndpoint, nil, nil, nil, &ans, &client.DoOptions{
		ResponseWrapperKeys: []string{"reply"},
	})
	return ans, mapError(err)
}

// ListRiskyHosts retrieves a list of endpoints with the highest risk score in your environment
// along with the reason affecting each score.
func (c *Client) ListRiskyHosts(ctx context.Context) ([]types.ListRiskyHostsResponse, error) {
	var ans []types.ListRiskyHostsResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListRiskyHostsEndpoint, nil, nil, nil, &ans, &client.DoOptions{
		ResponseWrapperKeys: []string{"reply"},
	})
	return ans, mapError(err)
}

// HealthCheck performs a health check on the service.
func (c *Client) HealthCheck(ctx context.Context) (types.HealthCheckResponse, error) {
	var ans types.HealthCheckResponse
	_, err := c.internalClient.Do(ctx, http.MethodGet, HealthCheckEndpoint, nil, nil, nil, &ans, &client.DoOptions{
		ResponseWrapperKeys: []string{"reply"},
	})
	return ans, mapError(err)
}

// GetTenantInfo retrieves information about the specified tenants.
func (c *Client) GetTenantInfo(ctx context.Context, req types.GetTenantInfoRequest) ([]types.TenantInfo, error) {
	var ans []types.TenantInfo
	_, err := c.internalClient.Do(ctx, http.MethodPost, GetTenantInfoEndpoint, nil, nil, req, &ans, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return ans, mapError(err)
}

// ListUserGroups retrieves a list of all user groups.
func (c *Client) ListUserGroups(ctx context.Context) ([]types.UserGroup, error) {
	var ans []types.UserGroup
	_, err := c.internalClient.Do(ctx, http.MethodGet, UserGroupEndpoint, nil, nil, nil, &ans, &client.DoOptions{
		ResponseWrapperKeys: []string{"data"},
	})
	return ans, mapError(err)
}

// GetUserGroup retrieves information about the specified user groups.
func (c *Client) GetUserGroup(ctx context.Context, req types.GetUserGroupRequest) ([]types.UserGroup, error) {
	var ans []types.UserGroup
	_, err := c.internalClient.Do(ctx, http.MethodPost, GetUserGroupEndpoint, nil, nil, req, &ans, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply", "data"},
	})
	return ans, mapError(err)
}

// CreateUserGroup creates a new user group and returns its ID.
func (c *Client) CreateUserGroup(ctx context.Context, req types.UserGroupCreateRequest) (string, error) {
	var resp types.UserGroupCreateResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, UserGroupEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"data"},
	})
	if err != nil {
		return "", mapError(err)
	}

	// Message is "user group with group id <id> created successfully"
	parts := strings.Split(resp.Message, " ")
	if len(parts) < 6 || parts[0] != "user" || parts[1] != "group" {
		return "", fmt.Errorf("unexpected create user group response message: %s", resp.Message)
	}
	groupID := parts[5]
	return groupID, nil
}

// EditUserGroup edits an existing user group.
// It takes a groupID and a UserGroupEditRequest object containing the fields to update.
func (c *Client) EditUserGroup(ctx context.Context, groupID string, req types.UserGroupEditRequest) (string, error) {
	var resp types.UserGroupEditResponse
	_, err := c.internalClient.Do(ctx, http.MethodPatch, UserGroupEndpoint, &[]string{groupID}, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"data"},
	})
	return resp.Message, mapError(err)
}

// DeleteUserGroup deletes an existing user group by its ID.
func (c *Client) DeleteUserGroup(ctx context.Context, groupID string) (string, error) {
	var resp types.UserGroupDeleteResponse
	_, err := c.internalClient.Do(ctx, http.MethodDelete, UserGroupEndpoint, &[]string{groupID}, nil, nil, &resp, &client.DoOptions{
		ResponseWrapperKeys: []string{"data"},
	})
	return resp.Message, mapError(err)
}

// ListIAMUsers retrieves a list of all users and their respective properties.
func (c *Client) ListIAMUsers(ctx context.Context) (*types.ListIamUsersResponse, error) {
	var ans types.ListIamUsersResponse
	_, err := c.internalClient.Do(ctx, http.MethodGet, IamUsersEndpoint, nil, nil, nil, &ans, nil)
	if err != nil {
		return nil, mapError(err)
	}
	return &ans, nil
}

// GetIAMUser retrieves a user and its respective properties.
func (c *Client) GetIAMUser(ctx context.Context, userEmail string) (*types.IamUser, error) {
	var ans types.GetIamUserResponse
	if _, err := c.internalClient.Do(ctx, http.MethodGet, IamUsersEndpoint, &[]string{userEmail}, nil, nil, &ans, nil); err != nil {
		return nil, mapError(err)
	}
	return &ans.Data, nil
}

// EditIAMUser edits an existing user.
func (c *Client) EditIAMUser(ctx context.Context, userEmail string, req types.IamUserEditRequest) (string, error) {
	var resp struct {
		Data struct {
			Message string `json:"message"`
		} `json:"data"`
	}
	// The request body is wrapped in {"request_data": ...} as seen in other API calls.
	_, err := c.internalClient.Do(ctx, http.MethodPatch, IamUsersEndpoint, &[]string{userEmail}, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys: []string{"request_data"},
	})
	return resp.Data.Message, mapError(err)
}

// GetScope retrieves the scope for the given entity type and ID.
func (c *Client) GetScope(ctx context.Context, entityType, entityID string) (*types.Scope, error) {
	var scope types.Scope
	_, err := c.internalClient.Do(ctx, http.MethodGet, ScopeEndpoint, &[]string{entityType, entityID}, nil, nil, &scope, &client.DoOptions{
		ResponseWrapperKeys: []string{"data"},
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &scope, nil
}

// EditScope modifies the scope for the given entity type and ID.
func (c *Client) EditScope(ctx context.Context, entityType, entityID string, req types.EditScopeRequestData) error {
	_, err := c.internalClient.Do(ctx, http.MethodPut, ScopeEndpoint, &[]string{entityType, entityID}, nil, req, nil, &client.DoOptions{
		RequestWrapperKeys: []string{"request_data"},
	})
	return mapError(err)
}
