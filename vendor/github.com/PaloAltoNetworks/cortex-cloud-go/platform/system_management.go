// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"net/http"
)

type User struct {
	UserEmail     string   `json:"user_email"`
	UserFirstName string   `json:"user_first_name"`
	UserLastName  string   `json:"user_last_name"`
	RoleName      string   `json:"role_name"`
	LastLoggedIn  int      `json:"last_logged_in"`
	UserType      string   `json:"user_type"`
	Groups        []string `json:"groups"`
	Scope         []string `json:"scope"`
}

type Reason struct {
	DateCreated string `json:"date_created"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Points      int    `json:"points"`
}

// ---------------------------
// Request/Response structs
// ---------------------------

type ListUsersResponse struct {
	Users []User `json:"reply"`
}

type ListRolesRequest struct {
	RequestData ListRolesRequestData `json:"request_data" validate:"required"`
}

type ListRolesRequestData struct {
	// TODO: add validation tag/function for role names?
	RoleNames []string `json:"role_names" validate:"required,min=1"`
}

type SetRoleRequest struct {
	RequestData SetRoleRequestData `json:"request_data" validate:"required"`
}

type SetRoleRequestData struct {
	UserEmails []string `json:"user_emails" validate:"required,min=1,dive,required,email"`
	RoleName   string   `json:"role_name"`
}

type GetRiskScoreRequest struct {
	RequestData GetRiskScoreRequestData `json:"request_data" validate:"required"`
}

type GetRiskScoreRequestData struct {
	Id string `json:"id" validate:"required,sysmgmtID"`
}

type SetRoleResponseReply struct {
	UpdateCount string `json:"update_count"`
}

type SetRoleResponse struct {
	Reply SetRoleResponseReply `json:"reply"`
}

type GetRiskScoreResponseReply struct {
	Type          string   `json:"type"`
	Id            string   `json:"id"`
	Score         int      `json:"score"`
	NormRiskScore int      `json:"norm_risk_score"`
	RiskLevel     string   `json:"risk_level"`
	Reasons       []Reason `json:"reasons"`
	Email         string   `json:"email"`
}

type GetRiskScoreResponse struct {
	Reply GetRiskScoreResponseReply `json:"reply"`
}

type ListRiskyUsersResponseReply struct {
	Type          string   `json:"type"`
	Id            string   `json:"id"`
	Score         int      `json:"score"`
	NormRiskScore int      `json:"norm_risk_score"`
	RiskLevel     string   `json:"risk_level"`
	Reasons       []Reason `json:"reasons"`
	Email         string   `json:"email"`
}

type ListRiskyUsersResponse struct {
	Reply []ListRiskyUsersResponseReply `json:"reply"`
}

type ListRiskyHostsResponseReply struct {
	Type          string   `json:"type"`
	Id            string   `json:"id"`
	Score         int      `json:"score"`
	NormRiskScore int      `json:"norm_risk_score"`
	RiskLevel     string   `json:"risk_level"`
	Reasons       []Reason `json:"reasons"`
}

type ListRiskyHostsResponse struct {
	Reply []ListRiskyHostsResponseReply `json:"reply"`
}

// ---------------------------
// Request functions
// ---------------------------

// List retrieves a list of the current users in your environment.
func (c *Client) ListUsers(ctx context.Context) (ListUsersResponse, error) {

	var ans ListUsersResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListUsersEndpoint, nil, nil, nil, &ans)

	return ans, err
}

func (c *Client) ListRoles(ctx context.Context, input ListRolesRequest) (ListUsersResponse, error) {
	var ans ListUsersResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListRolesEndpoint, nil, nil, input, &ans)

	return ans, err
}

// SetRole adds or removes one or more users from a role.
//
// If no RoleName is provided in the SetRoleRequest, the user is removed from a role.
func (c *Client) SetRole(ctx context.Context, input SetRoleRequest) (SetRoleResponse, error) {
	var ans SetRoleResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, SetUserRoleEndpoint, nil, nil, input, &ans)

	return ans, err
}

// GetRiskScore retrieves the risk score of a specific user or endpoint in your environment,
// along with the reason for the score.
func (c *Client) GetRiskScore(ctx context.Context, input GetRiskScoreRequest) (GetRiskScoreResponse, error) {
	var ans GetRiskScoreResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, GetRiskScoreEndpoint, nil, nil, input, &ans)

	return ans, err
}

// Retrieve a list of users with the highest risk score in your environment
// along with the reason affecting each score.
func (c *Client) ListRiskyUsers(ctx context.Context) (ListRiskyUsersResponse, error) {
	var ans ListRiskyUsersResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListRiskyUsersEndpoint, nil, nil, nil, &ans)

	return ans, err
}

// Retrieve a list of endpoints with the highest risk score in your environment
// along with the reason affecting each score.
func (c *Client) ListRiskyHosts(ctx context.Context) (ListRiskyHostsResponse, error) {
	var ans ListRiskyHostsResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListRiskyHostsEndpoint, nil, nil, nil, &ans)

	return ans, err
}
