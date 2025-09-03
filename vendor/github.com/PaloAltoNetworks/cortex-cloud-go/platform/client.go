// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"github.com/PaloAltoNetworks/cortex-cloud-go/api"
	"github.com/PaloAltoNetworks/cortex-cloud-go/internal/app"
)

// API endpoint path specification.
const (
	// Users, Roles and Groups
	ListUsersEndpoint      = "public_api/v1/rbac/get_users"
	ListRolesEndpoint      = "public_api/v1/rbac/get_roles"
	ListUserGroups         = "public_api/v1/rbac/get_user_group"
	SetUserRoleEndpoint    = "public_api/v1/rbac/set_user_role"
	GetRiskScoreEndpoint   = "public_api/v1/get_risk_score"
	ListRiskyUsersEndpoint = "public_api/v1/get_risky_users"
	ListRiskyHostsEndpoint = "public_api/v1/get_risky_hosts"
	// Authentication Settings
	ListIDPMetadataEndpoint = "public_api/v1/authentication-settings/get/metadata"
	ListAuthSettingsEndpoint = "public_api/v1/authentication-settings/get/settings"
	CreateAuthSettingsEndpoint = "public_api/v1/authentication-settings/create"
	UpdateAuthSettingsEndpoint = "public_api/v1/authentication-settings/update"
	DeleteAuthSettingsEndpoint = "public_api/v1/authentication-settings/delete"
)

// Client is the client for the namespace.
type Client struct {
	internalClient *app.Client
}

// NewClient returns a new client for this namespace.
func NewClient(config *api.Config) (*Client, error) {
	internalClient, err := app.NewClient(config)
	return &Client{internalClient: internalClient}, err
}
