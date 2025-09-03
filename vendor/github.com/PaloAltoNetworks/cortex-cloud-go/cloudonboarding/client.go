// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"github.com/PaloAltoNetworks/cortex-cloud-go/api"
	"github.com/PaloAltoNetworks/cortex-cloud-go/internal/app"
)

// API endpoint path specification.
const (
	CreateInstanceTemplateEndpoint              = "public_api/v1/cloud_onboarding/create_instance_template"
	GetIntegrationInstanceDetailsEndpoint       = "public_api/v1/cloud_onboarding/get_instance_details"
	ListIntegrationInstancesEndpoint            = "public_api/v1/cloud_onboarding/get_instances"
	EditIntegrationInstanceEndpoint             = "public_api/v1/cloud_onboarding/edit_instance"
	EnableOrDisableIntegrationInstancesEndpoint = "public_api/v1/cloud_onboarding/enable_disable_instance"
	DeleteIntegrationInstancesEndpoint          = "public_api/v1/cloud_onboarding/delete_instance"
	ListAccountsByInstanceEndpoint              = "public_api/v1/cloud_onboarding/get_accounts"
	EnableDisableAccountsInInstancesEndpoint    = "public_api/v1/cloud_onboarding/enable_disable_account"
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
