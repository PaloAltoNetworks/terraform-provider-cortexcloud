// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"net/http"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
)

type listCloudAccountsByInstanceRequest struct {
	InstanceIDs string                 `json:"instance_id"`
	FilterData  filterTypes.FilterData `json:"filter_data"`
}

type listCloudAccountsByInstanceResponse struct {
	Data        []types.CloudAccount `json:"DATA"`
	FilterCount int                  `json:"FILTER_COUNT"`
	TotalCount  int                  `json:"TOTAL_COUNT"`
}

func (c *Client) ListCloudAccountsByInstance(ctx context.Context, instanceID string, filters filterTypes.FilterData) ([]types.CloudAccount, int, int, error) {
	var (
		req listCloudAccountsByInstanceRequest = listCloudAccountsByInstanceRequest{
			InstanceIDs: instanceID,
			FilterData:  filters,
		}
		resp listCloudAccountsByInstanceResponse
	)
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListAccountsByInstanceEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})

	return resp.Data, resp.FilterCount, resp.TotalCount, err
}

type enableDisableAccountsInInstancesRequest struct {
	Ids        []string `json:"ids"`
	InstanceId string   `json:"instance_id"`
	Enable     bool     `json:"enable"`
}

func (c *Client) EnableCloudAccounts(ctx context.Context, instanceID string, accountIDs []string) error {
	return c.toggleCloudAccounts(ctx, instanceID, accountIDs, true)
}

func (c *Client) DisableCloudAccounts(ctx context.Context, instanceID string, accountIDs []string) error {
	return c.toggleCloudAccounts(ctx, instanceID, accountIDs, false)
}

func (c *Client) toggleCloudAccounts(ctx context.Context, instanceIDs string, accountIDs []string, enable bool) error {
	req := enableDisableAccountsInInstancesRequest{
		InstanceId: instanceIDs,
		Ids:        accountIDs,
		Enable:     enable,
	}

	_, err := c.internalClient.Do(ctx, http.MethodPost, EnableDisableAccountsInInstancesEndpoint, nil, nil, req, nil, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})

	return err
}
