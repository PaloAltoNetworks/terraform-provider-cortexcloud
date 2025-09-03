package cloudonboarding

import (
	"context"
	"net/http"
)

// ---------------------------
// Request/Response structs
// ---------------------------

// Get accounts in the specified integration instances

type ListAccountsByInstanceRequest struct {
	Data GetAccountsInInstancesRequestData `json:"request_data"`
}

type GetAccountsInInstancesRequestData struct {
	InstanceId string     `json:"instance_id"`
	FilterData FilterData `json:"filter_data"`
}

type ListAccountsByInstanceResponse struct {
	Reply ListAccountsByInstanceResponseReply `json:"reply"`
}

type ListAccountsByInstanceResponseReply struct {
	Data        ListAccountsByInstanceResponseData `json:"DATA"`
	FilterCount int                    `json:"FILTER_COUNT"`
	TotalCount  int                    `json:"TOTAL_COUNT"`
}

type ListAccountsByInstanceResponseData struct {
	Status      string `json:"status"`
	AccountName string `json:"account_name"`
	AccountId   string `json:"account_id"`
	Environment string `json:"environment"`
	Type        string `json:"type"`
	CreatedAt   string `json:"created_at"`
}

// Enable or disable cloud accounts

type EnableDisableAccountsInInstancesRequest struct {
	Data EnableDisableAccountsInInstancesRequestData `json:"request_data"`
}

type EnableDisableAccountsInInstancesRequestData struct {
	Ids        []string `json:"ids"`
	InstanceId string   `json:"instance_id"`
	Enable     bool     `json:"enable"`
}

type EnableDisableAccountsInInstancesResponse struct {
	Reply EnableDisableAccountsInInstancesResponseReply `json:"reply"`
}

type EnableDisableAccountsInInstancesResponseReply struct{}

// ---------------------------
// Request functions
// ---------------------------

func (c *Client) ListAccountsByInstance(ctx context.Context, input ListAccountsByInstanceRequest) (ListAccountsByInstanceResponse, error) {
	var ans ListAccountsByInstanceResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListAccountsByInstanceEndpoint, nil, nil, input, &ans)

	return ans, err
}

func (c *Client) EnableAccountsInInstance(ctx context.Context, instanceId string, accountIds []string) (EnableDisableAccountsInInstancesResponse, error) {
	return c.enableDisableAccountsInInstance(ctx, instanceId, accountIds, true)
}

func (c *Client) DisableAccountsInInstance(ctx context.Context, instanceId string, accountIds []string) (EnableDisableAccountsInInstancesResponse, error) {
	return c.enableDisableAccountsInInstance(ctx, instanceId, accountIds, false)
}

func (c *Client) enableDisableAccountsInInstance(ctx context.Context, instanceId string, accountIds []string, enable bool) (EnableDisableAccountsInInstancesResponse, error) {
	req := EnableDisableAccountsInInstancesRequest{
		Data: EnableDisableAccountsInInstancesRequestData{
			InstanceId: instanceId,
			Ids: accountIds,
			Enable: enable,
		},
	}

	var ans EnableDisableAccountsInInstancesResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, EnableDisableAccountsInInstancesEndpoint, nil, nil, req, &ans)

	return ans, err
}
