// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

type CloudAccount struct {
	Status      string `json:"status"`
	AccountName string `json:"account_name"`
	AccountId   string `json:"account_id"`
	Environment string `json:"environment"`
	Type        string `json:"type"`
	CreatedAt   string `json:"created_at"`
}

//type GetCloudAccountsRequest struct {
//	InstanceId string     `json:"instance_id"`
//	FilterData FilterData `json:"filter_data"`
//}

type ListAccountsByInstanceResponseReply struct {
	Data        []CloudAccount `json:"DATA"`
	FilterCount int            `json:"FILTER_COUNT"`
	TotalCount  int            `json:"TOTAL_COUNT"`
}

//type ListAccountsByInstanceResponseData struct {
//	Status      string `json:"status"`
//	AccountName string `json:"account_name"`
//	AccountId   string `json:"account_id"`
//	Environment string `json:"environment"`
//	Type        string `json:"type"`
//	CreatedAt   string `json:"created_at"`
//}

type EnableDisableAccountsInInstancesRequestData struct {
	Ids        []string `json:"ids"`
	InstanceId string   `json:"instance_id"`
	Enable     bool     `json:"enable"`
}

type EnableDisableAccountsInInstancesResponseReply struct{}
