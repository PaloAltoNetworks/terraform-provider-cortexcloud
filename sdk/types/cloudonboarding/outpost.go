// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"

	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
)

// Outpost represents an outpost object.
type Outpost struct {
	CloudProvider string `json:"cloud_provider"`
	OutpostID     string `json:"outpost_id"`
	CreatedAt     int64  `json:"created_at"`
	Type          string `json:"type"`
}

// CreateOutpostTemplateRequest is the request for the CreateOutpostTemplate endpoint.
type CreateOutpostTemplateRequest struct {
	cloudProvider      string
	customResourceTags []Tag
}

// CreateOutpostTemplateRequestOption defines a functional option for CreateOutpostTemplateRequest.
type CreateOutpostTemplateRequestOption func(*CreateOutpostTemplateRequest)

// NewCreateOutpostTemplateRequest creates a new CreateOutpostTemplateRequest.
func NewCreateOutpostTemplateRequest(cloudProvider string, options ...CreateOutpostTemplateRequestOption) CreateOutpostTemplateRequest {
	r := CreateOutpostTemplateRequest{
		cloudProvider: cloudProvider,
	}
	for _, option := range options {
		option(&r)
	}
	return r
}

// WithCustomResourceTags sets the custom resource tags for the request.
func WithCustomResourceTags(tags []Tag) CreateOutpostTemplateRequestOption {
	return func(r *CreateOutpostTemplateRequest) {
		r.customResourceTags = tags
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (r CreateOutpostTemplateRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		CloudProvider      string `json:"cloud_provider"`
		CustomResourceTags []Tag  `json:"custom_resources_tags,omitempty"`
	}

	return json.Marshal(&alias{
		CloudProvider:      r.cloudProvider,
		CustomResourceTags: r.customResourceTags,
	})
}

// UpdateOutpostRequest is the request for the UpdateOutpost endpoint.
// The OpenAPI spec for this endpoint is faulty, so this struct is a best guess.
type UpdateOutpostRequest struct {
	outpostID          string
	cloudProvider      string
	customResourceTags []Tag
}

// UpdateOutpostRequestOption defines a functional option for UpdateOutpostRequest.
type UpdateOutpostRequestOption func(*UpdateOutpostRequest)

// NewUpdateOutpostRequest creates a new UpdateOutpostRequest.
func NewUpdateOutpostRequest(outpostID, cloudProvider string, options ...UpdateOutpostRequestOption) UpdateOutpostRequest {
	r := UpdateOutpostRequest{
		outpostID:     outpostID,
		cloudProvider: cloudProvider,
	}
	for _, option := range options {
		option(&r)
	}
	return r
}

// WithUpdateCustomResourceTags sets the custom resource tags for the request.
func WithUpdateCustomResourceTags(tags []Tag) UpdateOutpostRequestOption {
	return func(r *UpdateOutpostRequest) {
		r.customResourceTags = tags
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (r UpdateOutpostRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		OutpostID          string `json:"outpost_id"`
		CloudProvider      string `json:"cloud_provider"`
		CustomResourceTags []Tag  `json:"custom_resources_tags,omitempty"`
	}

	return json.Marshal(&alias{
		OutpostID:          r.outpostID,
		CloudProvider:      r.cloudProvider,
		CustomResourceTags: r.customResourceTags,
	})
}

// ListOutpostsRequest is the request for the ListOutposts endpoint.
type ListOutpostsRequest struct {
	filterData filterTypes.FilterData
}

// ListOutpostsRequestOption defines a functional option for ListOutpostsRequest.
type ListOutpostsRequestOption func(*ListOutpostsRequest)

// NewListOutpostsRequest creates a new ListOutpostsRequest.
func NewListOutpostsRequest(options ...ListOutpostsRequestOption) ListOutpostsRequest {
	r := ListOutpostsRequest{}
	for _, option := range options {
		option(&r)
	}
	return r
}

// WithOutpostFilterData sets the filter data for the request.
func WithOutpostFilterData(filterData filterTypes.FilterData) ListOutpostsRequestOption {
	return func(r *ListOutpostsRequest) {
		r.filterData = filterData
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (r ListOutpostsRequest) MarshalJSON() ([]byte, error) {
	type alias struct {
		FilterData filterTypes.FilterData `json:"filter_data"`
	}

	return json.Marshal(&alias{
		FilterData: r.filterData,
	})
}

// ListOutpostsResponse is the response for the ListOutposts endpoint.
type ListOutpostsResponse struct {
	Data        []Outpost `json:"DATA"`
	FilterCount int       `json:"FILTER_COUNT"`
	TotalCount  int       `json:"TOTAL_COUNT"`
}
