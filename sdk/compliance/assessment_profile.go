// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	commontypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/compliance"
)

// CreateAssessmentProfile creates a new compliance assessment profile.
func (c *Client) CreateAssessmentProfile(ctx context.Context, req types.CreateAssessmentProfileRequest) (bool, error) {
	var resp commontypes.SuccessResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, CreateAssessmentProfileEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return resp.Success, err
}

// GetAssessmentProfile retrieves a specific assessment profile by ID.
func (c *Client) GetAssessmentProfile(ctx context.Context, req types.GetAssessmentProfileRequest) (*types.AssessmentProfile, error) {
	var resp types.GetAssessmentProfileResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, GetAssessmentProfileEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.AssessmentProfiles) == 0 {
		return nil, fmt.Errorf("assessment profile not found")
	}
	return &resp.AssessmentProfiles[0], nil
}

// UpdateAssessmentProfile updates an existing compliance assessment profile.
func (c *Client) UpdateAssessmentProfile(ctx context.Context, req types.UpdateAssessmentProfileRequest) (bool, error) {
	// First, fetch the existing profile to ensure all required fields are present
	existingProfile, err := c.GetAssessmentProfile(ctx, types.GetAssessmentProfileRequest{
		ID: req.ID,
	})
	if err != nil {
		return false, err
	}

	// Normalize ReportType - API returns "None" but requires "NONE" for updates
	reportType := strings.ToUpper(existingProfile.ReportType)
	if req.ReportType != "" {
		reportType = strings.ToUpper(req.ReportType)
	}

	// Create a new update request with all fields from the existing profile
	mergedReq := types.UpdateAssessmentProfileRequest{
		ID:          req.ID,
		ProfileName: existingProfile.Name,
		StandardID:  existingProfile.StandardID,
		Description: existingProfile.Description,
		ReportType:  reportType,
	}

	// Convert AssetGroupID from int to string
	if existingProfile.AssetGroupID != 0 {
		mergedReq.AssetGroupID = strconv.Itoa(existingProfile.AssetGroupID)
	}

	// IMPORTANT: Only set evaluation_frequency and report_targets if report_type is NOT "NONE"
	// The API rejects these fields when report_type is "NONE"
	if reportType != "NONE" {
		// Set EvaluationFrequency
		if existingProfile.ReportFrequency != nil && *existingProfile.ReportFrequency != "" {
			mergedReq.EvaluationFrequency = *existingProfile.ReportFrequency
		} else {
			mergedReq.EvaluationFrequency = "NONE"
		}
		// Set ReportTargets
		mergedReq.ReportTargets = existingProfile.ReportTargets
	}

	// Overwrite with any new values provided in the update request
	if req.ProfileName != "" {
		mergedReq.ProfileName = req.ProfileName
	}
	if req.AssetGroupID != "" {
		mergedReq.AssetGroupID = req.AssetGroupID
	}
	if req.StandardID != "" {
		mergedReq.StandardID = req.StandardID
	}
	if req.Description != "" {
		mergedReq.Description = req.Description
	}
	if req.Enabled != "" {
		mergedReq.Enabled = req.Enabled
	}

	// Only allow overriding these fields if report_type is not "NONE"
	if reportType != "NONE" {
		if req.ReportTargets != nil {
			mergedReq.ReportTargets = req.ReportTargets
		}
		if req.EvaluationFrequency != "" {
			mergedReq.EvaluationFrequency = req.EvaluationFrequency
		}
	}

	var resp commontypes.SuccessResponse
	_, err = c.internalClient.Do(ctx, http.MethodPost, UpdateAssessmentProfileEndpoint, nil, nil, mergedReq, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return resp.Success, err
}

// DeleteAssessmentProfile deletes an assessment profile.
func (c *Client) DeleteAssessmentProfile(ctx context.Context, req types.DeleteAssessmentProfileRequest) (bool, error) {
	var resp commontypes.SuccessResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, DeleteAssessmentProfileEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return resp.Success, err
}

// ListAssessmentProfiles retrieves all assessment profiles with optional filtering, sorting, and pagination.
func (c *Client) ListAssessmentProfiles(ctx context.Context, req types.ListAssessmentProfilesRequest) (*types.ListAssessmentProfilesResponse, error) {
	var resp types.ListAssessmentProfilesResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListAssessmentProfilesEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
