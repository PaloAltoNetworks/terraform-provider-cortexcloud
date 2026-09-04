// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"testing"
)

// millisecondTimestamp is a real-world 13-digit Unix millisecond epoch value.
// Values of this magnitude (~1.7e12) overflow a 32-bit int, which caused the
// provider to crash while fetching the cloud integration template.
const millisecondTimestamp int64 = 1709903622007

// TestListIntegrationInstancesResponse_UnmarshalMillisecondCreationTime is a
// regression test: the Cortex Cloud API returns a 13-digit Unix
// millisecond timestamp for creation_time, which previously failed to unmarshal
// into a Go int field with:
//
//	json: cannot unmarshal number 1709903622007 into Go struct field
//	ListIntegrationInstancesResponse.DATA.creation_time of type int
func TestListIntegrationInstancesResponse_UnmarshalMillisecondCreationTime(t *testing.T) {
	body := []byte(`{
		"instance_name": "AWS Account Group",
		"cloud_provider": "AWS",
		"scope": "ORGANIZATION",
		"status": "ACTIVE",
		"creation_time": 1709903622007,
		"deleted_at": 1709903999999
	}`)

	var resp ListIntegrationInstancesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unexpected unmarshal error for millisecond creation_time: %v", err)
	}

	if resp.CreationTime != millisecondTimestamp {
		t.Errorf("CreationTime = %d, want %d", resp.CreationTime, millisecondTimestamp)
	}
	if resp.DeletedAt != 1709903999999 {
		t.Errorf("DeletedAt = %d, want %d", resp.DeletedAt, int64(1709903999999))
	}
}

// TestListIntegrationInstancesResponseWrapper_MarshalPreservesMillisecondTime
// ensures the millisecond creation_time survives the Wrapper.Marshal() step that
// converts the API response into the IntegrationInstance used by the provider.
func TestListIntegrationInstancesResponseWrapper_MarshalPreservesMillisecondTime(t *testing.T) {
	body := []byte(`{
		"DATA": [
			{
				"instance_name": "AWS Account Group",
				"cloud_provider": "AWS",
				"scope": "ORGANIZATION",
				"status": "ACTIVE",
				"creation_time": 1709903622007
			}
		]
	}`)

	var wrapper ListIntegrationInstancesResponseWrapper
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	instances, err := wrapper.Marshal()
	if err != nil {
		t.Fatalf("unexpected Marshal error: %v", err)
	}
	if len(instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(instances))
	}
	if instances[0].CreationTime != millisecondTimestamp {
		t.Errorf("IntegrationInstance.CreationTime = %d, want %d",
			instances[0].CreationTime, millisecondTimestamp)
	}
}

// TestIntegrationInstance_UnmarshalMillisecondCreationTime verifies the
// IntegrationInstance struct (used directly by some endpoints) also accepts a
// 13-digit millisecond creation_time.
func TestIntegrationInstance_UnmarshalMillisecondCreationTime(t *testing.T) {
	body := []byte(`{
		"id": "abc-123",
		"instance_name": "AWS Account Group",
		"cloud_provider": "AWS",
		"scope": "ORGANIZATION",
		"status": "ACTIVE",
		"creation_time": 1709903622007
	}`)

	var instance IntegrationInstance
	if err := json.Unmarshal(body, &instance); err != nil {
		t.Fatalf("unexpected unmarshal error for millisecond creation_time: %v", err)
	}
	if instance.CreationTime != millisecondTimestamp {
		t.Errorf("CreationTime = %d, want %d", instance.CreationTime, millisecondTimestamp)
	}
}

// TestOutpost_UnmarshalMillisecondCreatedAt guards against the same class of bug
// on the Outpost.created_at field, which is also a millisecond epoch timestamp.
func TestOutpost_UnmarshalMillisecondCreatedAt(t *testing.T) {
	body := []byte(`{
		"cloud_provider": "AWS",
		"outpost_id": "outpost-1",
		"created_at": 1709903622007,
		"type": "MANAGED"
	}`)

	var outpost Outpost
	if err := json.Unmarshal(body, &outpost); err != nil {
		t.Fatalf("unexpected unmarshal error for millisecond created_at: %v", err)
	}
	if outpost.CreatedAt != millisecondTimestamp {
		t.Errorf("CreatedAt = %d, want %d", outpost.CreatedAt, millisecondTimestamp)
	}
}
