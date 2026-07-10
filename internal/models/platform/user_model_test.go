// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestToEditRequest_OmitsEmptyOptionalStrings verifies that Optional+Computed
// string fields (status, phone_number, role_name) are omitted from the edit
// request when they are null, unknown, or empty. Sending a pointer to "" would
// defeat the SDK's `omitempty` JSON tags and cause the API to reject empty
// strings (e.g. HTTP 400 "Invalid attribute status: ”").
func TestToEditRequest_OmitsEmptyOptionalStrings(t *testing.T) {
	tests := []struct {
		name   string
		status types.String
	}{
		{name: "null status", status: types.StringNull()},
		{name: "unknown status", status: types.StringUnknown()},
		{name: "empty status", status: types.StringValue("")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &UserModel{
				Email:       types.StringValue("jane.smith@example.com"),
				Status:      tc.status,
				PhoneNumber: types.StringNull(),
				RoleName:    types.StringUnknown(),
				GroupIDs:    types.ListNull(types.StringType),
			}

			req := m.ToEditRequest()

			if req.Status != nil {
				t.Errorf("Status = %q, want nil (field should be omitted)", *req.Status)
			}
			if req.PhoneNumber != nil {
				t.Errorf("PhoneNumber = %q, want nil (field should be omitted)", *req.PhoneNumber)
			}
			if req.RoleId != nil {
				t.Errorf("RoleId = %q, want nil (field should be omitted)", *req.RoleId)
			}
		})
	}
}

// TestToEditRequest_SendsSetOptionalStrings verifies that when the optional
// string fields are set to non-empty values, they are forwarded to the SDK
// request as pointers to those values.
func TestToEditRequest_SendsSetOptionalStrings(t *testing.T) {
	m := &UserModel{
		Email:       types.StringValue("jane.smith@example.com"),
		Status:      types.StringValue("active"),
		PhoneNumber: types.StringValue("+1-555-0100"),
		RoleName:    types.StringValue("Account Admin"),
		GroupIDs:    types.ListNull(types.StringType),
	}

	req := m.ToEditRequest()

	if req.Status == nil || *req.Status != "active" {
		t.Errorf("Status = %v, want %q", req.Status, "active")
	}
	if req.PhoneNumber == nil || *req.PhoneNumber != "+1-555-0100" {
		t.Errorf("PhoneNumber = %v, want %q", req.PhoneNumber, "+1-555-0100")
	}
	if req.RoleId == nil || *req.RoleId != "Account Admin" {
		t.Errorf("RoleId = %v, want %q", req.RoleId, "Account Admin")
	}
}

// TestNilIfEmptyString covers the helper's null/unknown/empty/set cases.
func TestNilIfEmptyString(t *testing.T) {
	if got := nilIfEmptyString(types.StringNull()); got != nil {
		t.Errorf("null: got %q, want nil", *got)
	}
	if got := nilIfEmptyString(types.StringUnknown()); got != nil {
		t.Errorf("unknown: got %q, want nil", *got)
	}
	if got := nilIfEmptyString(types.StringValue("")); got != nil {
		t.Errorf("empty: got %q, want nil", *got)
	}
	if got := nilIfEmptyString(types.StringValue("active")); got == nil || *got != "active" {
		t.Errorf("set: got %v, want %q", got, "active")
	}
}
