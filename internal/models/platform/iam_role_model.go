package models

import (
	"context"

	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type IamRoleModel struct {
	ID                   types.String `tfsdk:"id"`
	PrettyName           types.String `tfsdk:"pretty_name"`
	Description          types.String `tfsdk:"description"`
	ComponentPermissions types.Set    `tfsdk:"component_permissions"`
	DatasetPermissions   types.Set    `tfsdk:"dataset_permissions"`
	IsCustom             types.Bool   `tfsdk:"is_custom"`
	CreatedBy            types.String `tfsdk:"created_by"`
	CreatedTs            types.Int64  `tfsdk:"created_ts"`
	UpdatedTs            types.Int64  `tfsdk:"updated_ts"`
}

type DatasetPermissionModel struct {
	Category    types.String `tfsdk:"category"`
	AccessAll   types.Bool   `tfsdk:"access_all"`
	Permissions types.Set    `tfsdk:"permissions"`
}

// IamRoleDataSourceModel is a minimal view of IAM Role as returned by List/Get endpoints.
// DO NOT add create/update-only fields here.
type IamRoleDataSourceModel struct {
	RoleID      types.String `tfsdk:"role_id"`
	PrettyName  types.String `tfsdk:"pretty_name"`
	Description types.String `tfsdk:"description"`
	IsCustom    types.Bool   `tfsdk:"is_custom"`
	CreatedBy   types.String `tfsdk:"created_by"`
	CreatedTs   types.Int64  `tfsdk:"created_ts"`
	UpdatedTs   types.Int64  `tfsdk:"updated_ts"`
}

// RefreshFromRemote maps RoleListItem → state fields.
func (m *IamRoleModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, r *platformTypes.RoleListItem) {
	if r == nil {
		return
	}
	m.ID = types.StringValue(r.RoleID)
	m.PrettyName = types.StringValue(r.PrettyName)
	m.Description = types.StringValue(r.Description)
	m.IsCustom = types.BoolValue(r.IsCustom)

	m.CreatedBy = types.StringValue(r.CreatedBy)
	m.CreatedTs = types.Int64Value(r.CreatedTs)
	m.UpdatedTs = types.Int64Value(r.UpdatedTs)
}

func (m *IamRoleDataSourceModel) RefreshFromRemote(r *platformTypes.RoleListItem) {
	if r == nil {
		return
	}
	m.RoleID = types.StringValue(r.RoleID)
	m.PrettyName = types.StringValue(r.PrettyName)
	m.Description = types.StringValue(r.Description)
	m.IsCustom = types.BoolValue(r.IsCustom)
	m.CreatedBy = types.StringValue(r.CreatedBy)
	m.CreatedTs = types.Int64Value(r.CreatedTs)
	m.UpdatedTs = types.Int64Value(r.UpdatedTs)
}
