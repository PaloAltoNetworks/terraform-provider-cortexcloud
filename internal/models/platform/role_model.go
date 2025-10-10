package models

import (
	"context"

	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type RoleModel struct {
	PrettyName  types.String `tfsdk:"pretty_name"`
	Permissions types.List   `tfsdk:"permissions"`
	InsertTime  types.Int64  `tfsdk:"insert_time"`
	UpdateTime  types.Int64  `tfsdk:"update_time"`
	CreatedBy   types.String `tfsdk:"created_by"`
	Description types.String `tfsdk:"description"`
	Tags        types.String `tfsdk:"tags"`
	Groups      types.List   `tfsdk:"groups"`
	Users       types.List   `tfsdk:"users"`
}

func (m *RoleModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *platformTypes.Role) {
	tflog.Debug(ctx, "Refreshing attribute values")

	var diagsRefresh diag.Diagnostics

	tflog.Trace(ctx, "Converting Permissions to Terraform type")
	m.Permissions, diagsRefresh = types.ListValueFrom(ctx, types.StringType, remote.Permissions)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Converting Groups to Terraform type")
	m.Groups, diagsRefresh = types.ListValueFrom(ctx, types.StringType, remote.Groups)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Converting Users to Terraform type")
	m.Users, diagsRefresh = types.ListValueFrom(ctx, types.StringType, remote.Users)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	m.PrettyName = types.StringValue(remote.PrettyName)
	m.InsertTime = types.Int64Value(int64(remote.InsertTime))
	m.UpdateTime = types.Int64Value(int64(remote.UpdateTime))
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.Description = types.StringValue(remote.Description)
	m.Tags = types.StringValue(remote.Tags)
}
