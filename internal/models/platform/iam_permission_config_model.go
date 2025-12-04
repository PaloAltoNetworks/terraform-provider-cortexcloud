package models

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type IamPermissionConfigModel struct {
	ID              types.String          `tfsdk:"id"`
	RbacPermissions []RbacPermissionModel `tfsdk:"rbac_permissions"`
	DatasetGroups   []DatasetGroupModel   `tfsdk:"dataset_groups"`
}

type RbacPermissionModel struct {
	CategoryName  string             `tfsdk:"category_name"`
	SubCategories []SubCategoryModel `tfsdk:"sub_categories"`
}

type SubCategoryModel struct {
	SubCategoryName string                  `tfsdk:"sub_category_name"`
	Permissions     []PermissionConfigModel `tfsdk:"permissions"`
}

type PermissionConfigModel struct {
	Name           string               `tfsdk:"name"`
	ViewName       string               `tfsdk:"view_name"`
	ActionName     string               `tfsdk:"action_name"`
	SubPermissions []SubPermissionModel `tfsdk:"sub_permissions"`
}

type SubPermissionModel struct {
	ActionName string `tfsdk:"action_name"`
	Name       string `tfsdk:"name"`
}

type DatasetGroupModel struct {
	Datasets        []string `tfsdk:"datasets"`
	DatasetCategory string   `tfsdk:"dataset_category"`
}
