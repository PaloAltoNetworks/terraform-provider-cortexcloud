// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

type User struct {
	Email        string   `json:"user_email"`
	FirstName    string   `json:"user_first_name"`
	LastName     string   `json:"user_last_name"`
	RoleName     string   `json:"role_name"`
	LastLoggedIn int      `json:"last_logged_in"`
	UserType     string   `json:"user_type"`
	Groups       []string `json:"groups"`
	Scope        Scope    `json:"scope"`
}

type Scope struct {
	Assets       *Assets       `json:"assets"`
	DatasetsRows *DatasetsRows `json:"datasets_rows,omitempty"`
	Endpoints    *Endpoints    `json:"endpoints"`
	CasesIssues  *CasesIssues  `json:"cases_issues"`
}

type Assets struct {
	Mode        string            `json:"mode"`
	AssetGroups []ScopeAssetGroup `json:"asset_groups"`
}

type ScopeAssetGroup struct {
	ID   int    `json:"asset_group_id"`
	Name string `json:"asset_group_name"`
}

type DatasetsRows struct {
	DefaultFilterMode string   `json:"default_filter_mode"`
	Filters           []Filter `json:"filters"`
}

type Filter struct {
	Dataset string `json:"dataset"`
	Filter  string `json:"filter"`
}

type Endpoints struct {
	EndpointGroups *EndpointGroups `json:"endpoint_groups"`
	EndpointTags   *EndpointTags   `json:"endpoint_tags"`
}

type EndpointGroups struct {
	Mode string `json:"mode"`
	Tags []Tag  `json:"tags"`
}

type EndpointTags struct {
	Mode string `json:"mode"`
	Tags []Tag  `json:"tags"`
}

type CasesIssues struct {
	Mode string `json:"mode"`
	Tags []Tag  `json:"tags"`
}

type Tag struct {
	TagID   string `json:"tag_id"`
	TagName string `json:"tag_name"`
}

type EditScopeRequest struct {
	RequestData EditScopeRequestData `json:"request_data"`
}

type EditScopeRequestData struct {
	Endpoints    *EditEndpoints    `json:"endpoints"`
	CasesIssues  *EditCasesIssues  `json:"cases_issues"`
	Assets       *EditAssets       `json:"assets"`
	DatasetsRows *EditDatasetsRows `json:"datasets_rows,omitempty"`
}

type EditEndpoints struct {
	EndpointGroups *EditEndpointGroups `json:"endpoint_groups"`
	EndpointTags   *EditEndpointTags   `json:"endpoint_tags"`
}

type EditEndpointGroups struct {
	Names []string `json:"names"`
	Mode  string   `json:"mode"`
}

type EditEndpointTags struct {
	Names []string `json:"names"`
	Mode  string   `json:"mode"`
}

type EditCasesIssues struct {
	Mode  string   `json:"mode"`
	Names []string `json:"names"`
}

type EditAssets struct {
	Mode          string `json:"mode"`
	AssetGroupIDs []int  `json:"asset_group_ids"`
}

type EditDatasetsRows struct {
	Filters           []Filter `json:"filters"`
	DefaultFilterMode string   `json:"default_filter_mode"`
}

type Reason struct {
	DateCreated string `json:"date_created"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Points      int    `json:"points"`
}

// GetUserRequest is the request for getting a user.
type GetUserRequest struct {
	Email string `json:"email"`
}

// SetRoleRequest is the request for setting a role.
type SetRoleRequest struct {
	UserEmails []string `json:"user_emails"`
	RoleName   string   `json:"role_name"`
}

// SetRoleResponse is the response for setting a role.
type SetRoleResponse struct {
	UpdateCount string `json:"update_count"`
}

// GetRiskScoreRequest is the request for getting a risk score.
type GetRiskScoreRequest struct {
	ID string `json:"id"`
}

// GetRiskScoreResponse is the response for getting a risk score.
type GetRiskScoreResponse struct {
	Type          string   `json:"type"`
	ID            string   `json:"id"`
	Score         int      `json:"score"`
	NormRiskScore int      `json:"norm_risk_score"`
	RiskLevel     string   `json:"risk_level"`
	Reasons       []Reason `json:"reasons"`
	Email         string   `json:"email"`
}

// ListRiskyUsersResponse is the response for listing risky users.
type ListRiskyUsersResponse struct {
	Type          string   `json:"type"`
	ID            string   `json:"id"`
	Score         int      `json:"score"`
	NormRiskScore int      `json:"norm_risk_score"`
	RiskLevel     string   `json:"risk_level"`
	Reasons       []Reason `json:"reasons"`
	Email         string   `json:"email"`
}

// ListRiskyHostsResponse is the response for listing risky hosts.
type ListRiskyHostsResponse struct {
	Type          string   `json:"type"`
	ID            string   `json:"id"`
	Score         int      `json:"score"`
	NormRiskScore int      `json:"norm_risk_score"`
	RiskLevel     string   `json:"risk_level"`
	Reasons       []Reason `json:"reasons"`
}

// HealthCheckResponse defines the response for the health check endpoint.
type HealthCheckResponse struct {
	Service   string `json:"service"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Timestamp int64  `json:"timestamp"`
}

// GetTenantInfoRequest defines the request for the get_tenant_info endpoint.
type GetTenantInfoRequest struct {
	Tenants []string `json:"tenants,omitempty"`
}

// TenantInfoLicense defines a license associated with a tenant.
type TenantInfoLicense struct {
	LicenseID      string `json:"license_id"`
	LicenseType    string `json:"license_type"`
	LicenseName    string `json:"license_name"`
	ExpirationDate int64  `json:"expiration_date"`
	IsExpired      bool   `json:"is_expired"`
}

// TenantInfo defines information about a tenant.
type TenantInfo struct {
	TenantID       string              `json:"tenant_id"`
	TenantName     string              `json:"tenant_name"`
	DisplayName    string              `json:"display_name"`
	CustomerName   string              `json:"customer_name"`
	ParentTenantID string              `json:"parent_tenant_id"`
	TenantType     string              `json:"tenant_type"`
	IsActive       bool                `json:"is_active"`
	Licenses       []TenantInfoLicense `json:"licenses"`
}

// GetUserGroupRequest defines the request for the get_user_group endpoint.
type GetUserGroupRequest struct {
	GroupNames []string `json:"group_names"`
}

// NestedGroup represents a child group within a user group.
type NestedGroup struct {
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name"`
}

// UserGroup defines the structure for a single user group.
type UserGroup struct {
	GroupID        string        `json:"group_id"`
	GroupName      string        `json:"group_name"`
	Description    string        `json:"description"`
	RoleName       string        `json:"role_id"`
	PrettyRoleName string        `json:"pretty_role_name"`
	CreatedBy      string        `json:"created_by"`
	CreatedTS      int64         `json:"created_ts"`
	UpdatedTS      int64         `json:"updated_ts"`
	Users          []string      `json:"users"`
	GroupType      string        `json:"group_type"`
	NestedGroups   []NestedGroup `json:"nested_groups"`
	IDPGroups      []string      `json:"idp_groups"`
}

// UserGroupCreateRequest defines the request for creating a user group.
type UserGroupCreateRequest struct {
	GroupName    string   `json:"group_name"`
	RoleName     string   `json:"role_id,omitempty"`
	Description  string   `json:"description,omitempty"`
	Users        []string `json:"users,omitempty"`
	NestedGroups []string `json:"nested_group_ids,omitempty"`
	IDPGroups    []string `json:"idp_groups,omitempty"`
}

// UserGroupCreateResponse is the response from the UserGroupCreate API.
type UserGroupCreateResponse struct {
	Message string `json:"message"`
}

// UserGroupEditRequest defines the request for editing a user group.
type UserGroupEditRequest struct {
	GroupName      string   `json:"group_name,omitempty"`
	RoleName       string   `json:"role_id,omitempty"`
	Description    string   `json:"description,omitempty"`
	Users          []string `json:"users,omitempty"`
	NestedGroupIDs []string `json:"nested_group_ids,omitempty"`
	IDPGroups      []string `json:"idp_groups,omitempty"`
}

// UserGroupEditResponse is the response from the UserGroupEdit API.
type UserGroupEditResponse struct {
	Message string `json:"message"`
}

// UserGroupDeleteResponse is the response from the UserGroupDelete API.
type UserGroupDeleteResponse struct {
	Message string `json:"message"`
}

// IamUserGroupInfo represents a group a user belongs to.
type IamUserGroupInfo struct {
	GroupID   int    `json:"group_id"`
	GroupName string `json:"group_name"`
}

// IamUser represents a user account in the platform.
type IamUser struct {
	Email        string        `json:"user_email"`
	FirstName    string        `json:"user_first_name"`
	LastName     string        `json:"user_last_name"`
	PhoneNumber  string        `json:"phone_number"`
	Status       string        `json:"status"`
	RoleName     string        `json:"role_name"`
	LastLoggedIn int64         `json:"last_logged_in"`
	Hidden       bool          `json:"is_hidden"`
	UserType     string        `json:"user_type"`
	Groups       []NestedGroup `json:"groups"`
}

// IamUsersMetadata contains metadata for a list of users.
type IamUsersMetadata struct {
	TotalCount int `json:"total_count"`
}

// ListIamUsersResponse is the response from the ListIAMUsers API.
type ListIamUsersResponse struct {
	Data     []IamUser        `json:"data"`
	Metadata IamUsersMetadata `json:"metadata"`
}

// GetIamUserResponse is the response from the GetIAMUser API.
type GetIamUserResponse struct {
	Data IamUser `json:"data"`
}

// IamUserEditRequest defines the request for editing a user.
type IamUserEditRequest struct {
	FirstName   *string  `json:"user_first_name,omitempty"`
	LastName    *string  `json:"user_last_name,omitempty"`
	RoleId      *string  `json:"role_id,omitempty"`
	PhoneNumber *string  `json:"phone_number,omitempty"`
	Status      *string  `json:"status,omitempty"`
	Hidden      *bool    `json:"is_hidden,omitempty"`
	UserGroups  []string `json:"user_groups,omitempty"`
}

type RoleListItem struct {
	RoleID      string `json:"role_id"`
	PrettyName  string `json:"pretty_name"`
	Description string `json:"description"`
	IsCustom    bool   `json:"is_custom"`
	CreatedBy   string `json:"created_by"`
	CreatedTs   int64  `json:"created_ts"`
	UpdatedTs   int64  `json:"updated_ts"`
}

type ListRolesResponse struct {
	Data     []RoleListItem `json:"data"`
	Metadata struct {
		TotalCount int `json:"total_count"`
	} `json:"metadata"`
}

type DatasetPermission struct {
	Category    string   `json:"category"`
	AccessAll   bool     `json:"access_all"`
	Permissions []string `json:"permissions"`
}

type RoleCreateRequestData struct {
	ComponentPermissions []string            `json:"component_permissions"`
	DatasetPermissions   []DatasetPermission `json:"dataset_permissions,omitempty"`
	PrettyName           string              `json:"pretty_name"`
	Description          string              `json:"description,omitempty"`
}

type RoleCreateRequest struct {
	RequestData RoleCreateRequestData `json:"request_data"`
}

type RoleCreateResponse struct {
	RoleID      string `json:"role_id"`
	PrettyName  string `json:"pretty_name"`
	Description string `json:"description"`
	IsCustom    bool   `json:"is_custom"`
	CreatedBy   string `json:"created_by"`
	CreatedTs   int64  `json:"created_ts"`
	UpdatedTs   int64  `json:"updated_ts"`
}

type PermissionConfig struct {
	Name           string          `json:"name"`
	ViewName       string          `json:"view_name"`
	ActionName     string          `json:"action_name"`
	SubPermissions []SubPermission `json:"sub_permissions"`
}

type SubPermission struct {
	ActionName string `json:"action_name"`
	Name       string `json:"name"`
}

type SubCategory struct {
	SubCategoryName string             `json:"sub_category_name"`
	Permissions     []PermissionConfig `json:"permissions"`
}

type RbacPermission struct {
	CategoryName  string        `json:"category_name"`
	SubCategories []SubCategory `json:"sub_categories"`
}

type DatasetGroup struct {
	Datasets        []string `json:"datasets"`
	DatasetCategory string   `json:"dataset_category"`
}

type PermissionConfigsResponseData struct {
	RbacPermissions []RbacPermission `json:"rbac_permissions"`
	DatasetGroups   []DatasetGroup   `json:"datasetGroups"`
}

type ListPermissionConfigsResponse struct {
	Data PermissionConfigsResponseData `json:"data"`
}
