// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_ListUsers(t *testing.T) {
	t.Run("should list users successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+ListUsersEndpoint, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": [
					{
						"user_email": "test@example.com",
						"user_first_name": "Test",
						"user_last_name": "User",
						"role_name": "Admin"
					}
				]
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		users, err := client.ListUsers(context.Background())
		assert.NoError(t, err)
		require.Len(t, users, 1)
		user := users[0]
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "Test", user.FirstName)
		assert.Equal(t, "User", user.LastName)
		assert.Equal(t, "Admin", user.RoleName)
	})
}

func TestClient_SetRole(t *testing.T) {
	t.Run("should set role successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+SetUserRoleEndpoint, r.URL.Path)

			var req map[string]types.SetRoleRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)
			assert.Equal(t, "new-role", req["request_data"].RoleName)
			assert.Equal(t, []string{"user@example.com"}, req["request_data"].UserEmails)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply": {"update_count": "1"}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		setReq := types.SetRoleRequest{
			RoleName:   "new-role",
			UserEmails: []string{"user@example.com"},
		}
		resp, err := client.SetRole(context.Background(), setReq)
		assert.NoError(t, err)
		assert.Equal(t, "1", resp.UpdateCount)
	})
}

func TestClient_GetRiskScore(t *testing.T) {
	t.Run("should get risk score successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+GetRiskScoreEndpoint, r.URL.Path)

			var req map[string]types.GetRiskScoreRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)
			assert.Equal(t, "user123", req["request_data"].ID)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": {
					"id": "user123",
					"score": 95,
					"risk_level": "Critical"
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		getReq := types.GetRiskScoreRequest{
			ID: "user123",
		}
		resp, err := client.GetRiskScore(context.Background(), getReq)
		assert.NoError(t, err)
		assert.Equal(t, "user123", resp.ID)
		assert.Equal(t, 95, resp.Score)
	})
}

func TestClient_ListRiskyUsers(t *testing.T) {
	t.Run("should list risky users successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+ListRiskyUsersEndpoint, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": [
					{
						"id": "user456",
						"email": "risky@example.com",
						"score": 80,
						"risk_level": "High"
					}
				]
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.ListRiskyUsers(context.Background())
		assert.NoError(t, err)
		assert.Len(t, resp, 1)
		assert.Equal(t, "risky@example.com", resp[0].Email)
	})
}

func TestClient_ListRiskyHosts(t *testing.T) {
	t.Run("should list risky hosts successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+ListRiskyHostsEndpoint, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": [
					{
						"id": "host789",
						"score": 70,
						"risk_level": "Medium"
					}
				]
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.ListRiskyHosts(context.Background())
		assert.NoError(t, err)
		assert.Len(t, resp, 1)
		assert.Equal(t, "host789", resp[0].ID)
	})
}

func TestClient_HealthCheck(t *testing.T) {
	t.Run("should return health check status successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/"+HealthCheckEndpoint, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": {
					"service": "Cortex API",
					"status": "OK",
					"reason": "",
					"timestamp": 1678886400000
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.HealthCheck(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, "Cortex API", resp.Service)
		assert.Equal(t, "OK", resp.Status)
	})
}

func TestClient_GetTenantInfo(t *testing.T) {
	t.Run("should get tenant info successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+GetTenantInfoEndpoint, r.URL.Path)

			var req map[string]types.GetTenantInfoRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)
			assert.Equal(t, []string{"tenant1"}, req["request_data"].Tenants)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": [
					{
						"tenant_id": "tenant1",
						"tenant_name": "Tenant One"
					}
				]
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		getReq := types.GetTenantInfoRequest{
			Tenants: []string{"tenant1"},
		}
		resp, err := client.GetTenantInfo(context.Background(), getReq)
		assert.NoError(t, err)
		assert.Len(t, resp, 1)
		assert.Equal(t, "tenant1", resp[0].TenantID)
		assert.Equal(t, "Tenant One", resp[0].TenantName)
	})
}

func TestClient_ListUserGroups(t *testing.T) {
	t.Run("should list user groups successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/"+UserGroupEndpoint, r.URL.Path)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"data": [
					{
						"group_id": "test_group1",
						"group_name": "Group1",
						"description": "Group One",
						"role_name": "role_name01",
						"pretty_role_name": "Role Name 01",
						"created_by": "user1@test.com",
						"updated_by": "user1@test.com",
						"created_ts": 1661170832341,
						"updated_ts": 1661171650679,
						"users": ["user1@test.com"],
						"group_type": "custom",
						"nested_groups": [],
						"idp_groups": []
					}
				],
				"metadata": {"total_count": 1}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.ListUserGroups(context.Background())
		assert.NoError(t, err)
		require.Len(t, resp, 1)
		assert.Equal(t, "test_group1", resp[0].GroupID)
		assert.Equal(t, "Group1", resp[0].GroupName)
		assert.Equal(t, "Group One", resp[0].Description)
	})
}

func TestClient_GetUserGroup(t *testing.T) {
	t.Run("should get user group successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+GetUserGroupEndpoint, r.URL.Path)

			var req map[string]types.GetUserGroupRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)
			assert.Equal(t, []string{"group1"}, req["request_data"].GroupNames)

			w.WriteHeader(http.StatusOK)
			// This mock response is based on the API spec provided by the user.
			fmt.Fprint(w, `{
				"reply": {
					"data": [
						{
							"group_id": "test_group1",
							"group_name": "Group1",
							"description": "Group One",
							"role_name": "role_name01",
							"pretty_role_name": "Role Name 01",
							"created_by": "user1@test.com",
							"updated_by": "user1@test.com",
							"created_ts": 1661170832341,
							"updated_ts": 1661171650679,
							"users": ["user1@test.com"],
							"group_type": "custom",
							"nested_groups": [],
							"idp_groups": []
						}
					],
					"metadata": {"total_count": 1}
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		getReq := types.GetUserGroupRequest{
			GroupNames: []string{"group1"},
		}
		resp, err := client.GetUserGroup(context.Background(), getReq)
		assert.NoError(t, err)
		require.Len(t, resp, 1)
		assert.Equal(t, "test_group1", resp[0].GroupID)
		assert.Equal(t, "Group1", resp[0].GroupName)
		assert.Equal(t, "Group One", resp[0].Description)
	})
}

func TestClient_CreateUserGroup(t *testing.T) {
	t.Run("should create user group successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+UserGroupEndpoint, r.URL.Path)

			var req map[string]types.UserGroupCreateRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)
			assert.Equal(t, "New Group", req["request_data"].GroupName)
			assert.Equal(t, "A new group for testing", req["request_data"].Description)

			w.WriteHeader(http.StatusCreated)
			// A create operation typically returns the newly created object.
			fmt.Fprint(w, `{
				"data": {
					"message": "user group with group id new-group-id created successfully"
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := types.UserGroupCreateRequest{
			GroupName:   "New Group",
			Description: "A new group for testing",
		}
		resp, err := client.CreateUserGroup(context.Background(), createReq)
		assert.NoError(t, err)
		assert.Equal(t, "new-group-id", resp)
	})
}

func TestClient_EditUserGroup(t *testing.T) {
	t.Run("should edit user group successfully", func(t *testing.T) {
		const groupID = "group-to-edit-id"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPatch, r.Method)
			assert.Equal(t, fmt.Sprintf("/"+UserGroupEndpoint+"/%s", groupID), r.URL.Path)

			var req map[string]types.UserGroupEditRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)
			require.NotNil(t, req["request_data"].GroupName)

			w.WriteHeader(http.StatusOK)
			// A successful PATCH often returns a simple success message.
			fmt.Fprint(w, `{
				"data": {
					"message": "user group with group id group-to-edit-id updated successfully"
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		newName := "Updated Name"
		editReq := types.UserGroupEditRequest{
			GroupName: newName,
		}
		resp, err := client.EditUserGroup(context.Background(), groupID, editReq)
		assert.NoError(t, err)
		assert.Equal(t, "user group with group id group-to-edit-id updated successfully", resp)
	})
}

func TestClient_DeleteUserGroup(t *testing.T) {
	t.Run("should delete user group successfully", func(t *testing.T) {
		const groupID = "group-to-delete-id"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, fmt.Sprintf("/"+UserGroupEndpoint+"/%s", groupID), r.URL.Path)

			w.WriteHeader(http.StatusOK)
			// A successful DELETE often returns a simple success message.
			fmt.Fprint(w, `{
				"data": {
					"message": "user group with group id group-to-delete-id deleted successfully"
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.DeleteUserGroup(context.Background(), groupID)
		assert.NoError(t, err)
		assert.Equal(t, "user group with group id group-to-delete-id deleted successfully", resp)
	})
}

func TestClient_ListIAMUsers(t *testing.T) {
	t.Run("should list iam users successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/"+IamUsersEndpoint, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"data": [
					{
						"user_email": "user1@test.com",
						"user_first_name": "<first name>",
						"user_last_name": "<last name>",
						"phone_number": "408-753-4000",
						"status": "Active",
						"role_name": "Investigator",
						"last_logged_in": 1640024700241,
						"hidden": true,
						"user_type": "CSP",
						"groups": [
							{
								"group_id": "1234",
								"group_name": "usergroup1"
							}
						]
					},
					{
						"user_email": "user2@test.com",
						"user_first_name": "<first name>",
						"user_last_name": "<last name>",
						"phone_number": "408-753-4000",
						"status": "Active",
						"role_name": "Investigator",
						"last_logged_in": 1640024700241,
						"hidden": true,
						"user_type": "CSP",
						"groups": [
							{
								"group_id": "123",
								"group_name": "usergroup2"
							}
						]
					}
				],
				"metadata": {
					"total_count": 2
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.ListIAMUsers(context.Background())
		assert.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 2, resp.Metadata.TotalCount)
		require.Len(t, resp.Data, 2)

		user1 := resp.Data[0]
		assert.Equal(t, "user1@test.com", user1.Email)
		assert.Equal(t, "<first name>", user1.FirstName)
		assert.Equal(t, "usergroup1", user1.Groups[0].GroupName)

		user2 := resp.Data[1]
		assert.Equal(t, "user2@test.com", user2.Email)
		assert.Equal(t, "usergroup2", user2.Groups[0].GroupName)
	})
}

func TestClient_GetIAMUser(t *testing.T) {
	t.Run("should get iam user successfully", func(t *testing.T) {
		userEmail := "user@test.com"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s/%s", IamUsersEndpoint, userEmail), r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"data": {
					"user_email": "user@test.com",
					"user_first_name": "<first name>",
					"user_last_name": "<last name>",
					"phone_number": "408-753-4000",
					"status": "Active",
					"role_name": "Account Admin",
					"last_logged_in": 1640024700241,
					"hidden": true,
					"user_type": "CSP",
					"groups": [
						{
							"group_id": "unique_group_id",
							"group_name": "usergroup"
						}
					]
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		user, err := client.GetIAMUser(context.Background(), userEmail)
		assert.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "user@test.com", user.Email)
		assert.Equal(t, "Account Admin", user.RoleName)
		require.Len(t, user.Groups, 1)
		assert.Equal(t, "unique_group_id", user.Groups[0].GroupID)
		assert.Equal(t, "usergroup", user.Groups[0].GroupName)
	})
}

func TestClient_EditIAMUser(t *testing.T) {
	t.Run("should edit iam user successfully", func(t *testing.T) {
		userEmail := "user@test.com"

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPatch, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s/%s", IamUsersEndpoint, userEmail), r.URL.Path)

			var body struct {
				RequestData types.IamUserEditRequest `json:"request_data"`
			}
			err := json.NewDecoder(r.Body).Decode(&body)
			assert.NoError(t, err)

			assert.NotNil(t, body.RequestData.FirstName)
			assert.Equal(t, "NewName", *body.RequestData.FirstName)
			assert.Equal(t, []string{"newgroup"}, body.RequestData.UserGroups)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"data":{"message":"User updated successfully"}}`)
		})

		client, server := setupTest(t, handler)
		defer server.Close()

		newFirstName := "NewName"
		editReq := types.IamUserEditRequest{
			FirstName:  &newFirstName,
			UserGroups: []string{"newgroup"},
		}

		resp, err := client.EditIAMUser(context.Background(), userEmail, editReq)
		assert.NoError(t, err)
		assert.Equal(t, "User updated successfully", resp)
	})
}

func TestClient_GetScope(t *testing.T) {
	t.Run("should get scope successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/platform/iam/v1/scope/user/123", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"data": {
					"assets": {
						"mode": "scope",
						"asset_groups": [
							{
								"asset_group_id": 1,
								"asset_group_name": "Asset Test Group 1"
							}
						]
					}
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		scope, err := client.GetScope(context.Background(), "user", "123")
		assert.NoError(t, err)
		require.NotNil(t, scope)
		assert.Equal(t, "scope", scope.Assets.Mode)
		require.Len(t, scope.Assets.AssetGroups, 1)
		assert.Equal(t, 1, scope.Assets.AssetGroups[0].ID)
		assert.Equal(t, "Asset Test Group 1", scope.Assets.AssetGroups[0].Name)
	})
}

func TestClient_EditScope(t *testing.T) {
	t.Run("should edit scope successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPut, r.Method)
			assert.Equal(t, "/platform/iam/v1/scope/user/123", r.URL.Path)

			var req struct {
				RequestData types.EditScopeRequestData `json:"request_data"`
			}
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)
			assert.NotNil(t, req.RequestData)
			require.NotNil(t, req.RequestData.Assets)
			assert.Equal(t, "scope", req.RequestData.Assets.Mode)
			assert.Equal(t, []int{1, 2, 3}, req.RequestData.Assets.AssetGroupIDs)

			w.WriteHeader(http.StatusOK)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		editReq := types.EditScopeRequestData{
			Assets: &types.EditAssets{
				Mode:          "scope",
				AssetGroupIDs: []int{1, 2, 3},
			},
		}
		err := client.EditScope(context.Background(), "user", "123", editReq)
		assert.NoError(t, err)
	})
}

func TestClient_ListAllRoles(t *testing.T) {
	t.Run("should list all roles successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/"+RoleEndpoint, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"data": [
					{
						"role_id": "test_role_01",
						"pretty_name": "Test Role Pretty Name 01",
						"description": "Complete description",
						"is_custom": true,
						"created_by": "User 01",
						"created_ts": 1661171650679,
						"updated_ts": 1661171650679
					}
				],
				"metadata": {"total_count": 1}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.ListAllRoles(context.Background())
		assert.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 1, resp.Metadata.TotalCount)
		require.Len(t, resp.Data, 1)
		assert.Equal(t, "test_role_01", resp.Data[0].RoleID)
	})
}

func TestClient_CreateRole(t *testing.T) {
	t.Run("should create role successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+RoleEndpoint, r.URL.Path)

			var req map[string]types.RoleCreateRequestData
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)
			assert.Equal(t, "CustomRoleName", req["request_data"].PrettyName)

			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{
				"data": {
					"message": "role_id test_role_01 created successfully."
				}
			}`)
		})

		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := types.RoleCreateRequest{
			RequestData: types.RoleCreateRequestData{
				PrettyName:           "CustomRoleName",
				ComponentPermissions: []string{"rules_action"},
			},
		}
		resp, err := client.CreateRole(context.Background(), createReq)
		assert.NoError(t, err)

		assert.Equal(t, "test_role_01", resp.RoleID)
	})

	t.Run("should return error when role creation fails (400)", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+RoleEndpoint, r.URL.Path)

			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{
				"data": {
					"err_msg": "The request contains invalid or missing parameters.",
					"metadata": {
						"err_extra": "The role name CustomRoleName is already utilized by another role.",
						"err_code": 400
					}
				}
			}`)
		})

		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := types.RoleCreateRequest{
			RequestData: types.RoleCreateRequestData{
				PrettyName: "CustomRoleName",
			},
		}
		resp, err := client.CreateRole(context.Background(), createReq)

		assert.Error(t, err)
		assert.Nil(t, resp)

		assert.Contains(t, err.Error(), "The request contains invalid or missing parameters")
		assert.Contains(t, err.Error(), "The role name CustomRoleName is already utilized")
	})
}

func TestClient_DeleteRole(t *testing.T) {
	t.Run("should delete role successfully", func(t *testing.T) {
		const roleID = "role-to-delete-id"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, fmt.Sprintf("/"+RoleEndpoint+roleID), r.URL.Path)
			w.WriteHeader(http.StatusOK)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		err := client.DeleteRole(context.Background(), roleID)
		assert.NoError(t, err)
	})
}

func TestClient_ListPermissionConfigs(t *testing.T) {
	t.Run("should list permission configs successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/"+PermissionConfigEndpoint, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"data": {
					"rbac_permissions": [
						{
							"category_name": "Dashboards & Reports",
							"sub_categories": [
								{
									"permissions": [
										{
											"name": "Dashboards",
											"view_name": "dashboard_view",
											"action_name": "dashboard_action"
										}
									]
								}
							]
						}
					],
					"datasetGroups": [
						{
							"datasets": ["alerts"],
							"dataset_category": "System"
						}
					]
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.ListPermissionConfigs(context.Background())
		assert.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.Data.RbacPermissions, 1)
		assert.Equal(t, "Dashboards & Reports", resp.Data.RbacPermissions[0].CategoryName)
		require.Len(t, resp.Data.DatasetGroups, 1)
		assert.Equal(t, "System", resp.Data.DatasetGroups[0].DatasetCategory)
	})
}
