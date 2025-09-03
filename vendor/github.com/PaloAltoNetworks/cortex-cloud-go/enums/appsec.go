// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package enums

import (
)

type Category string

func (c Category) IsACategory() bool {
	return c.IsAIacCategory() || c.IsASecretsCategory()
}

func (c Category) IsAIacCategory() bool {
	return ContainsIacCategory(string(c))
}

func (c Category) IsASecretsCategory() bool {
	return ContainsSecretsCategory(string(c))
}

func (c Category) String() string {
	if c.IsAIacCategory() {
		return IacCategory(c).String()
	} else if c.IsASecretsCategory() {
		return SecretsCategory(c).String()
	} else {
		return ""
	}
}

func ContainsCategory(s string) bool {
	iacOk := ContainsIacCategory(s)
	secretsOk := ContainsSecretsCategory(s)
	return iacOk || secretsOk
}

func OptionalContainsCategory(s *string) bool {
	if s == nil {
		return true
	}

	return ContainsCategory(*s)
}

// ==============================================================================
// IacCategoryEnums
// ==============================================================================

// IacCategory represents the top-level categories for IaC issues.
type IacCategory Category

// IacSubCategory represents the sub-categories within each IaC category.
type IacSubCategory string

const (
	// IacCategory AI_ML
	IacCategoryAIML IacCategory = "AI_ML"
	// IacSubCategory for AI_ML
	IacSubCategoryAIMLGuardrails     IacSubCategory = "GUARDRAILS"
	IacSubCategoryAIMLRiskyModels    IacSubCategory = "RISKY_MODELS"
	IacSubCategoryAIMLPublicExposure IacSubCategory = "PUBLIC_EXPOSURE"
	IacSubCategoryAIMLPermissions    IacSubCategory = "PERMISSIONS"

	// IacCategory LOGGING
	IacCategoryLogging IacCategory = "LOGGING"
	// IacSubCategory for LOGGING
	IacSubCategoryLoggingEncryption        IacSubCategory = "ENCRYPTION"
	IacSubCategoryLoggingPermissions       IacSubCategory = "PERMISSIONS"
	IacSubCategoryLoggingRetention         IacSubCategory = "RETENTION"
	IacSubCategoryLoggingFormats           IacSubCategory = "FORMATS"
	IacSubCategoryLoggingDisabledOrMissing IacSubCategory = "DISABLED_OR_MISSING"
	IacSubCategoryLoggingPublicExposure    IacSubCategory = "PUBLIC_EXPOSURE"
	IacSubCategoryLoggingUnderUse          IacSubCategory = "UNDER_USE"

	// IacCategory KUBERNETES
	IacCategoryKubernetes IacCategory = "KUBERNETES"
	// IacSubCategory for KUBERNETES
	IacSubCategoryKubernetesNetworkPolicies            IacSubCategory = "NETWORK_POLICIES"
	IacSubCategoryKubernetesAccessControl              IacSubCategory = "ACCESS_CONTROL"
	IacSubCategoryKubernetesLoggingAndMonitoring       IacSubCategory = "LOGGING_AND_MONITORING"
	IacSubCategoryKubernetesResourceManagement         IacSubCategory = "RESOURCE_MANAGEMENT"
	IacSubCategoryKubernetesNativeSecurityControls     IacSubCategory = "NATIVE_SECURITY_CONTROLS"
	IacSubCategoryKubernetesManagementServicesExposure IacSubCategory = "MANAGEMENT_SERVICES_EXPOSURE"

	// IacCategory COMPUTE
	IacCategoryCompute IacCategory = "COMPUTE"
	// IacSubCategory for COMPUTE
	IacSubCategoryComputeOverprovisioned            IacSubCategory = "OVERPROVISIONED"
	IacSubCategoryComputeStartupScriptLeaks         IacSubCategory = "STARTUP_SCRIPT_LEAKS"
	IacSubCategoryComputeDefaultCredentialsOrAuth   IacSubCategory = "DEFAULT_CREDENTIALS_OR_AUTH"
	IacSubCategoryComputeUnsanctionedResourceOrType IacSubCategory = "UNSANCTIONED_RESOURCE_OR_TYPE"

	// IacCategory STORAGE
	IacCategoryStorage IacCategory = "STORAGE"
	// IacSubCategory for STORAGE
	IacSubCategoryStorageEncryption  IacSubCategory = "ENCRYPTION"
	IacSubCategoryStoragePermissions IacSubCategory = "PERMISSIONS"
	IacSubCategoryStorageBackups     IacSubCategory = "BACKUPS"
	IacSubCategoryStorageVersioning  IacSubCategory = "VERSIONING"
	IacSubCategoryStorageReplication IacSubCategory = "REPLICATION"
	IacSubCategoryStorageAlerting    IacSubCategory = "ALERTING"
	IacSubCategoryStorageRedundancy  IacSubCategory = "REDUNDANCY"

	// IacCategory PUBLIC
	IacCategoryPublic IacCategory = "PUBLIC"
	// IacSubCategory for PUBLIC
	IacSubCategoryPublicAdminInterfaces   IacSubCategory = "ADMIN_INTERFACES"
	IacSubCategoryPublicDatabaseEndpoints IacSubCategory = "DATABASE_ENDPOINTS"
	IacSubCategoryPublicStorageBuckets    IacSubCategory = "STORAGE_BUCKETS"
	IacSubCategoryPublicAPIs              IacSubCategory = "APIS"
	IacSubCategoryPublicSensitivePorts    IacSubCategory = "SENSITIVE_PORTS"

	// IacCategory NETWORKING
	IacCategoryNetworking IacCategory = "NETWORKING"
	// IacSubCategory for NETWORKING
	IacSubCategoryNetworkingLoadBalancing          IacSubCategory = "LOAD_BALANCING"
	IacSubCategoryNetworkingIngressControls        IacSubCategory = "INGRESS_CONTROLS"
	IacSubCategoryNetworkingEgressControls         IacSubCategory = "EGRESS_CONTROLS"
	IacSubCategoryNetworkingEncryptionAndProtocols IacSubCategory = "ENCRYPTION_AND_PROTOCOLS"
	IacSubCategoryNetworkingVPCVCNVNET             IacSubCategory = "VPC_VCN_VNET"
	IacSubCategoryNetworkingFlowLogs               IacSubCategory = "FLOW_LOGS"

	// IacCategory MONITORING
	IacCategoryMonitoring IacCategory = "MONITORING"
	// IacSubCategory for MONITORING
	IacSubCategoryMonitoringTagsAndMetadata          IacSubCategory = "TAGS_AND_METADATA"
	IacSubCategoryMonitoringResourceHealth           IacSubCategory = "RESOURCE_HEALTH"
	IacSubCategoryMonitoringPerformanceMonitoring    IacSubCategory = "PERFORMANCE_MONITORING"
	IacSubCategoryMonitoringAlertingAndNotifications IacSubCategory = "ALERTING_AND_NOTIFICATIONS"
	IacSubCategoryMonitoringUnintegrated             IacSubCategory = "UNINTEGRATED"
	IacSubCategoryMonitoringStorage                  IacSubCategory = "STORAGE"

	// IacCategory IAM
	IacCategoryIAM IacCategory = "IAM"
	// IacSubCategory for IAM
	IacSubCategoryIAMOverlyPermissive       IacSubCategory = "OVERLY_PERMISSIVE"
	IacSubCategoryIAMUnused                 IacSubCategory = "UNUSED"
	IacSubCategoryIAMCredentialExposure     IacSubCategory = "CREDENTIAL_EXPOSURE"
	IacSubCategoryIAMMFA                    IacSubCategory = "MFA"
	IacSubCategoryIAMRoleSeparation         IacSubCategory = "ROLE_SEPARATION"
	IacSubCategoryIAMShared                 IacSubCategory = "SHARED"
	IacSubCategoryIAMExpiredKeyControls     IacSubCategory = "EXPIRED_KEY_CONTROLS"
	IacSubCategoryIAMAuthenticationPolicies IacSubCategory = "AUTHENTICATION_POLICIES"
)

// iacCategorySubCategories maps IacCategory to its valid IacSubCategory values.
var iacCategorySubCategories = map[IacCategory][]IacSubCategory{
	IacCategoryAIML: {
		IacSubCategoryAIMLGuardrails,
		IacSubCategoryAIMLRiskyModels,
		IacSubCategoryAIMLPublicExposure,
		IacSubCategoryAIMLPermissions,
	},
	IacCategoryLogging: {
		IacSubCategoryLoggingEncryption,
		IacSubCategoryLoggingPermissions,
		IacSubCategoryLoggingRetention,
		IacSubCategoryLoggingFormats,
		IacSubCategoryLoggingDisabledOrMissing,
		IacSubCategoryLoggingPublicExposure,
		IacSubCategoryLoggingUnderUse,
	},
	IacCategoryKubernetes: {
		IacSubCategoryKubernetesNetworkPolicies,
		IacSubCategoryKubernetesAccessControl,
		IacSubCategoryKubernetesLoggingAndMonitoring,
		IacSubCategoryKubernetesResourceManagement,
		IacSubCategoryKubernetesNativeSecurityControls,
		IacSubCategoryKubernetesManagementServicesExposure,
	},
	IacCategoryCompute: {
		IacSubCategoryComputeOverprovisioned,
		IacSubCategoryComputeStartupScriptLeaks,
		IacSubCategoryComputeDefaultCredentialsOrAuth,
		IacSubCategoryComputeUnsanctionedResourceOrType,
	},
	IacCategoryStorage: {
		IacSubCategoryStorageEncryption,
		IacSubCategoryStoragePermissions,
		IacSubCategoryStorageBackups,
		IacSubCategoryStorageVersioning,
		IacSubCategoryStorageReplication,
		IacSubCategoryStorageAlerting,
		IacSubCategoryStorageRedundancy,
	},
	IacCategoryPublic: {
		IacSubCategoryPublicAdminInterfaces,
		IacSubCategoryPublicDatabaseEndpoints,
		IacSubCategoryPublicStorageBuckets,
		IacSubCategoryPublicAPIs,
		IacSubCategoryPublicSensitivePorts,
	},
	IacCategoryNetworking: {
		IacSubCategoryNetworkingLoadBalancing,
		IacSubCategoryNetworkingIngressControls,
		IacSubCategoryNetworkingEgressControls,
		IacSubCategoryNetworkingEncryptionAndProtocols,
		IacSubCategoryNetworkingVPCVCNVNET,
		IacSubCategoryNetworkingFlowLogs,
	},
	IacCategoryMonitoring: {
		IacSubCategoryMonitoringTagsAndMetadata,
		IacSubCategoryMonitoringResourceHealth,
		IacSubCategoryMonitoringPerformanceMonitoring,
		IacSubCategoryMonitoringAlertingAndNotifications,
		IacSubCategoryMonitoringUnintegrated,
		IacSubCategoryMonitoringStorage,
	},
	IacCategoryIAM: {
		IacSubCategoryIAMOverlyPermissive,
		IacSubCategoryIAMUnused,
		IacSubCategoryIAMCredentialExposure,
		IacSubCategoryIAMMFA,
		IacSubCategoryIAMRoleSeparation,
		IacSubCategoryIAMShared,
		IacSubCategoryIAMExpiredKeyControls,
		IacSubCategoryIAMAuthenticationPolicies,
	},
}

// String returns the string representation of an IacCategory.
func (ic IacCategory) String() string {
	return string(ic)
}

// AllIacCategories returns a slice of all valid IacCategory string values.
func AllIacCategories() []string {
	categories := make([]string, 0, len(iacCategorySubCategories))
	for cat := range iacCategorySubCategories {
		categories = append(categories, string(cat))
	}
	return categories
}

// ContainsIacCategory checks if the given string is a valid IacCategory.
func ContainsIacCategory(s string) bool {
	_, ok := iacCategorySubCategories[IacCategory(s)]
	return ok
}

// String returns the string representation of an IacSubCategory.
func (isc IacSubCategory) String() string {
	return string(isc)
}

// AllIacSubCategories returns a slice of all valid IacSubCategory string values for a given category.
func AllIacSubCategories(category IacCategory) []string {
	subCategories, ok := iacCategorySubCategories[category]
	if !ok {
		return nil
	}
	result := make([]string, len(subCategories))
	for i, sc := range subCategories {
		result[i] = string(sc)
	}
	return result
}

// ContainsIacSubCategory checks if the given subCategory string is valid for the given IacCategory.
func ContainsIacSubCategory(category IacCategory, subCategory string) bool {
	subCategories, ok := iacCategorySubCategories[category]
	if !ok {
		return false
	}
	for _, sc := range subCategories {
		if string(sc) == subCategory {
			return true
		}
	}
	return false
}

// ==============================================================================
// SecretsCategoryEnums
// ==============================================================================

// SecretsCategory represents the categories for secrets.
type SecretsCategory Category

const (
	SecretsCategoryAPIKeys                  SecretsCategory = "API_KEYS"
	SecretsCategoryDatabaseCredentials      SecretsCategory = "DATABASE_CREDENTIALS"
	SecretsCategoryEncryptionKeys           SecretsCategory = "ENCRYPTION_KEYS"
	SecretsCategoryCloudServiceProviderKeys SecretsCategory = "CLOUD_SERVICE_PROVIDER_KEYS"
	SecretsCategorySSHKeys                  SecretsCategory = "SSH_KEYS"
	SecretsCategoryEnvironmentVariables     SecretsCategory = "ENVIRONMENT_VARIABLES"
	SecretsCategorySensitiveTokens          SecretsCategory = "SENSITIVE_TOKENS"
	SecretsCategoryThirdPartyServices       SecretsCategory = "THIRD_PARTY_SERVICES"
)

// allSecretsCategories holds all valid SecretsCategory values.
var allSecretsCategories = []SecretsCategory{
	SecretsCategoryAPIKeys,
	SecretsCategoryDatabaseCredentials,
	SecretsCategoryEncryptionKeys,
	SecretsCategoryCloudServiceProviderKeys,
	SecretsCategorySSHKeys,
	SecretsCategoryEnvironmentVariables,
	SecretsCategorySensitiveTokens,
	SecretsCategoryThirdPartyServices,
}

// String returns the string representation of a SecretsCategory.
func (sc SecretsCategory) String() string {
	return string(sc)
}

// AllSecretsCategories returns a slice of all valid SecretsCategory string values.
func AllSecretsCategories() []string {
	result := make([]string, len(allSecretsCategories))
	for i, sc := range allSecretsCategories {
		result[i] = string(sc)
	}
	return result
}

// ContainsSecretsCategory checks if the given string is a valid SecretsCategory.
func ContainsSecretsCategory(s string) bool {
	for _, sc := range allSecretsCategories {
		if string(sc) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// SeverityEnums
// ==============================================================================

// Severity represents the severity levels.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// allSeverities holds all valid Severity values.
var allSeverities = []Severity{
	SeverityInfo,
	SeverityLow,
	SeverityMedium,
	SeverityHigh,
	SeverityCritical,
}

// String returns the string representation of a Severity.
func (s Severity) String() string {
	return string(s)
}

// AllSeverities returns a slice of all valid Severity string values.
func AllSeverities() []string {
	result := make([]string, len(allSeverities))
	for i, s := range allSeverities {
		result[i] = string(s)
	}
	return result
}

// ContainsSeverity checks if the given string is a valid Severity.
func ContainsSeverity(s string) bool {
	for _, sev := range allSeverities {
		if string(sev) == s {
			return true
		}
	}
	return false
}

func OptionalContainsSeverity(s *string) bool {
	if s == nil {
		return true
	}

	return ContainsSeverity(*s)
}

// ==============================================================================
// ScannerEnums
// ==============================================================================

// Scanner represents the scanner types.
type Scanner string

const (
	ScannerIAC     Scanner = "IAC"
	ScannerSecrets Scanner = "SECRETS"
)

// allScanners holds all valid Scanner values.
var allScanners = []Scanner{
	ScannerIAC,
	ScannerSecrets,
}

// String returns the string representation of a Scanner.
func (s Scanner) String() string {
	return string(s)
}

// AllScanners returns a slice of all valid Scanner string values.
func AllScanners() []string {
	result := make([]string, len(allScanners))
	for i, s := range allScanners {
		result[i] = string(s)
	}
	return result
}

// ContainsScanner checks if the given string is a valid Scanner.
func ContainsScanner(s string) bool {
	for _, scanner := range allScanners {
		if string(scanner) == s {
			return true
		}
	}
	return false
}

func OptionalContainsScanner(s *string) bool {
	if s == nil {
		return true
	}

	return ContainsScanner(*s)
}

// ==============================================================================
// SortByEnums
// ==============================================================================

// SortBy represents the SortBy options for the List function.
type SortBy string

const (
	SortByCreatedAt SortBy = "created_at"
	SortByName      SortBy = "name"
	SortByLabels    SortBy = "labels"
)

// allSortBys holds all valid SortBy values.
var allSortBys = []SortBy{
	SortByCreatedAt,
	SortByName,
	SortByLabels,
}

// String returns the string representation of a SortBy.
func (s SortBy) String() string {
	return string(s)
}

// AllSortBys returns a slice of all valid SortBy string values.
func AllSortBys() []string {
	result := make([]string, len(allSortBys))
	for i, s := range allSortBys {
		result[i] = string(s)
	}
	return result
}

// ContainsSortBy checks if the given string is a valid SortBy.
func ContainsSortBy(s string) bool {
	for _, scanner := range allSortBys {
		if string(scanner) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// FrameworkNameEnums
// ==============================================================================

// FrameworkName represents the framework names.
type FrameworkName string

const (
	FrameworkNameAnsible           FrameworkName = "ANSIBLE"
	FrameworkNameARM               FrameworkName = "ARM"
	FrameworkNameBicep             FrameworkName = "BICEP"
	FrameworkNameCICDAzureOrg      FrameworkName = "CI_CD_AZURE_ORG"
	FrameworkNameCICDAzureRepo     FrameworkName = "CI_CD_AZURE_REPO"
	FrameworkNameCICDBitbucketOrg  FrameworkName = "CI_CD_BITBUCKET_ORG"
	FrameworkNameCICDBitbucketRepo FrameworkName = "CI_CD_BITBUCKET_REPO"
	FrameworkNameCICDCircleCI      FrameworkName = "CI_CD_CIRCLE_CI"
	FrameworkNameCICDCrossSystem   FrameworkName = "CI_CD_CROSS_SYSTEM"
	FrameworkNameCICDGithubOrg     FrameworkName = "CI_CD_GITHUB_ORG"
	FrameworkNameCICDGithubRepo    FrameworkName = "CI_CD_GITHUB_REPO"
	FrameworkNameCICDGitlabOrg     FrameworkName = "CI_CD_GITLAB_ORG"
	FrameworkNameCICDGitlabRepo    FrameworkName = "CI_CD_GITLAB_REPO"
	FrameworkNameCI_CDJenkinsCI    FrameworkName = "CI_CD_JENKINS_CI"
	FrameworkNameCloudformation    FrameworkName = "CLOUDFORMATION"
	FrameworkNameDockerfile        FrameworkName = "DOCKERFILE"
	FrameworkNameGit               FrameworkName = "GIT"
	FrameworkNameHelm              FrameworkName = "HELM"
	FrameworkNameKubernetes        FrameworkName = "KUBERNETES"
	FrameworkNameKustomize         FrameworkName = "KUSTOMIZE"
	FrameworkNameOpenAPI           FrameworkName = "OPENAPI"
	FrameworkNameSecrets           FrameworkName = "SECRETS"
	FrameworkNameServerless        FrameworkName = "SERVERLESS"
	FrameworkNameTerraform         FrameworkName = "TERRAFORM"
	FrameworkNameTerraformPlan     FrameworkName = "TERRAFORMPLAN"
)

// allFrameworkNames holds all valid FrameworkName values.
var allFrameworkNames = []FrameworkName{
	FrameworkNameAnsible,
	FrameworkNameARM,
	FrameworkNameBicep,
	FrameworkNameCICDAzureOrg,
	FrameworkNameCICDAzureRepo,
	FrameworkNameCICDBitbucketOrg,
	FrameworkNameCICDBitbucketRepo,
	FrameworkNameCICDCircleCI,
	FrameworkNameCICDCrossSystem,
	FrameworkNameCICDGithubOrg,
	FrameworkNameCICDGithubRepo,
	FrameworkNameCICDGitlabOrg,
	FrameworkNameCICDGitlabRepo,
	FrameworkNameCI_CDJenkinsCI,
	FrameworkNameCloudformation,
	FrameworkNameDockerfile,
	FrameworkNameGit,
	FrameworkNameHelm,
	FrameworkNameKubernetes,
	FrameworkNameKustomize,
	FrameworkNameOpenAPI,
	FrameworkNameSecrets,
	FrameworkNameServerless,
	FrameworkNameTerraform,
	FrameworkNameTerraformPlan,
}

// String returns the string representation of a FrameworkName.
func (fn FrameworkName) String() string {
	return string(fn)
}

// AllFrameworkNames returns a slice of all valid FrameworkName string values.
func AllFrameworkNames() []string {
	result := make([]string, len(allFrameworkNames))
	for i, fn := range allFrameworkNames {
		result[i] = string(fn)
	}
	return result
}

// ContainsFrameworkName checks if the given string is a valid FrameworkName.
func ContainsFrameworkName(s string) bool {
	for _, fn := range allFrameworkNames {
		if string(fn) == s {
			return true
		}
	}
	return false
}

func (fn FrameworkName) IsAFrameworkName() bool {
	return ContainsFrameworkName(string(fn))
}
