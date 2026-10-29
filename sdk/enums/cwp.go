// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package enums

// ==============================================================================
// Policy Type Enums
// ==============================================================================

type PolicyType string

const (
	PolicyTypeCompliance PolicyType = "COMPLIANCE"
	PolicyTypeMalware    PolicyType = "MALWARE"
	PolicyTypeSecret     PolicyType = "SECRET"
	PolicyTypeNull       PolicyType = ""
)

// allPolicyTypes holds all valid PolicyType values.
var allPolicyTypes = []PolicyType{
	PolicyTypeCompliance,
	PolicyTypeMalware,
	PolicyTypeSecret,
	PolicyTypeNull,
}

// Returns the string representation of a PolicyType.
func (pt PolicyType) String() string {
	return string(pt)
}

// AllPolicyTypes returns a slice of all valid PolicyType string values.
func AllPolicyTypes() []string {
	result := make([]string, len(allPolicyTypes))
	for i, pt := range allPolicyTypes {
		result[i] = string(pt)
	}
	return result
}

// ContainsPolicyType checks if the given string is a valid PolicyType.
func ContainsPolicyType(s string) bool {
	for _, policyType := range allPolicyTypes {
		if string(policyType) == s {
			return true // Includes empty string check
		}
	}
	return false
}

// ==============================================================================
// Evaluation Mode Enums
// ==============================================================================

type EvaluationMode string

const (
	EvaluationModePeriodic   EvaluationMode = "PERIODIC"
	EvaluationModeContinuous EvaluationMode = "CONTINUOUS"
	EvaluationModeNull       EvaluationMode = ""
)

// allEvaluationModes holds all valid EvaluationMode values.
var allEvaluationModes = []EvaluationMode{
	EvaluationModePeriodic,
	EvaluationModeContinuous,
	EvaluationModeNull,
}

// Returns the string representation of an EvaluationMode.
func (em EvaluationMode) String() string {
	return string(em)
}

// AllEvaluationModes returns a slice of all valid EvaluationMode string values.
func AllEvaluationModes() []string {
	result := make([]string, len(allEvaluationModes))
	for i, em := range allEvaluationModes {
		result[i] = string(em)
	}
	return result
}

// ContainsEvaluationMode checks if the given string is a valid EvaluationMode.
func ContainsEvaluationMode(s string) bool {
	for _, evaluationMode := range allEvaluationModes {
		if string(evaluationMode) == s {
			return true // Includes empty string check√
		}
	}
	return false
}

// =============================================================================
// Evaluation Stage Enums
// ==============================================================================
type EvaluationStage string

const (
	EvaluationStageCI      EvaluationStage = "CI"
	EvaluationStageRuntime EvaluationStage = "RUNTIME"
	EvaluationStageDeploy  EvaluationStage = "DEPLOY"
	EvaluationStageNull    EvaluationStage = ""
)

// allEvaluationStages holds all valid EvaluationStage values.
var allEvaluationStages = []EvaluationStage{
	EvaluationStageCI,
	EvaluationStageRuntime,
	EvaluationStageDeploy,
	EvaluationStageNull,
}

// Returns the string representation of an EvaluationStage.
func (es EvaluationStage) String() string {
	return string(es)
}

// AllEvaluationStages returns a slice of all valid EvaluationStage string values.
func AllEvaluationStages() []string {
	result := make([]string, len(allEvaluationStages))
	for i, es := range allEvaluationStages {
		result[i] = string(es)
	}
	return result
}

// ContainsEvaluationStage checks if the given string is a valid EvaluationStage.
func ContainsEvaluationStage(s string) bool {
	for _, evaluationStage := range allEvaluationStages {
		if string(evaluationStage) == s {
			return true // Includes empty string check
		}
	}
	return false
}

// =============================================================================
// Policy Action Enums
// ==============================================================================
type PolicyAction string

const (
	PolicyActionIssue   PolicyAction = "ISSUE"
	PolicyActionPrevent PolicyAction = "PREVENT"
	PolicyActionNull    PolicyAction = "NULL"
)

// allActions holds all valid PolicyAction values.
var allPolicyActions = []PolicyAction{
	PolicyActionIssue,
	PolicyActionPrevent,
	PolicyActionNull,
}

// Returns the string representation of an PolicyAction.
func (a PolicyAction) String() string {
	return string(a)
}

// AllPolicyActions returns a slice of all valid PolicyAction string values.
func AllPolicyActions() []string {
	result := make([]string, len(allPolicyActions))
	for i, a := range allPolicyActions {
		result[i] = string(a)
	}
	return result
}

// ContainsPolicyAction checks if the given string is a valid PolicyAction.
func ContainsPolicyAction(s string) bool {
	for _, policyAction := range allPolicyActions {
		if string(policyAction) == s {
			return true // Includes empty string check
		}
	}
	return false
}

// ==============================================================================
// Policy Severity Enums
// ==============================================================================
type PolicySeverity string

const (
	PolicySeverityLow      PolicySeverity = "LOW"
	PolicySeverityMedium   PolicySeverity = "MEDIUM"
	PolicySeverityHigh     PolicySeverity = "HIGH"
	PolicySeverityCritical PolicySeverity = "CRITICAL"
	PolicySeverityNull     PolicySeverity = ""
)

// allSeverities holds all valid PolicySeverity values.
var allPolicySeverities = []PolicySeverity{
	PolicySeverityLow,
	PolicySeverityMedium,
	PolicySeverityHigh,
	PolicySeverityCritical,
	PolicySeverityNull,
}

// Returns the string representation of a PolicySeverity.
func (s PolicySeverity) String() string {
	return string(s)
}

// AllPolicySeverities returns a slice of all valid PolicySeverity string values.
func AllPolicySeverities() []string {
	result := make([]string, len(allPolicySeverities))
	for i, s := range allPolicySeverities {
		result[i] = string(s)
	}
	return result
}

// ContainsPolicySeverity checks if the given string is a valid PolicySeverity.
func ContainsPolicySeverity(s string) bool {
	for _, policySeverity := range allPolicySeverities {
		if string(policySeverity) == s {
			return true // Includes empty string check
		}
	}
	return false
}

// ==============================================================================
// Registry Onboarding Enums
// ==============================================================================
//
// The initial scan configuration mode (ALL / LATEST_TAG / TAGS_MODIFIED_DAYS)
// is shared with cloud onboarding and lives in RegistryScanningType.

// RegistryVendor is the vendor of a third-party container registry connector.
type RegistryVendor string

const (
	RegistryVendorDocker                  RegistryVendor = "DOCKER"
	RegistryVendorJFrog                   RegistryVendor = "JFROG"
	RegistryVendorSonatype                RegistryVendor = "SONATYPE"
	RegistryVendorDockerHub               RegistryVendor = "DOCKER_HUB"
	RegistryVendorHarbor                  RegistryVendor = "HARBOR"
	RegistryVendorGitLabContainerRegistry RegistryVendor = "GITLAB_CONTAINER_REGISTRY"
	RegistryVendorOpenShift               RegistryVendor = "OPENSHIFT"
)

func (v RegistryVendor) String() string { return string(v) }

// AllRegistryVendors returns all valid RegistryVendor values.
func AllRegistryVendors() []string {
	return []string{
		RegistryVendorDocker.String(),
		RegistryVendorJFrog.String(),
		RegistryVendorSonatype.String(),
		RegistryVendorDockerHub.String(),
		RegistryVendorHarbor.String(),
		RegistryVendorGitLabContainerRegistry.String(),
		RegistryVendorOpenShift.String(),
	}
}

// RegistryScanningMode is where registry scanning is executed.
type RegistryScanningMode string

const (
	RegistryScanningModeCloud         RegistryScanningMode = "CLOUD"
	RegistryScanningModeOutpost       RegistryScanningMode = "OUTPOST"
	RegistryScanningModeBroker        RegistryScanningMode = "BROKER"
	RegistryScanningModeNotApplicable RegistryScanningMode = "NOT_APPLICABLE"
	RegistryScanningModeKAPI          RegistryScanningMode = "KAPI"
)

func (m RegistryScanningMode) String() string { return string(m) }

// AllRegistryScanningModes returns all valid RegistryScanningMode values.
func AllRegistryScanningModes() []string {
	return []string{
		RegistryScanningModeCloud.String(),
		RegistryScanningModeOutpost.String(),
		RegistryScanningModeBroker.String(),
		RegistryScanningModeNotApplicable.String(),
		RegistryScanningModeKAPI.String(),
	}
}

// RegistryCloudProvider is the Cortex cloud environment used for CLOUD scanning.
type RegistryCloudProvider string

const (
	RegistryCloudProviderAWS   RegistryCloudProvider = "AWS"
	RegistryCloudProviderGCP   RegistryCloudProvider = "GCP"
	RegistryCloudProviderAzure RegistryCloudProvider = "AZURE"
)

func (p RegistryCloudProvider) String() string { return string(p) }

// AllRegistryCloudProviders returns all valid RegistryCloudProvider values.
func AllRegistryCloudProviders() []string {
	return []string{
		RegistryCloudProviderAWS.String(),
		RegistryCloudProviderGCP.String(),
		RegistryCloudProviderAzure.String(),
	}
}

// RegistryHostingType is whether a registry is cloud hosted or self hosted.
type RegistryHostingType string

const (
	RegistryHostingTypeCloudHosted RegistryHostingType = "CLOUD_HOSTED"
	RegistryHostingTypeSelfHosted  RegistryHostingType = "SELF_HOSTED"
)

func (t RegistryHostingType) String() string { return string(t) }

// AllRegistryHostingTypes returns all valid RegistryHostingType values.
func AllRegistryHostingTypes() []string {
	return []string{
		RegistryHostingTypeCloudHosted.String(),
		RegistryHostingTypeSelfHosted.String(),
	}
}

// RegistryBrokerType is the Broker VM type used for BROKER scanning.
type RegistryBrokerType string

const (
	RegistryBrokerTypeVM      RegistryBrokerType = "BROKER_VM"
	RegistryBrokerTypeCluster RegistryBrokerType = "BROKER_CLUSTER"
)

func (t RegistryBrokerType) String() string { return string(t) }

// AllRegistryBrokerTypes returns all valid RegistryBrokerType values.
func AllRegistryBrokerTypes() []string {
	return []string{
		RegistryBrokerTypeVM.String(),
		RegistryBrokerTypeCluster.String(),
	}
}

// RegistryFilterType controls whether asset scope filters include or exclude.
type RegistryFilterType string

const (
	RegistryFilterTypeInclude RegistryFilterType = "INCLUDE"
	RegistryFilterTypeExclude RegistryFilterType = "EXCLUDE"
)

func (t RegistryFilterType) String() string { return string(t) }

// AllRegistryFilterTypes returns all valid RegistryFilterType values.
func AllRegistryFilterTypes() []string {
	return []string{
		RegistryFilterTypeInclude.String(),
		RegistryFilterTypeExclude.String(),
	}
}
