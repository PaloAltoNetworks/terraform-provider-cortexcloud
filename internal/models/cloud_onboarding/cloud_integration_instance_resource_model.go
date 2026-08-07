// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"fmt"
	"sort"
	"strings"

	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// CloudIntegrationInstanceResourceModel is the Terraform model backing the
// cortexcloud_cloud_integration_instance resource. It is deliberately distinct
// from the data-source-facing CloudIntegrationInstanceModel: the resource must
// expose writable attributes that are part of the edit request but absent from
// the read type (outpost_id, cloud_partition, scope_modifications), and marking
// them on the shared data-source model would change the data source schema.
type CloudIntegrationInstanceResourceModel struct {
	// Writable / read attributes.
	ID                      types.String `tfsdk:"id"`
	InstanceName            types.String `tfsdk:"instance_name"`
	OutpostID               types.String `tfsdk:"outpost_id"`
	CloudProvider           types.String `tfsdk:"cloud_provider"`
	CloudPartition          types.String `tfsdk:"cloud_partition"`
	AdditionalCapabilities  types.Object `tfsdk:"additional_capabilities"`
	CollectionConfiguration types.Object `tfsdk:"collection_configuration"`
	CustomResourcesTags     types.Set    `tfsdk:"custom_resources_tags"`
	ScopeModifications      types.Object `tfsdk:"scope_modifications"`

	// Computed / read-only attributes.
	Collector types.String `tfsdk:"collector"`
	Scope     types.String `tfsdk:"scope"`
	Status    types.String `tfsdk:"status"`
	// SecurityCapabilities is a types.Set rather than a []SecurityCapability so
	// it can hold the unknown value Terraform assigns to computed attributes
	// during apply.
	SecurityCapabilities types.Set    `tfsdk:"security_capabilities"`
	Scan                 types.Object `tfsdk:"scan"`
	UpgradeAvailable     types.Bool   `tfsdk:"upgrade_available"`
}

// ToGetRequest builds a GetIntegrationInstanceRequest from the model's ID.
func (m *CloudIntegrationInstanceResourceModel) ToGetRequest(ctx context.Context, diags *diag.Diagnostics) *cloudOnboardingTypes.GetIntegrationInstanceRequest {
	tflog.Debug(ctx, "Creating GetIntegrationInstanceRequest from CloudIntegrationInstanceResourceModel")
	return cloudOnboardingTypes.NewGetIntegrationInstanceRequest(m.ID.ValueString())
}

// ToEditRequest builds an EditIntegrationInstanceRequest from the resource plan,
// wiring the resource-only write-only fields (outpost_id, cloud_partition,
// scope_modifications) in addition to the shared editable fields.
func (m *CloudIntegrationInstanceResourceModel) ToEditRequest(ctx context.Context, diags *diag.Diagnostics) *cloudOnboardingTypes.EditIntegrationInstanceRequest {
	tflog.Debug(ctx, "Creating EditIntegrationInstanceRequest from CloudIntegrationInstanceResourceModel")

	// No unknown value may reach the request. edit_instance is a strict
	// full-replace and the SDK targets (*bool, string) cannot represent unknown,
	// so converting one yields a Go zero value that is then written over live
	// state — an empty registry scanning type, a disabled capability. The
	// nested attributes are Optional+Computed, so every attribute the
	// practitioner did not configure arrives unknown during apply; resolving
	// them against the live instance is MergeFromRemote's job. Anything still
	// unknown at this point is a defect, so fail loudly and name it rather than
	// shipping a malformed full-replace body.
	assertNoUnknownAttributes(diags, "additional_capabilities", m.AdditionalCapabilities)
	assertNoUnknownAttributes(diags, "collection_configuration", m.CollectionConfiguration)
	assertNoUnknownAttributes(diags, "scope_modifications", m.ScopeModifications)
	if diags.HasError() {
		return nil
	}

	// A null additional_capabilities object is tolerated: leave the target as a
	// zero-value AdditionalCapabilities rather than attempting a conversion that
	// would emit diagnostics. Null leaves (as opposed to unknown ones) are a
	// legitimate "not set" and are coerced to the documented defaults below.
	var additionalCapabilities cloudOnboardingTypes.AdditionalCapabilities
	if !m.AdditionalCapabilities.IsNull() && !m.AdditionalCapabilities.IsUnknown() {
		diags.Append(m.AdditionalCapabilities.As(ctx, &additionalCapabilities, basetypes.ObjectAsOptions{})...)
	}
	// The edit_instance contract requires every additional_capabilities boolean
	// to serialize as a concrete true/false; a null pointer is rejected by the
	// API's validation. Coerce any unset capability to false and enforce the
	// registry_scanning <-> registry_scanning_options coupling (both or neither).
	normalizeAdditionalCapabilities(&additionalCapabilities)

	var collectionConfiguration cloudOnboardingTypes.CollectionConfiguration
	if !m.CollectionConfiguration.IsNull() && !m.CollectionConfiguration.IsUnknown() {
		diags.Append(m.CollectionConfiguration.As(ctx, &collectionConfiguration, basetypes.ObjectAsOptions{})...)
	}

	// The edit_instance contract requires custom_resources_tags to be a JSON
	// list; a null value is rejected. Default to a non-nil empty slice so the
	// field always marshals as [] rather than null.
	customResourcesTags := []cloudOnboardingTypes.Tag{}
	if !m.CustomResourcesTags.IsNull() && !m.CustomResourcesTags.IsUnknown() {
		diags.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)
	}

	if diags.HasError() {
		return nil
	}

	options := []cloudOnboardingTypes.EditIntegrationInstanceRequestOption{
		cloudOnboardingTypes.WithEditAdditionalCapabilities(additionalCapabilities),
		cloudOnboardingTypes.WithEditCloudProvider(m.CloudProvider.ValueString()),
		cloudOnboardingTypes.WithEditCollectionConfiguration(collectionConfiguration),
		cloudOnboardingTypes.WithEditCustomResourcesTags(customResourcesTags),
	}

	// instance_name is optional/omitempty: only set it when configured.
	if !m.InstanceName.IsNull() && !m.InstanceName.IsUnknown() {
		options = append(options, cloudOnboardingTypes.WithEditInstanceName(m.InstanceName.ValueString()))
	}

	// outpost_id (scan_env_id) is optional/omitempty: only set it when configured.
	if !m.OutpostID.IsNull() && !m.OutpostID.IsUnknown() {
		options = append(options, cloudOnboardingTypes.WithEditOutpostID(m.OutpostID.ValueString()))
	}

	// cloud_partition is a write-only optional field.
	if !m.CloudPartition.IsNull() && !m.CloudPartition.IsUnknown() {
		options = append(options, cloudOnboardingTypes.WithEditCloudPartition(m.CloudPartition.ValueString()))
	}

	// scope_modifications is always marshalled by the request type, and the
	// edit_instance contract requires its regions block, so it is wired
	// unconditionally with a disabled regions block as the fallback.
	var scopeModifications cloudOnboardingTypes.ScopeModifications
	if !m.ScopeModifications.IsNull() && !m.ScopeModifications.IsUnknown() {
		diags.Append(m.ScopeModifications.As(ctx, &scopeModifications, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil
		}
	}
	if scopeModifications.Regions == nil {
		scopeModifications.Regions = &cloudOnboardingTypes.ScopeModificationRegions{Enabled: false}
	}
	options = append(options, cloudOnboardingTypes.WithEditScopeModifications(scopeModifications))

	return cloudOnboardingTypes.NewEditIntegrationInstanceRequest(m.ID.ValueString(), options...)
}

// normalizeAdditionalCapabilities enforces the edit_instance contract rules for
// the additional_capabilities block: every boolean must serialize to a concrete
// true/false (a null pointer is rejected by the API), and registry_scanning is
// coupled with registry_scanning_options (both or neither may be present). Unset
// booleans are coerced to false, and registry_scanning_options is dropped when
// registry_scanning is not enabled.
func normalizeAdditionalCapabilities(ac *cloudOnboardingTypes.AdditionalCapabilities) {
	ac.XSIAMAnalytics = boolPtrOrFalse(ac.XSIAMAnalytics)
	ac.DataSecurityPostureManagement = boolPtrOrFalse(ac.DataSecurityPostureManagement)
	ac.RegistryScanning = boolPtrOrFalse(ac.RegistryScanning)
	ac.ServerlessScanning = boolPtrOrFalse(ac.ServerlessScanning)
	ac.AgentlessDiskScanning = boolPtrOrFalse(ac.AgentlessDiskScanning)

	// Registry coupling: registry_scanning_options may only accompany an enabled
	// registry_scanning. Drop the options block otherwise so the pair is "both
	// or neither".
	if ac.RegistryScanning == nil || !*ac.RegistryScanning {
		ac.RegistryScanningOptions = nil
	}
}

// boolPtrOrFalse returns the given *bool unchanged when it is non-nil, or a
// pointer to false when it is nil. It guarantees a concrete boolean is
// serialized for edit_instance capability fields.
func boolPtrOrFalse(b *bool) *bool {
	if b != nil {
		return b
	}
	falseValue := false
	return &falseValue
}

// MergeFromRemote overlays the live instance state onto the model for editable
// fields the plan leaves unspecified (null/unknown). The edit_instance API is a
// strict full-replace: any editable field omitted from the request is blanked
// server-side. To avoid clobbering server state the caller reads the current
// instance first and merges it here, so only fields the practitioner actually
// configured diverge from the live values. Configured (non-null) plan fields are
// left untouched; the identity (id) and read-only/computed fields are populated
// by RefreshFromRemote after the edit and are not merged here.
func (m *CloudIntegrationInstanceResourceModel) MergeFromRemote(ctx context.Context, diags *diag.Diagnostics, data cloudOnboardingTypes.IntegrationInstance) {
	tflog.Debug(ctx, "Merging unspecified editable fields from live instance state")

	if m.CloudProvider.IsNull() || m.CloudProvider.IsUnknown() {
		m.CloudProvider = types.StringValue(data.CloudProvider)
	}

	if m.InstanceName.IsNull() || m.InstanceName.IsUnknown() {
		if data.InstanceName != "" {
			m.InstanceName = types.StringValue(data.InstanceName)
		}
	}

	remoteAdditionalCapabilities, diagsMerge := types.ObjectValueFrom(ctx, m.AdditionalCapabilities.AttributeTypes(ctx), data.AdditionalCapabilities)
	diags.Append(diagsMerge...)
	if diags.HasError() {
		return
	}
	m.AdditionalCapabilities = mergeUnspecifiedObjectAttributes(ctx, diags, m.AdditionalCapabilities, remoteAdditionalCapabilities)
	if diags.HasError() {
		return
	}

	remoteCollectionConfiguration, diagsMerge := types.ObjectValueFrom(ctx, m.CollectionConfiguration.AttributeTypes(ctx), data.CollectionConfiguration)
	diags.Append(diagsMerge...)
	if diags.HasError() {
		return
	}
	m.CollectionConfiguration = mergeUnspecifiedObjectAttributes(ctx, diags, m.CollectionConfiguration, remoteCollectionConfiguration)
	if diags.HasError() {
		return
	}

	if m.CustomResourcesTags.IsNull() || m.CustomResourcesTags.IsUnknown() {
		tags, diagsMerge := types.SetValueFrom(ctx, m.CustomResourcesTags.ElementType(ctx), data.CustomResourcesTags)
		diags.Append(diagsMerge...)
		if diags.HasError() {
			return
		}
		m.CustomResourcesTags = tags
	}
}

// mergeUnspecifiedObjectAttributes overlays remote onto planned, attribute by
// attribute, returning a value that keeps every attribute the practitioner
// configured and inherits the live value for every attribute they did not.
// Nested objects are merged recursively so a configured sibling never causes an
// unconfigured one to be blanked. A whole-object gate is not sufficient here:
// under edit_instance's full-replace semantics an unknown sibling attribute
// would otherwise serialize as false and silently disable a live capability.
func mergeUnspecifiedObjectAttributes(ctx context.Context, diags *diag.Diagnostics, planned, remote types.Object) types.Object {
	if planned.IsNull() || planned.IsUnknown() {
		return remote
	}
	if remote.IsNull() || remote.IsUnknown() {
		return planned
	}

	attributeTypes := planned.AttributeTypes(ctx)
	plannedAttributes := planned.Attributes()
	remoteAttributes := remote.Attributes()
	merged := make(map[string]attr.Value, len(plannedAttributes))

	for name, plannedValue := range plannedAttributes {
		remoteValue, ok := remoteAttributes[name]
		if !ok {
			merged[name] = plannedValue
			continue
		}

		// Recurse only when both sides actually carry attributes. A null or
		// unknown remote value still satisfies the types.Object assertion, and
		// recursing into it just returns the planned object — including any
		// unknown children — which would then reach the request. Falling
		// through instead keeps the planned object intact for a genuinely new
		// nested block, and any unknown child it still carries is caught by the
		// assertion in ToEditRequest rather than silently zeroed.
		plannedObject, plannedIsObject := plannedValue.(types.Object)
		remoteObject, remoteIsObject := remoteValue.(types.Object)
		plannedIsPopulatedObject := plannedIsObject && !plannedObject.IsNull() && !plannedObject.IsUnknown()
		remoteIsPopulatedObject := remoteIsObject && !remoteObject.IsNull() && !remoteObject.IsUnknown()
		if plannedIsPopulatedObject && remoteIsPopulatedObject {
			merged[name] = mergeUnspecifiedObjectAttributes(ctx, diags, plannedObject, remoteObject)
			continue
		}

		if plannedValue.IsNull() || plannedValue.IsUnknown() {
			merged[name] = remoteValue
			continue
		}

		merged[name] = plannedValue
	}

	mergedObject, diagsMerge := types.ObjectValue(attributeTypes, merged)
	diags.Append(diagsMerge...)
	if diags.HasError() {
		return planned
	}
	return mergedObject
}

// assertNoUnknownAttributes appends an error diagnostic naming every unknown
// leaf under the given object. It is the safety net for the full-replace edit:
// the SDK request types cannot represent unknown, so an unknown that survives
// MergeFromRemote would otherwise be serialized as a Go zero value ("" for an
// enum, false for a capability) and overwrite live configuration with no
// diagnostic at all. Failing loudly keeps a provider defect visible instead of
// turning it into a silent bad write.
func assertNoUnknownAttributes(diags *diag.Diagnostics, name string, value types.Object) {
	unknownPaths := collectUnknownAttributePaths(name, value)
	if len(unknownPaths) == 0 {
		return
	}

	sort.Strings(unknownPaths)
	diags.AddError(
		"Unresolved Values in Cloud Integration Instance Edit Request",
		fmt.Sprintf(
			"The following attributes are not known at apply time and cannot be "+
				"sent to the edit API: %s. Because the edit replaces the whole "+
				"instance configuration, sending a placeholder for them would "+
				"overwrite the live configuration. Set these attributes "+
				"explicitly in the configuration, or report this as a provider "+
				"bug if they are values the provider should have resolved.",
			strings.Join(unknownPaths, ", "),
		),
	)
}

// collectUnknownAttributePaths returns the dotted attribute paths of every
// unknown leaf under the given object, recursing into nested objects. An object
// that is itself unknown is reported as a single path; a null object has no
// unknown leaves.
func collectUnknownAttributePaths(prefix string, value types.Object) []string {
	if value.IsUnknown() {
		return []string{prefix}
	}
	if value.IsNull() {
		return nil
	}

	var paths []string
	for name, attribute := range value.Attributes() {
		attributePath := prefix + "." + name
		if nestedObject, isObject := attribute.(types.Object); isObject {
			paths = append(paths, collectUnknownAttributePaths(attributePath, nestedObject)...)
			continue
		}
		if attribute.IsUnknown() {
			paths = append(paths, attributePath)
		}
	}
	return paths
}

// RefreshFromRemote maps the read type returned by GetIntegrationInstanceDetails
// onto the resource model. It does not touch the write-only attributes
// (cloud_partition, scope_modifications) which are absent from the read type.
func (m *CloudIntegrationInstanceResourceModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, data cloudOnboardingTypes.IntegrationInstance) {
	tflog.Debug(ctx, "Refreshing resource attribute values")

	tflog.Trace(ctx, "Converting AdditionalCapabilities to Terraform type")
	additionalCapabilities, diagsRefresh := types.ObjectValueFrom(ctx, m.AdditionalCapabilities.AttributeTypes(ctx), data.AdditionalCapabilities)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Converting CollectionConfiguration to Terraform type")
	collectionConfiguration, diagsRefresh := types.ObjectValueFrom(ctx, m.CollectionConfiguration.AttributeTypes(ctx), data.CollectionConfiguration)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Converting CustomResourceTags to Terraform type")
	tags, diagsRefresh := types.SetValueFrom(ctx, m.CustomResourcesTags.ElementType(ctx), data.CustomResourcesTags)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Converting Scan to Terraform type")
	scan, diagsRefresh := types.ObjectValueFrom(ctx, m.Scan.AttributeTypes(ctx), data.Scan)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Converting SecurityCapabilities to Terraform type")
	var securityCapabilities []SecurityCapability
	for _, sc := range data.SecurityCapabilities {
		securityCapability := SecurityCapability{
			Name:        types.StringValue(sc.Name),
			Description: types.StringValue(sc.Description),
			StatusCode:  types.Int32Value(int32(sc.Status)),
			Status:      types.StringValue(securityCapabilityStatusToString(sc.Status)),
		}

		if sc.LastScanCoverage != nil {
			lastScanCoverage, diagsCoverage := types.ObjectValueFrom(ctx, lastScanCoverageAttrTypes, sc.LastScanCoverage)
			diags.Append(diagsCoverage...)
			if diags.HasError() {
				return
			}
			securityCapability.LastScanCoverage = lastScanCoverage
		} else {
			securityCapability.LastScanCoverage = types.ObjectNull(lastScanCoverageAttrTypes)
		}

		securityCapabilities = append(securityCapabilities, securityCapability)
	}

	securityCapabilitiesSet, diagsRefresh := types.SetValueFrom(ctx, securityCapabilitySetType, securityCapabilities)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	m.ID = types.StringValue(data.ID)
	m.AdditionalCapabilities = additionalCapabilities
	m.CloudProvider = types.StringValue(data.CloudProvider)
	m.Collector = types.StringValue(data.Collector)
	m.CollectionConfiguration = collectionConfiguration
	m.CustomResourcesTags = tags
	m.InstanceName = types.StringValue(data.InstanceName)
	m.Scan = scan
	m.Scope = types.StringValue(data.Scope)
	m.Status = types.StringValue(data.Status)
	m.SecurityCapabilities = securityCapabilitiesSet
	m.UpgradeAvailable = types.BoolValue(data.UpgradeAvailable)

	// outpost_id is surfaced on the read type; keep it in sync where available.
	if data.OutpostID != "" {
		m.OutpostID = types.StringValue(data.OutpostID)
	}
}
