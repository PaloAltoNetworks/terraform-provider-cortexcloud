// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// TestManualCloudIntegrationInstanceIsRegistered verifies the manual connector
// resource is advertised by the provider under its expected type name.
//
// A resource that is implemented but not registered is invisible: a
// configuration referencing it fails at plan time with "invalid resource type",
// and no other test in the package would notice. This walks the provider's own
// registration list and asks each resource for its metadata, so it cannot pass
// by a resource merely existing in the codebase.
func TestManualCloudIntegrationInstanceIsRegistered(t *testing.T) {
	ctx := context.Background()

	const (
		providerTypeName = "cortexcloud"
		wantTypeName     = "cortexcloud_cloud_manual_integration_instance"
	)

	registered := map[string]bool{}
	for _, newResource := range (&CortexCloudProvider{}).Resources(ctx) {
		var metadata resource.MetadataResponse
		newResource().Metadata(ctx, resource.MetadataRequest{ProviderTypeName: providerTypeName}, &metadata)
		registered[metadata.TypeName] = true
	}

	if !registered[wantTypeName] {
		t.Fatalf("%s is not registered with the provider: a configuration referencing it "+
			"would fail at plan time with an invalid resource type", wantTypeName)
	}
}

// TestContainerRegistryResourceAndDataSourceAreRegistered verifies the CWP
// registry onboarding resource and data source are both advertised by the
// provider under their expected type names, for the same reason as above: an
// implemented-but-unregistered resource/data source is invisible until a real
// configuration fails at plan time.
func TestContainerRegistryResourceAndDataSourceAreRegistered(t *testing.T) {
	ctx := context.Background()
	const (
		providerTypeName = "cortexcloud"
		wantTypeName     = "cortexcloud_container_registry"
	)

	registeredResources := map[string]bool{}
	for _, newResource := range (&CortexCloudProvider{}).Resources(ctx) {
		var metadata resource.MetadataResponse
		newResource().Metadata(ctx, resource.MetadataRequest{ProviderTypeName: providerTypeName}, &metadata)
		registeredResources[metadata.TypeName] = true
	}
	if !registeredResources[wantTypeName] {
		t.Fatalf("resource %s is not registered with the provider", wantTypeName)
	}

	registeredDataSources := map[string]bool{}
	for _, newDataSource := range (&CortexCloudProvider{}).DataSources(ctx) {
		var metadata datasource.MetadataResponse
		newDataSource().Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: providerTypeName}, &metadata)
		registeredDataSources[metadata.TypeName] = true
	}
	if !registeredDataSources[wantTypeName] {
		t.Fatalf("data source %s is not registered with the provider", wantTypeName)
	}
}
