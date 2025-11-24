// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/log"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	cloudOnboardingDataSources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/data_sources/cloud_onboarding"
	platformDataSources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/data_sources/platform"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	cloudOnboardingResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/cloud_onboarding"
	platformResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/platform"
	cloudOnboardingEphemeralResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/ephemeral/cloud_onboarding"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider                       = &CortexCloudProvider{}
	_ provider.ProviderWithEphemeralResources = &CortexCloudProvider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New(version string) func() provider.Provider {
	tflog.Info(context.Background(), fmt.Sprintf("Cortex Cloud Terraform Provider version: %s", version))
	if version == "test" {
		return func() provider.Provider {
			return &CortexCloudProvider{
				version: version,
			}
		}
	}

	return func() provider.Provider {
		return &CortexCloudProvider{
			version: version,
		}
	}
}

// CortexCloudProvider is the provider implementation.
type CortexCloudProvider struct {
	version string
}

func (p *CortexCloudProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "cortexcloud"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *CortexCloudProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"config_file": schema.StringAttribute{
				Optional:    true,
				Description: "Local path to provider configuration JSON file.",
			},
			"fqdn": schema.StringAttribute{
				Optional: true,
				Description: fmt.Sprintf("The FQDN of your Cortex Cloud "+
					"tenant. Can also be configured using the `%s`"+
					"environment variable.", "CORTEX_FQDN"),
				//"environment variable.", client.CORTEXCLOUD_API_URL_ENV_VAR),
			},
			"api_url": schema.StringAttribute{
				Optional: true,
				Description: fmt.Sprintf("The API URL of your Cortex Cloud tenant. "+
					"You can retrieve this from the Cortex Cloud console by "+
					"navigating to Settings > Configurations > Integrations > "+
					"API Keys and clicking the \"Copy API URL\" button. Can "+
					"also be configured using the `%s` environment "+
					"variable.", "CORTEX_API_URL"),
				//"variable.", client.CORTEXCLOUD_API_URL_ENV_VAR),
			},
			"api_key": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "The API key for the user in Cortex Cloud that the " +
					"provider will use. You can create this from the Cortex Cloud " +
					"console by navigating to Settings > Configurations > Integrations " +
					"> API Keys. Can also be configured using the `CORTEX_API_KEY` " +
					"environment variable. \n\nWARNING: If you are running the provider " +
					"with Terraform with the `TF_LOG` environment variable set to `DEBUG`, " +
					"the provider will output this value in the debug logs.",
			},
			"api_key_id": schema.Int32Attribute{
				Optional:  true,
				Sensitive: true,
				Description: "The ID of the API key provided in the \"api_key\" " +
					"argument. You can retrieve this from the Cortex Cloud console " +
					"by navigating to Settings > Configurations > Integrations > " +
					"API Keys. Can also be configured using the `CORTEX_API_KEY_ID` " +
					"environment variable.",
			},
			"api_key_type": schema.StringAttribute{
				Optional: true,
				Description: "The type of API key provided. Defaults to " +
					"`standard`. Must be set to `advanced` if configuring " +
					"the provider with an advanced API key. When using an " +
					"advanced API key, requests to the Cortex API must " +
					"include a nonce (64 byte random string) and a timestamp" +
					"populated in the request headers to prevent replay " +
					"attacks.",
			},
			"sdk_log_level": schema.StringAttribute{
				Optional:    true,
				Description: "TODO",
			},
			"skip_ssl_verify": schema.BoolAttribute{
				Optional:    true,
				Description: "TODO",
			},
			"request_timeout": schema.Int32Attribute{
				Optional: true,
				Description: "Time (in seconds) to wait for requests to the Cortex " +
					"Cloud API to return before timing out. If omitted, the default value " +
					"is `60`. Can also be configured using the `CORTEX_TF_REQUEST_TIMEOUT` " +
					"environment variable.",
			},
			"request_retry_interval": schema.Int32Attribute{
				Optional: true,
				Description: "Time (in seconds) to wait between API requests in " +
					"the event of an HTTP 429 (Too Many Requests) response. If omitted, " +
					"the default value is `3`. Can also be configured using the " +
					"`CORTEX_TF_REQUEST_RETRY_INTERVAL` environment variable.",
			},
			"crash_stack_dir": schema.StringAttribute{
				Optional: true,
				Description: "The location on the filesystem where the crash stack " +
					"contents will be written in the event of the provider encountering " +
					"an unexpected error. If omitted, the default value is an empty " +
					"string, which will be interpreted as `$TMPDIR` on Unix systems (or " +
					"`/tmp` if `$TMPDIR` is empty). On Windows systems, an empty string " +
					"will be interpreted as the the first of the following values that is " +
					"non-empty, in order of evaluation: `%%TMP%%`, `%%TEMP%%`, " +
					"%%USERPROFILE%%`, or the Windows directory. Can also be configured " +
					"using the `CORTEX_TF_CRASH_STACK_DIR` environment variable.",
			},
		},
	}
}

func (p *CortexCloudProvider) Resources(ctx context.Context) []func() resource.Resource {
	resources := []func() resource.Resource{}

	tflog.Debug(ctx, "Registering Cloud Onboarding Resources")
	resources = append(
		resources,
		cloudOnboardingResources.NewCloudIntegrationTemplateAwsResource,
		cloudOnboardingResources.NewCloudIntegrationTemplateAzureResource,
		cloudOnboardingResources.NewCloudIntegrationTemplateGcpResource,
	)

	tflog.Debug(ctx, "Registering Platform Resources")
	resources = append(
		resources,
		platformResources.NewAuthenticationSettingsResource,
		platformResources.NewAssetGroupResource,
		platformResources.NewUserGroupResource,
		platformResources.NewUserResource,
		platformResources.NewScopeResource,
		platformResources.NewIamRoleResource,
	)

	return resources
}

func (p *CortexCloudProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	datasources := []func() datasource.DataSource{}

	tflog.Debug(ctx, "Registering Cloud Onboarding Data Sources")
	datasources = append(datasources,
		cloudOnboardingDataSources.NewCloudIntegrationInstanceDataSource,
		cloudOnboardingDataSources.NewCloudIntegrationInstancesDataSource,
		cloudOnboardingDataSources.NewOutpostDataSource,
		cloudOnboardingDataSources.NewOutpostsDataSource,
		cloudOnboardingDataSources.NewOutpostTemplateDataSource,
	)

	tflog.Debug(ctx, "Registering Platform Data Sources")
	datasources = append(datasources,
		platformDataSources.NewUserDataSource,
		platformDataSources.NewIamRoleDataSource,
		platformDataSources.NewGroupDataSource,
		platformDataSources.NewIamPermissionConfigDataSource,
	)

	return datasources
}

func (p *CortexCloudProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	ephemeralResources := []func() ephemeral.EphemeralResource{}

	tflog.Debug(ctx, "Registering Cloud Onboarding Ephemeral Resources")
	ephemeralResources = append(ephemeralResources,
		cloudOnboardingEphemeralResources.NewOutpostTemplateEphemeralResource,
	)

	return ephemeralResources
}

func (p *CortexCloudProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	tflog.Debug(ctx, "Starting provider configuration")

	// Retrieve configuration values from provider block
	var providerConfig *models.CortexCloudProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, providerConfig)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse config file
	providerConfig.ParseConfigFile(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse environment variables
	providerConfig.ParseEnvVars(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate provider configuration
	providerConfig.Validate(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	fqdn := providerConfig.FQDN.ValueString()
	apiURL := providerConfig.APIURL.ValueString()
	apiKey := providerConfig.APIKey.ValueString()
	apiKeyID := int(providerConfig.APIKeyID.ValueInt32())
	apiKeyType := providerConfig.APIKeyType.ValueString()
	sdkLogLevel := providerConfig.SDKLogLevel.ValueString()

	tflog.Debug(ctx, fmt.Sprintf("Using %s API key against API URL: %s", apiKeyType, apiURL))

	// Set logger fields
	ctx = tflog.SetField(ctx, "cortex_fqdn", fqdn)
	ctx = tflog.SetField(ctx, "cortex_api_key", apiKey)
	ctx = tflog.SetField(ctx, "cortex_api_key_id", apiKeyID)
	ctx = tflog.SetField(ctx, "cortex_api_key_type", apiKeyType)

	// TODO: create config param for conditionally applying the following masks
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "cortex_api_key", "cortex_api_key_id")

	// Initialize SDK clients
	clients := models.CortexCloudSDKClients{}

	tflog.Debug(ctx, "Initializing platform client")
	platformClient, err := platform.NewClient(
		platform.WithCortexFQDN(fqdn),
		platform.WithCortexAPIURL(apiURL),
		platform.WithCortexAPIKey(apiKey),
		platform.WithCortexAPIKeyID(apiKeyID),
		platform.WithCortexAPIKeyType(apiKeyType),
		platform.WithSkipSSLVerify(providerConfig.SkipSSLVerify.ValueBool()),
		platform.WithTimeout(int(providerConfig.RequestTimeout.ValueInt32())),
		//platform.WithRetryMaxDelay(providerConfig.RetryMaxDelay),
		platform.WithCrashStackDir(providerConfig.CrashStackDir.ValueString()),
		platform.WithLogger(log.TflogAdapter{}),
		platform.WithLogLevel(sdkLogLevel),
	)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	// Set the API URL logger field
	// TODO: define a way to retrieve this value without first creating a
	// client (or export)
	ctx = tflog.SetField(ctx, "cortex_api_url", platformClient.APIURL())

	tflog.Debug(ctx, "Initializing cloudonboarding client")
	cloudOnboardingClient, err := cloudonboarding.NewClient(
		cloudonboarding.WithCortexFQDN(fqdn),
		cloudonboarding.WithCortexAPIURL(apiURL),
		cloudonboarding.WithCortexAPIKey(apiKey),
		cloudonboarding.WithCortexAPIKeyID(apiKeyID),
		cloudonboarding.WithCortexAPIKeyType(apiKeyType),
		cloudonboarding.WithSkipSSLVerify(providerConfig.SkipSSLVerify.ValueBool()),
		cloudonboarding.WithTimeout(int(providerConfig.RequestTimeout.ValueInt32())),
		//cloudonboarding.WithRetryMaxDelay(providerConfig.RetryMaxDelay),
		cloudonboarding.WithCrashStackDir(providerConfig.CrashStackDir.ValueString()),
		cloudonboarding.WithLogger(log.TflogAdapter{}),
		cloudonboarding.WithLogLevel(sdkLogLevel),
	)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	tflog.Debug(ctx, "Cortex Cloud API client setup complete")

	// Attach SDK clients to model
	clients.CloudOnboarding = cloudOnboardingClient
	clients.Platform = platformClient

	// Assign clients model pointer to ProviderData to allow resources and
	// data sources to access SDK functions
	resp.DataSourceData = &clients
	resp.ResourceData = &clients
	resp.EphemeralResourceData = &clients
}
