// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	"github.com/PaloAltoNetworks/cortex-cloud-go/client"
	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/log"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	cloudOnboardingDataSources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/data_sources/cloud_onboarding"
	platformDataSources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/data_sources/platform"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	appSecResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/application_security"
	cloudOnboardingResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/cloud_onboarding"
	platformResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/platform"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider = &CortexCloudProvider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New(version string) func() provider.Provider {
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
				Description: "TODO",
			},
			"cortex_cloud_api_url": schema.StringAttribute{
				Optional: true,
				Description: fmt.Sprintf("The API URL of your Cortex Cloud tenant. "+
					"You can retrieve this from the Cortex Cloud console by "+
					"navigating to Settings > Configurations > Integrations > "+
					"API Keys and clicking the \"Copy API URL\" button. Can "+
					"also be configured using the `%s` environment "+
					"variable.", client.CORTEXCLOUD_API_URL_ENV_VAR),
			},
			"cortex_cloud_api_port": schema.Int32Attribute{
				Optional:    true,
				Description: "TODO",
			},
			"cortex_cloud_api_key": schema.StringAttribute{
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
			"cortex_cloud_api_key_id": schema.Int32Attribute{
				Optional:  true,
				Sensitive: true,
				Description: "The ID of the API key provided in the \"api_key\" " +
					"argument. You can retrieve this from the Cortex Cloud console " +
					"by navigating to Settings > Configurations > Integrations > " +
					"API Keys. Can also be configured using the `CORTEX_API_KEY_ID` " +
					"environment variable.",
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
			"check_environment": schema.BoolAttribute{
				Optional:    true,
				Description: "TODO",
			},
		},
	}
}

func (p *CortexCloudProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		cloudOnboardingResources.NewCloudIntegrationTemplateResource,
		appSecResources.NewApplicationSecurityRuleResource,
		platformResources.NewAuthenticationSettingsResource,
		platformResources.NewAssetGroupResource,
	}
}

func (p *CortexCloudProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		cloudOnboardingDataSources.NewCloudIntegrationInstanceDataSource,
		platformDataSources.NewUserDataSource,
		platformDataSources.NewRoleDataSource,
		platformDataSources.NewGroupDataSource,
	}
}

func (p *CortexCloudProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	tflog.Debug(ctx, "Starting provider configuration")

	// Retrieve configuration values from provider block
	var providerConfig models.CortexCloudProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &providerConfig)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse config file
	(&providerConfig).ParseConfigFile(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse environment variables
	(&providerConfig).ParseEnvVars(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate provider configuration
	(&providerConfig).Validate(ctx, &resp.Diagnostics)

	var (
		clientConfig *client.Config
		err          error
		apiUrl       string
		apiKey       string
		apiKeyID     int
		sdkLogLevel  string
	)

	apiUrl = providerConfig.ApiUrl.ValueString()
	apiKey = providerConfig.ApiKey.ValueString()
	apiKeyID = int(providerConfig.ApiKeyId.ValueInt32())
	sdkLogLevel = providerConfig.SdkLogLevel.ValueString()
	tflog.Debug(ctx, fmt.Sprintf("api url = %s", apiUrl))

	// TODO: Check api key values against /api_keys/validate endpoint

	// Create SDK config from provider values
	clientConfig = client.NewConfig(
		apiUrl,
		apiKey,
		apiKeyID,
		providerConfig.CheckEnvironment.ValueBool(),
		client.WithApiPort(int(providerConfig.ApiPort.ValueInt32())),
		client.WithSkipVerifyCertificate(providerConfig.SkipSslVerify.ValueBool()),
		client.WithTimeout(int(providerConfig.RequestTimeout.ValueInt32())),
		//client.WithRetryMaxDelay(providerConfig.RetryMaxDelay),
		client.WithCrashStackDir(providerConfig.CrashStackDir.ValueString()),
		client.WithLogger(log.TflogAdapter{}),
		client.WithLogLevel(sdkLogLevel),
	)

	// Validate SDK client configuration
	if err = clientConfig.Validate(); err != nil {
		resp.Diagnostics.AddError("Cortex Cloud SDK Configuration Error", err.Error())
		return
	}

	// Initialize SDK clients
	clients := models.CortexCloudSDKClients{}

	appSecClient, err := appsec.NewClient(clientConfig)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	cloudOnboardingClient, err := cloudonboarding.NewClient(clientConfig)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	platformClient, err := platform.NewClient(clientConfig)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	tflog.Debug(ctx, "Cortex Cloud API client setup complete")

	// Attach SDK clients to model
	clients.AppSec = appSecClient
	clients.CloudOnboarding = cloudOnboardingClient
	clients.Platform = platformClient

	// Assign clients model pointer to ProviderData to allow resources and
	// data sources to access SDK functions
	resp.DataSourceData = &clients
	resp.ResourceData = &clients
}
