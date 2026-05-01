// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudsec"
	"github.com/PaloAltoNetworks/cortex-cloud-go/compliance"
	"github.com/PaloAltoNetworks/cortex-cloud-go/cwp"
	"github.com/PaloAltoNetworks/cortex-cloud-go/log"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	"github.com/PaloAltoNetworks/cortex-cloud-go/vulnerability"

	appsecDataSources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/data_sources/appsec"
	cloudOnboardingDataSources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/data_sources/cloud_onboarding"
	cloudsecDataSources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/data_sources/cloudsec"
	complianceDataSources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/data_sources/compliance"
	cwpDataSources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/data_sources/cwp"
	platformDataSources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/data_sources/platform"
	vulnerabilityDataSources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/data_sources/vulnerability"
	cloudOnboardingEphemeralResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/ephemeral/cloud_onboarding"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	appsecResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/appsec"
	cloudOnboardingResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/cloudonboarding"
	cloudsecResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/cloudsec"
	complianceResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/compliance"
	cwpResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/cwp"
	platformResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/platform"
	vulnerabilityResources "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/vulnerability"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider                       = &CortexCloudProvider{}
	_ provider.ProviderWithEphemeralResources = &CortexCloudProvider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New(version string) func() provider.Provider {
	switch version {
	case "test":
		fmt.Printf("=======================================================\n" +
			"Provider execution started in TEST mode\n" +
			"=======================================================\n")
	case "dev":
		fmt.Printf("=======================================================\n" +
			"Provider execution started in DEV mode\n" +
			"=======================================================\n")
	default:
		tflog.Info(context.Background(), fmt.Sprintf("Cortex Cloud Terraform Provider (version %s)", version))
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
			"api_url": schema.StringAttribute{
				Optional: true,
				Description: fmt.Sprintf("The API URL of your Cortex Cloud tenant. "+
					"\n\n\tThis can be retrieved from the Cortex Cloud console by navigating to `Settings > Configurations`, selecting `API Keys` under the `Integrations` section, and clicking the `Copy API URL` button. "+
					"\n\n\tCan also be configured using the `%s` environment variable.",
					models.APIURLEnvVar),
			},
			"api_key": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: fmt.Sprintf("Your Cortex Cloud API key. "+
					"\n\n\tCreate a new API key in the Cortex Cloud console by navigating to `Settings > Configurations`, selecting `API Keys` under the `Integrations` section, and clicking the `New Key` button. "+
					"\n\n\tCan also be configured using the `%s` environment variable."+
					"\n\n>[!WARNING]\n>Once you reach the screen displaying your new API key, you will not be able to view this screen again after closing the window. Ensure that you copy the key value before closing the window.",
					models.APIKeyEnvVar),
			},
			"api_key_id": schema.Int32Attribute{
				Optional:  true,
				Sensitive: true,
				Description: fmt.Sprintf("Your Cortex Cloud API key. "+
					"\n\n\tFor existing API keys, this can be retrieved from the Cortex Cloud console by navigating to `Settings > Configurations`, selecting `API Keys` under the `Integrations` section, and finding the row associated with your API key. The key ID value will be in the `ID` column. "+
					"\n\n\tCan also be configured using the `%s` environment variable.",
					models.APIKeyIDEnvVar),
			},
			"api_key_type": schema.StringAttribute{
				Optional: true,
				Description: fmt.Sprintf("The type of your provided Cortex Cloud API key. "+
					"\n\n\tAdvanced API keys are hashed using a nonce, a random string, and a timestamp to prevent replay attacks. "+
					"\n\n\tPossible values are: `standard`, `advanced`"+
					"\n\n\tDefaults to `advanced`. "+
					"\n\n\tCan also be configured using the `%s` environment variable.\n",
					models.APIKeyTypeEnvVar),
			},
			"config_file": schema.StringAttribute{
				Optional:    true,
				Description: "The path to a JSON file containing the provider configuration values.\n",
			},
			"sdk_log_level": schema.StringAttribute{
				Optional: true,
				Description: fmt.Sprintf("The log level for the Cortex Cloud Go SDK. "+
					"\n\n\tAll communications between the provider and the Cortex Cloud API are handled by the Cortex Cloud Go SDK. Logs from the SDK will be included in the logging output of the provider. "+
					"\n\n\tPossible values are: `info`, `warn`, `error`, `debug` "+
					"\n\n\tDefaults to `info`. "+
					"\n\n\tCan also be configured using the `%s` environment variable."+
					"\n\n>[!NOTE]\n>SDK logs will only be visible in the provider logs if the [Terraform log level](https://developer.hashicorp.com/terraform/internals/debugging) is set to `DEBUG` or `TRACE`."+
					"\n\n>[!WARNING]\n>Setting this value to `debug` will cause the SDK to log all API requests and responses, which include sensitive values such as your API key.\n",
					models.SDKLogLevelEnvVar),
			},
			"skip_ssl_verify": schema.BoolAttribute{
				Optional: true,
				Description: fmt.Sprintf("Toggles SSL certificate verification for requests against the Cortex Cloud API."+
					"\n\n\tDefaults to `false`. "+
					"\n\n\tCan also be configured using the `%s` environment variable.\n",
					models.SkipSSLVerifyEnvVar),
			},
			"request_timeout": schema.Int32Attribute{
				Optional: true,
				Description: fmt.Sprintf("The amount of time (in seconds) the provider will wait for a response to for a given request to the Cortex Cloud API before timing out. "+
					"\n\n\tDefaults to `30`. "+
					"\n\n\tCan also be configured using the `%s` environment variable.\n",
					models.RequestTimeoutEnvVar),
			},
			"request_max_retries": schema.Int32Attribute{
				Optional: true,
				Description: fmt.Sprintf("The number of times the provider will retry a request to the Cortex Cloud API if it recieves a retryable HTTP response code (401, 429, 502, 503, or 504)."+
					"\n\n\tDefaults to `3`."+
					"\n\n\tCan also be configured using the `%s` environment variable.\n",
					models.RequestMaxRetriesEnvVar),
			},
			"request_max_retry_delay": schema.Int32Attribute{
				Optional: true,
				Description: fmt.Sprintf("The maximum amount of time (in seconds) the provider will wait before retrying a failed request to the Cortex Cloud API. "+
					"\n\n\tThe delay between retries is calculated using an exponential backoff to give the system enough time to recover, along with jitter (±25%% randomization) to prevent the thundering herd problem. The final calculated amount of seconds will be capped at this value."+
					"\n\n\tDefaults to `60`."+
					"\n\n\tCan also be configured using the `%s` environment variable.\n",
					models.RequestMaxRetryDelayEnvVar),
			},
			"crash_stack_dir": schema.StringAttribute{
				Optional: true,
				Description: fmt.Sprintf("The directory where text files containing the stack dump (also known as a stack trace) will be written whenever the provider encounters a runtime error or panics."+
					"\n\n\tIf an unhandled runtime error occurs during provider execution, a diagnostic message will be displayed that includes the path to a .txt file containing the full crash stack. We kindly encourage users to report any such occurances to the Cortex Cloud Terraform provider development team and include this file."+
					"\n\n\tDefaults to the value of the `TMPDIR` environment variable on Unix systems (or `/tmp` if `TMPDIR` is empty/not configured)."+
					"\n\n\tOn Windows systems, the default value will be interpreted as the first non-empty value in the following set of environment variables, in order of evaluation: `%%TMP%%`, `%%TEMP%%`, `%%USERPROFILE%%`. If none of these variables are set, the value will be set to the Windows directory (`C:\\Users\\<YourUsername>\\AppData\\Local\\Temp`)."+
					"\n\n\tCan also be configured using the `%s` environment variable.\n",
					models.CrashStackDirEnvVar),
			},
		},
	}
}

func (p *CortexCloudProvider) Resources(ctx context.Context) []func() resource.Resource {
	resources := []func() resource.Resource{}

	tflog.Debug(ctx, "Starting resource registration")

	tflog.Debug(ctx, "Registering Cloud Onboarding resources")
	resources = append(
		resources,
		cloudOnboardingResources.NewCloudIntegrationTemplateAwsResource,
		cloudOnboardingResources.NewCloudIntegrationTemplateAzureResource,
		cloudOnboardingResources.NewCloudIntegrationTemplateGcpResource,
		cloudOnboardingResources.NewOutpostTemplateResource,
	)

	tflog.Debug(ctx, "Registering CloudSec resources")
	resources = append(
		resources,
		cloudsecResources.NewCloudSecPolicyResource,
		cloudsecResources.NewCloudSecRuleResource,
	)

	tflog.Debug(ctx, "Registering Platform resources")
	resources = append(
		resources,
		platformResources.NewAuthenticationSettingsResource,
		platformResources.NewAssetGroupResource,
		platformResources.NewUserGroupResource,
		platformResources.NewUserResource,
		platformResources.NewScopeResource,
		platformResources.NewIamRoleResource,
		platformResources.NewNotificationForwardingConfigAgentAuditLogsResource,
		platformResources.NewNotificationForwardingConfigManagementAuditLogsResource,
		platformResources.NewNotificationForwardingConfigIssuesResource,
		platformResources.NewNotificationForwardingConfigCasesResource,
	)

	tflog.Debug(ctx, "Registering Compliance resources")
	resources = append(
		resources,
		complianceResources.NewControlResource,
		complianceResources.NewStandardResource,
		complianceResources.NewAssessmentProfileResource,
	)

	tflog.Debug(ctx, "Registering Vulnerability resources")
	resources = append(
		resources,
		vulnerabilityResources.NewPolicyResource,
	)

	tflog.Debug(ctx, "Registering AppSec resources")
	resources = append(
		resources,
		appsecResources.NewRuleResource,
		appsecResources.NewPolicyResource,
	)

	tflog.Debug(ctx, "Registering CWP Resources")
	resources = append(
		resources,
		cwpResources.NewPolicyResource,
	)

	tflog.Debug(ctx, "Resource registration complete")

	return resources
}

func (p *CortexCloudProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	datasources := []func() datasource.DataSource{}

	tflog.Debug(ctx, "Starting data source registration")

	tflog.Debug(ctx, "Registering Cloud Onboarding data sources")
	datasources = append(datasources,
		cloudOnboardingDataSources.NewCloudIntegrationInstanceDataSource,
		cloudOnboardingDataSources.NewCloudIntegrationInstancesDataSource,
		cloudOnboardingDataSources.NewOutpostDataSource,
		cloudOnboardingDataSources.NewOutpostsDataSource,
	)

	tflog.Debug(ctx, "Registering CloudSec data sources")
	datasources = append(datasources,
		cloudsecDataSources.NewCloudSecPolicyDataSource,
		cloudsecDataSources.NewCloudSecRuleDataSource,
		cloudsecDataSources.NewCloudSecRulesDataSource,
	)

	tflog.Debug(ctx, "Registering Platform data sources")
	datasources = append(datasources,
		platformDataSources.NewUserDataSource,
		platformDataSources.NewIamRoleDataSource,
		platformDataSources.NewGroupDataSource,
		platformDataSources.NewIamPermissionConfigDataSource,
	)

	tflog.Debug(ctx, "Registering Compliance data sources")
	datasources = append(datasources,
		complianceDataSources.NewControlDataSource,
		complianceDataSources.NewControlsDataSource,
		complianceDataSources.NewStandardDataSource,
		complianceDataSources.NewStandardsDataSource,
		complianceDataSources.NewAssessmentProfileDataSource,
		complianceDataSources.NewAssessmentProfilesDataSource,
	)

	tflog.Debug(ctx, "Registering Vulnerability data sources")
	datasources = append(datasources,
		vulnerabilityDataSources.NewPolicyDataSource,
		vulnerabilityDataSources.NewPoliciesDataSource,
	)

	tflog.Debug(ctx, "Registering AppSec data sources")
	datasources = append(datasources,
		appsecDataSources.NewRuleDataSource,
		appsecDataSources.NewRulesDataSource,
		appsecDataSources.NewPolicyDataSource,
		appsecDataSources.NewPoliciesDataSource,
		appsecDataSources.NewRuleLabelsDataSource,
	)

	tflog.Debug(ctx, "Registering CWP Data Sources")
	datasources = append(datasources,
		cwpDataSources.NewPolicyDataSource,
		cwpDataSources.NewPoliciesDataSource,
	)

	tflog.Debug(ctx, "Data Source registration complete")

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

func getProviderConfig(ctx context.Context, config tfsdk.Config, diagnostics *diag.Diagnostics, version string) *models.CortexCloudProviderModel {
	// Retrieve configuration values from provider block
	var providerConfig *models.CortexCloudProviderModel
	diagnostics.Append(config.Get(ctx, &providerConfig)...)
	if diagnostics.HasError() {
		return &models.CortexCloudProviderModel{}
	}

	// Parse config file
	providerConfig.ParseConfigFile(ctx, diagnostics)
	if diagnostics.HasError() {
		return &models.CortexCloudProviderModel{}
	}

	// Parse environment variables — skip in test mode so the mock server URL
	// set in the HCL config block is not overwritten by real credentials from
	// the environment.
	if version != "test" {
		providerConfig.ParseEnvVars(ctx, diagnostics)
		if diagnostics.HasError() {
			return &models.CortexCloudProviderModel{}
		}
	}

	// Validate provider configuration
	providerConfig.Validate(ctx, diagnostics)
	if diagnostics.HasError() {
		return &models.CortexCloudProviderModel{}
	}

	return providerConfig
}

func (p *CortexCloudProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	tflog.Debug(ctx, "Starting provider configuration")

	// Retrieve configuration values from provider block
	providerConfig := getProviderConfig(ctx, req.Config, &resp.Diagnostics, p.version)
	if resp.Diagnostics.HasError() {
		return
	}

	// Initialize SDK clients
	clients := models.CortexCloudSDKClients{}

	tflog.Debug(ctx, "Initializing platform client")
	platformClient, err := platform.NewClient(
		platform.WithCortexAPIURL(providerConfig.APIURL.ValueString()),
		platform.WithCortexAPIKey(providerConfig.APIKey.ValueString()),
		platform.WithCortexAPIKeyID(int(providerConfig.APIKeyID.ValueInt32())),
		platform.WithCortexAPIKeyType(providerConfig.APIKeyType.ValueString()),
		platform.WithSkipSSLVerify(providerConfig.SkipSSLVerify.ValueBool()),
		platform.WithTimeout(int(providerConfig.RequestTimeout.ValueInt32())),
		platform.WithMaxRetries(int(providerConfig.RequestMaxRetries.ValueInt32())),
		platform.WithRetryMaxDelay(int(providerConfig.RequestMaxRetryDelay.ValueInt32())),
		platform.WithCrashStackDir(providerConfig.CrashStackDir.ValueString()),
		platform.WithLogger(log.TflogAdapter{}),
		platform.WithLogLevel(providerConfig.SDKLogLevel.ValueString()),
	)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	tflog.Debug(ctx, "Initializing cloudonboarding client")
	cloudOnboardingClient, err := cloudonboarding.NewClient(
		platform.WithCortexAPIURL(providerConfig.APIURL.ValueString()),
		platform.WithCortexAPIKey(providerConfig.APIKey.ValueString()),
		platform.WithCortexAPIKeyID(int(providerConfig.APIKeyID.ValueInt32())),
		platform.WithCortexAPIKeyType(providerConfig.APIKeyType.ValueString()),
		platform.WithSkipSSLVerify(providerConfig.SkipSSLVerify.ValueBool()),
		platform.WithTimeout(int(providerConfig.RequestTimeout.ValueInt32())),
		platform.WithMaxRetries(int(providerConfig.RequestMaxRetries.ValueInt32())),
		platform.WithRetryMaxDelay(int(providerConfig.RequestMaxRetryDelay.ValueInt32())),
		platform.WithCrashStackDir(providerConfig.CrashStackDir.ValueString()),
		platform.WithLogger(log.TflogAdapter{}),
		platform.WithLogLevel(providerConfig.SDKLogLevel.ValueString()),
	)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	tflog.Debug(ctx, "Initializing cloudsec client")
	cloudSecClient, err := cloudsec.NewClient(
		platform.WithCortexAPIURL(providerConfig.APIURL.ValueString()),
		platform.WithCortexAPIKey(providerConfig.APIKey.ValueString()),
		platform.WithCortexAPIKeyID(int(providerConfig.APIKeyID.ValueInt32())),
		platform.WithCortexAPIKeyType(providerConfig.APIKeyType.ValueString()),
		platform.WithSkipSSLVerify(providerConfig.SkipSSLVerify.ValueBool()),
		platform.WithTimeout(int(providerConfig.RequestTimeout.ValueInt32())),
		platform.WithMaxRetries(int(providerConfig.RequestMaxRetries.ValueInt32())),
		platform.WithRetryMaxDelay(int(providerConfig.RequestMaxRetryDelay.ValueInt32())),
		platform.WithCrashStackDir(providerConfig.CrashStackDir.ValueString()),
		platform.WithLogger(log.TflogAdapter{}),
		platform.WithLogLevel(providerConfig.SDKLogLevel.ValueString()),
	)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	tflog.Debug(ctx, "Initializing appsec client")
	appsecClient, err := appsec.NewClient(
		appsec.WithCortexAPIURL(providerConfig.APIURL.ValueString()),
		appsec.WithCortexAPIKey(providerConfig.APIKey.ValueString()),
		appsec.WithCortexAPIKeyID(int(providerConfig.APIKeyID.ValueInt32())),
		appsec.WithCortexAPIKeyType(providerConfig.APIKeyType.ValueString()),
		appsec.WithSkipSSLVerify(providerConfig.SkipSSLVerify.ValueBool()),
		appsec.WithTimeout(int(providerConfig.RequestTimeout.ValueInt32())),
		appsec.WithMaxRetries(int(providerConfig.RequestMaxRetries.ValueInt32())),
		appsec.WithRetryMaxDelay(int(providerConfig.RequestMaxRetryDelay.ValueInt32())),
		appsec.WithCrashStackDir(providerConfig.CrashStackDir.ValueString()),
		appsec.WithLogger(log.TflogAdapter{}),
		appsec.WithLogLevel(providerConfig.SDKLogLevel.ValueString()),
	)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	tflog.Debug(ctx, "Initializing compliance client")
	complianceClient, err := compliance.NewClient(
		compliance.WithCortexAPIURL(providerConfig.APIURL.ValueString()),
		compliance.WithCortexAPIKey(providerConfig.APIKey.ValueString()),
		compliance.WithCortexAPIKeyID(int(providerConfig.APIKeyID.ValueInt32())),
		compliance.WithCortexAPIKeyType(providerConfig.APIKeyType.ValueString()),
		compliance.WithSkipSSLVerify(providerConfig.SkipSSLVerify.ValueBool()),
		compliance.WithTimeout(int(providerConfig.RequestTimeout.ValueInt32())),
		compliance.WithMaxRetries(int(providerConfig.RequestMaxRetries.ValueInt32())),
		compliance.WithRetryMaxDelay(int(providerConfig.RequestMaxRetryDelay.ValueInt32())),
		compliance.WithCrashStackDir(providerConfig.CrashStackDir.ValueString()),
		compliance.WithLogger(log.TflogAdapter{}),
		compliance.WithLogLevel(providerConfig.SDKLogLevel.ValueString()),
	)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	tflog.Debug(ctx, "Initializing vulnerability client")
	vulnerabilityClient, err := vulnerability.NewClient(
		vulnerability.WithCortexAPIURL(providerConfig.APIURL.ValueString()),
		vulnerability.WithCortexAPIKey(providerConfig.APIKey.ValueString()),
		vulnerability.WithCortexAPIKeyID(int(providerConfig.APIKeyID.ValueInt32())),
		vulnerability.WithCortexAPIKeyType(providerConfig.APIKeyType.ValueString()),
		vulnerability.WithSkipSSLVerify(providerConfig.SkipSSLVerify.ValueBool()),
		vulnerability.WithTimeout(int(providerConfig.RequestTimeout.ValueInt32())),
		vulnerability.WithMaxRetries(int(providerConfig.RequestMaxRetries.ValueInt32())),
		vulnerability.WithRetryMaxDelay(int(providerConfig.RequestMaxRetryDelay.ValueInt32())),
		vulnerability.WithCrashStackDir(providerConfig.CrashStackDir.ValueString()),
		vulnerability.WithLogger(log.TflogAdapter{}),
		vulnerability.WithLogLevel(providerConfig.SDKLogLevel.ValueString()),
	)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	tflog.Debug(ctx, "Cortex Cloud API client setup complete")

	tflog.Debug(ctx, "Initializing CWP client")
	cwpClient, err := cwp.NewClient(
		cwp.WithCortexAPIURL(providerConfig.APIURL.ValueString()),
		cwp.WithCortexAPIKey(providerConfig.APIKey.ValueString()),
		cwp.WithCortexAPIKeyID(int(providerConfig.APIKeyID.ValueInt32())),
		cwp.WithCortexAPIKeyType(providerConfig.APIKeyType.ValueString()),
		cwp.WithSkipSSLVerify(providerConfig.SkipSSLVerify.ValueBool()),
		cwp.WithTimeout(int(providerConfig.RequestTimeout.ValueInt32())),
		cwp.WithMaxRetries(int(providerConfig.RequestMaxRetries.ValueInt32())),
		cwp.WithRetryMaxDelay(int(providerConfig.RequestMaxRetryDelay.ValueInt32())),
		cwp.WithCrashStackDir(providerConfig.CrashStackDir.ValueString()),
		cwp.WithLogger(log.TflogAdapter{}),
		cwp.WithLogLevel(providerConfig.SDKLogLevel.ValueString()),
	)
	if err != nil {
		resp.Diagnostics.AddError("Cortex Cloud API Setup Error", err.Error())
		return
	}

	// Attach SDK clients to model
	clients.AppSec = appsecClient
	clients.CloudOnboarding = cloudOnboardingClient
	clients.CloudSec = cloudSecClient
	clients.Compliance = complianceClient
	clients.CWP = cwpClient
	clients.Platform = platformClient
	clients.Vulnerability = vulnerabilityClient

	// Assign clients model pointer to ProviderData to allow resources and
	// data sources to access SDK functions
	resp.DataSourceData = &clients
	resp.ResourceData = &clients
	resp.EphemeralResourceData = &clients
}
