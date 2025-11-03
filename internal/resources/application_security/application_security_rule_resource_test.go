// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package application_security_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

var (
	// Unit Tests

	AppSecRule1Name        = "test-rule"
	AppSecRule1Description = "test description"
	AppSecRule1Category    = enums.IacCategoryCompute.String()
	AppSecRule1SubCategory = enums.IacSubCategoryComputeOverprovisioned.String()
	AppSecRule1Scanner     = enums.ScannerIAC.String()
	AppSecRule1Severity    = enums.SeverityInfo.String()
	AppSecRule1Labels      = []string{
		"label1",
		"label2",
	}
	AppSecRule1Framework1Name                   = enums.FrameworkNameTerraform.String()
	AppSecRule1Framework1Definition             = "scope:\n  provider: aws\ndefinition:\n  or:\n    - cond_type: attribute\n      resource_types:\n        - aws_instance\n      attribute: instance_type\n      operator: equals\n      value: t2.micro\n"
	AppSecRule1Framework1DefinitionLink         = "http://docs.com/framework"
	AppSecRule1Framework1RemediationDescription = "fix it"

	AppSecUnitTestConfigTmpl = `provider "cortexcloud" {
	cortex_cloud_api_url = %s
	cortex_cloud_api_port = 443
	cortex_cloud_api_key = "test"
	cortex_cloud_api_key_id = 123
}
resource "cortexcloud_application_security_rule" "test" {
	name     = %s
	description = %s
	severity = %s
	scanner  = %s
	frameworks = [
		{
			name = %s
			definition = %s
			definition_link = %s
			remediation_description = %s
		}
	]
	category = %s
	sub_category = %s
	labels   = %s
}`

	AppSecUnitTestCreateOrCloneResponseTmpl = `{
	"id": "test-rule-id",
	"name": %s,
	"category": %s,
	"cloudProvider": "aws",
	"createdAt": {
		"value": "2025-08-26T00:00:00.000Z"
	},
	"description": %s,
	"detectionMethod": "some-method",
	"docLink": "http://docs.com",
	"domain": "test-domain",
	"findingCategory": "test-finding-category",
	"findingDocs": "http://docs.com/finding",
	"findingTypeId": 123,
	"findingTypeName": "test-finding",
	"frameworks": [{
		"name": %s,
		"definition": %s,
		"definitionLink": %s,
		"remediationDescription": %s
	}],
	"isCustom": true,
	"isEnabled": true,
	"labels": %s,
	"mitreTactics": ["tactic1"],
	"mitreTechniques": ["technique1"],
	"owner": "test-owner",
	"scanner": %s,
	"severity": %s,
	"source": "custom",
	"subCategory": %s,
	"updatedAt": {
		"value": "2025-08-26T00:00:00.000Z"
	}
}`

	AppSecUnitTestGetResponseTmpl = `{
	"id": "test-rule-id",
	"name": %s,
	"category": %s,
	"cloudProvider": "aws",
	"createdAt": {
		"value": "2025-08-26T00:00:00.000Z"
	},
	"description": %s,
	"detectionMethod": "some-method",
	"docLink": "http://docs.com",
	"domain": "test-domain",
	"findingCategory": "test-finding-category",
	"findingDocs": "http://docs.com/finding",
	"findingTypeId": 123,
	"findingTypeName": "test-finding",
	"frameworks": [{
		"name": %s,
		"definition": %s,
		"definitionLink": %s,
		"remediationDescription": %s
	}],
	"isCustom": true,
	"isEnabled": true,
	"labels": %s,
	"mitreTactics": ["tactic1"],
	"mitreTechniques": ["technique1"],
	"owner": "test-owner",
	"scanner": %s,
	"severity": %s,
	"source": "custom",
	"subCategory": %s,
	"updatedAt": {
		"value": "2025-08-26T00:00:00.000Z"
	}
}`
)

// AppSecRuleLabelsHCL returns the provided labels as a HCL string.
func AppSecRuleLabelsHCL(labels []string) string {
	return fmt.Sprintf(`["%s"]`, strings.Join(labels, "\", \""))
}

func TestUnitApplicationSecurityRuleResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if strings.HasSuffix(r.URL.String(), "/validate") { // validate
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{ "isValid": true }`)
				return
			}
			if strings.HasSuffix(r.URL.String(), "/rules") { // CreateOrClone
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(
					w,
					AppSecUnitTestCreateOrCloneResponseTmpl,
					strconv.Quote(AppSecRule1Name),
					strconv.Quote(AppSecRule1Category),
					strconv.Quote(AppSecRule1Description),
					strconv.Quote(AppSecRule1Framework1Name),
					strconv.Quote(AppSecRule1Framework1Definition),
					strconv.Quote(AppSecRule1Framework1DefinitionLink),
					strconv.Quote(AppSecRule1Framework1RemediationDescription),
					AppSecRuleLabelsHCL(AppSecRule1Labels),
					strconv.Quote(AppSecRule1Scanner),
					strconv.Quote(AppSecRule1Severity),
					strconv.Quote(AppSecRule1SubCategory),
				)
				return
			}
		}

		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/rules/") && !strings.HasSuffix(r.URL.Path, "rule-labels") { // Get
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(
				w,
				AppSecUnitTestGetResponseTmpl,
				strconv.Quote(AppSecRule1Name),
				strconv.Quote(AppSecRule1Category),
				strconv.Quote(AppSecRule1Description),
				strconv.Quote(AppSecRule1Framework1Name),
				strconv.Quote(AppSecRule1Framework1Definition),
				strconv.Quote(AppSecRule1Framework1DefinitionLink),
				strconv.Quote(AppSecRule1Framework1RemediationDescription),
				AppSecRuleLabelsHCL(AppSecRule1Labels),
				strconv.Quote(AppSecRule1Scanner),
				strconv.Quote(AppSecRule1Severity),
				strconv.Quote(AppSecRule1SubCategory),
			)
			return
		}

		if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, fmt.Sprintf("/rules/%s", "test-rule-id")) { // Delete
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Not Found: %s %s", r.Method, r.URL.Path)
	}))

	defer server.Close()

	testConfig := fmt.Sprintf(
		AppSecUnitTestConfigTmpl,
		strconv.Quote(server.URL),
		strconv.Quote(AppSecRule1Name),
		strconv.Quote(AppSecRule1Description),
		strconv.Quote(AppSecRule1Severity),
		strconv.Quote(AppSecRule1Scanner),
		strconv.Quote(AppSecRule1Framework1Name),
		strconv.Quote(AppSecRule1Framework1Definition),
		strconv.Quote(AppSecRule1Framework1DefinitionLink),
		strconv.Quote(AppSecRule1Framework1RemediationDescription),
		strconv.Quote(AppSecRule1Category),
		strconv.Quote(AppSecRule1SubCategory),
		AppSecRuleLabelsHCL(AppSecRule1Labels),
	)

	//fmt.Println(testConfig)

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: testConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "id", "test-rule-id"),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "name", AppSecRule1Name),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "category", AppSecRule1Category),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "scanner", AppSecRule1Scanner),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "severity", AppSecRule1Severity),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "labels.#", fmt.Sprintf("%d", len(AppSecRule1Labels))),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "frameworks.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "frameworks.0.name", AppSecRule1Framework1Name),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "frameworks.0.definition", AppSecRule1Framework1Definition),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "cloud_provider", "aws"),
				),
			},
		},
	})
}
