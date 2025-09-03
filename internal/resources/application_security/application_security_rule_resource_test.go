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

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/acceptance"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

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
					acceptance.AppSecUnitTestCreateOrCloneResponseTmpl,
					strconv.Quote(acceptance.AppSecRule1Name),
					strconv.Quote(acceptance.AppSecRule1Category),
					strconv.Quote(acceptance.AppSecRule1Description),
					strconv.Quote(acceptance.AppSecRule1Framework1Name),
					strconv.Quote(acceptance.AppSecRule1Framework1Definition),
					strconv.Quote(acceptance.AppSecRule1Framework1DefinitionLink),
					strconv.Quote(acceptance.AppSecRule1Framework1RemediationDescription),
					acceptance.AppSecRuleLabelsHCL(acceptance.AppSecRule1Labels),
					strconv.Quote(acceptance.AppSecRule1Scanner),
					strconv.Quote(acceptance.AppSecRule1Severity),
					strconv.Quote(acceptance.AppSecRule1SubCategory),
				)
				return
			}
		}

		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/rules/") && !strings.HasSuffix(r.URL.Path, "rule-labels") { // Get
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(
				w,
				acceptance.AppSecUnitTestGetResponseTmpl,
				strconv.Quote(acceptance.AppSecRule1Name),
				strconv.Quote(acceptance.AppSecRule1Category),
				strconv.Quote(acceptance.AppSecRule1Description),
				strconv.Quote(acceptance.AppSecRule1Framework1Name),
				strconv.Quote(acceptance.AppSecRule1Framework1Definition),
				strconv.Quote(acceptance.AppSecRule1Framework1DefinitionLink),
				strconv.Quote(acceptance.AppSecRule1Framework1RemediationDescription),
				acceptance.AppSecRuleLabelsHCL(acceptance.AppSecRule1Labels),
				strconv.Quote(acceptance.AppSecRule1Scanner),
				strconv.Quote(acceptance.AppSecRule1Severity),
				strconv.Quote(acceptance.AppSecRule1SubCategory),
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
		acceptance.AppSecUnitTestConfigTmpl,
		strconv.Quote(server.URL),
		strconv.Quote(acceptance.AppSecRule1Name),
		strconv.Quote(acceptance.AppSecRule1Description),
		strconv.Quote(acceptance.AppSecRule1Severity),
		strconv.Quote(acceptance.AppSecRule1Scanner),
		strconv.Quote(acceptance.AppSecRule1Framework1Name),
		strconv.Quote(acceptance.AppSecRule1Framework1Definition),
		strconv.Quote(acceptance.AppSecRule1Framework1DefinitionLink),
		strconv.Quote(acceptance.AppSecRule1Framework1RemediationDescription),
		strconv.Quote(acceptance.AppSecRule1Category),
		strconv.Quote(acceptance.AppSecRule1SubCategory),
		acceptance.AppSecRuleLabelsHCL(acceptance.AppSecRule1Labels),
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
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "name", acceptance.AppSecRule1Name),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "category", acceptance.AppSecRule1Category),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "scanner", acceptance.AppSecRule1Scanner),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "severity", acceptance.AppSecRule1Severity),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "labels.#", fmt.Sprintf("%d", len(acceptance.AppSecRule1Labels))),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "frameworks.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "frameworks.0.name", acceptance.AppSecRule1Framework1Name),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "frameworks.0.definition", acceptance.AppSecRule1Framework1Definition),
					resource.TestCheckResourceAttr("cortexcloud_application_security_rule.test", "cloud_provider", "aws"),
				),
			},
		},
	})
}
