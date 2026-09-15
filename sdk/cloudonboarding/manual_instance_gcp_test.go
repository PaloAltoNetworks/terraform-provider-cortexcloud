// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// GCP manual onboarding
//
// Provenance of the field names asserted below, because it decides how much
// they can be trusted:
//
// The onboarding contract instructs callers to build a create body from the
// object the identifiers endpoint hands back — "Pass the manual_details object
// returned by the Get Manual Connector Identifiers call". That endpoint
// therefore publishes the write shape, per provider, as a template of empty
// strings. 18 captured GCP calls to it, spanning all three scopes, both audit
// settings and several capability combinations, agree on exactly seven keys.
// Those captures are checked in at testdata/gcp_manual_details_offers.json and
// drive the coverage gate below.
//
// What is NOT proven, and is deliberately not asserted anywhere here:
//
//   - No GCP create or edit has ever been accepted. The single captured GCP
//     create sent real values and came back HTTP 500, so "the API accepts these
//     names" rests on the contract's instruction, not on a 200.
//   - No GCP connector has ever been read back. Every captured
//     get_edit_instance_details reply is AWS or Azure, so the GCP read shape is
//     inferred from the offer rather than observed.
//
// Both limitations are recorded in the type comments as well.
// ----------------------------------------------------------------------------

// gcpOfferRecord mirrors one captured get_manual_connector_identifiers reply
// together with the request conditions that produced it.
type gcpOfferRecord struct {
	Source           string            `json:"source"`
	Scope            string            `json:"scope"`
	ScanMode         string            `json:"scan_mode"`
	AuditLogsEnabled bool              `json:"audit_logs_enabled"`
	CapabilitiesOn   []string          `json:"capabilities_enabled"`
	ManualDetails    map[string]string `json:"manual_details"`
}

func loadGCPOffers(t *testing.T) []gcpOfferRecord {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "gcp_manual_details_offers.json"))
	require.NoError(t, err, "captured GCP offers must be readable")

	var records []gcpOfferRecord
	require.NoError(t, json.Unmarshal(raw, &records))
	require.NotEmpty(t, records, "fixture must contain captured offers")

	return records
}

// The gate. Every key the API has ever offered for GCP must exist on the write
// type, and unmarshalling an offer must not silently drop any of them.
//
// It is driven by the captured payloads rather than by a list retyped from the
// struct: a gate written from the struct would only prove the struct equals
// itself. Deleting a GCP field from ManualDetails makes this fail.
func TestManualDetailsCoversEveryCapturedGCPOfferKey(t *testing.T) {
	records := loadGCPOffers(t)
	modelled := jsonKeys(t, types.ManualDetails{})

	// Collect each key with one witness capture, so a failure names the file
	// that proves the key is real.
	witness := map[string]string{}
	for _, rec := range records {
		for key := range rec.ManualDetails {
			if _, seen := witness[key]; !seen {
				witness[key] = rec.Source
			}
		}
	}
	require.NotEmpty(t, witness)

	for key, source := range witness {
		require.True(t, modelled[key],
			"manual_details key %q is offered by the API but missing from ManualDetails; witness: %s",
			key, source)
	}
}

// Unmarshalling every captured offer into ManualDetails must round-trip back to
// the same set of keys. This catches a field that is declared but tagged with
// the wrong JSON name, which the key check above cannot see.
func TestManualDetailsRoundTripsEveryCapturedGCPOffer(t *testing.T) {
	for _, rec := range loadGCPOffers(t) {
		t.Run(rec.Source, func(t *testing.T) {
			// Give every offered key a distinct, recognisable value so a field
			// mapped to the wrong tag surfaces as a mismatch rather than as two
			// coincidentally equal empty strings.
			populated := map[string]string{}
			for key := range rec.ManualDetails {
				populated[key] = "value-for-" + key
			}
			body, err := json.Marshal(populated)
			require.NoError(t, err)

			var details types.ManualDetails
			require.NoError(t, json.Unmarshal(body, &details))

			out, err := json.Marshal(details)
			require.NoError(t, err)

			var got map[string]string
			require.NoError(t, json.Unmarshal(out, &got))

			require.Equal(t, populated, got,
				"every offered key must survive an unmarshal/marshal round trip")
		})
	}
}

// omitempty on the GCP members is what keeps an AWS or Azure request free of
// empty GCP keys. Asserting it directly stops a later edit from turning every
// request into one carrying six blank GCP fields.
func TestManualDetailsOmitsUnsetGCPFields(t *testing.T) {
	awsOnly := types.ManualDetails{
		AccountID: strPtr("782785052462"),
		RoleARN:   strPtr("arn:aws:iam::782785052462:role/CortexPlatformRole"),
	}

	body, err := json.Marshal(awsOnly)
	require.NoError(t, err)

	require.JSONEq(t,
		`{"account_id":"782785052462","role_arn":"arn:aws:iam::782785052462:role/CortexPlatformRole"}`,
		string(body),
		"unset GCP fields must not appear in a non-GCP request")
}

// Table-driven marshal and unmarshal of the GCP write shape, one case per
// captured tenant configuration. The expected JSON in each case is the exact
// key set the API offered for that configuration.
func TestManualDetailsGCPMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		details types.ManualDetails
		want    string
	}{
		{
			// evidence: stage1/raw/C00-ident-GCP-ACCOUNT-MANAGED-capsEmpty-auditFalse.json
			// The three keys offered for every GCP configuration.
			name: "account scope, audit off, no capabilities",
			details: types.ManualDetails{
				OrganizationID:      strPtr("9996114313562"),
				AccountID:           strPtr("tf-test-probe11-project"),
				ServiceAccountEmail: strPtr("svc@tf-test-probe11-project.iam.gserviceaccount.com"),
			},
			want: `{
				"organization_id": "9996114313562",
				"account_id": "tf-test-probe11-project",
				"service_account_email": "svc@tf-test-probe11-project.iam.gserviceaccount.com"
			}`,
		},
		{
			// evidence: stage1/raw/C01-ident-GCP-ACCOUNT-MANAGED-capsEmpty-auditTrue.json
			// Enabling audit logs adds exactly the two audit keys.
			name: "account scope, audit on",
			details: types.ManualDetails{
				OrganizationID:            strPtr("9996114313562"),
				AccountID:                 strPtr("tf-test-probe11-project"),
				ServiceAccountEmail:       strPtr("svc@tf-test-probe11-project.iam.gserviceaccount.com"),
				AuditServiceAccountEmail:  strPtr("audit@tf-test-probe11-project.iam.gserviceaccount.com"),
				AuditPubSubSubscriptionID: strPtr("projects/tf-test-probe11-project/subscriptions/probe11-sub"),
			},
			want: `{
				"organization_id": "9996114313562",
				"account_id": "tf-test-probe11-project",
				"service_account_email": "svc@tf-test-probe11-project.iam.gserviceaccount.com",
				"audit_service_account_email": "audit@tf-test-probe11-project.iam.gserviceaccount.com",
				"audit_pubsub_subscription_id": "projects/tf-test-probe11-project/subscriptions/probe11-sub"
			}`,
		},
		{
			// evidence: stage1/raw/C11-ident-GCP-ACCOUNT_GROUP-MANAGED-capsEmpty-auditFalse.json
			// account_group is offered only for ACCOUNT_GROUP scope, and only
			// inside manual_details — it is a different field from the
			// account_group on account_details.
			name: "account group scope adds account_group",
			details: types.ManualDetails{
				OrganizationID:      strPtr("9996114313562"),
				AccountID:           strPtr("tf-test-probe11-project"),
				ServiceAccountEmail: strPtr("svc@tf-test-probe11-project.iam.gserviceaccount.com"),
				AccountGroup:        strPtr("folders/123456789"),
			},
			want: `{
				"organization_id": "9996114313562",
				"account_id": "tf-test-probe11-project",
				"service_account_email": "svc@tf-test-probe11-project.iam.gserviceaccount.com",
				"account_group": "folders/123456789"
			}`,
		},
		{
			// evidence: probe-11-contract-conformance/phase2-creates.json
			// The widest GCP body we ever sent. It was rejected with HTTP 500,
			// so this asserts the serialisation only, not acceptance.
			name: "all six non-group keys",
			details: types.ManualDetails{
				OrganizationID:                    strPtr("9996114313562"),
				AccountID:                         strPtr("tf-test-probe11-project"),
				ServiceAccountEmail:               strPtr("probe11-service_account@tf-test-probe11-project.iam.gserviceaccount.com"),
				OutpostScannerServiceAccountEmail: strPtr("probe11-outpost_scanner_service_account@tf-test-probe11-project.iam.gserviceaccount.com"),
				AuditServiceAccountEmail:          strPtr("probe11-audit_service_account@tf-test-probe11-project.iam.gserviceaccount.com"),
				AuditPubSubSubscriptionID:         strPtr("projects/tf-test-probe11-project/subscriptions/probe11-sub"),
			},
			want: `{
				"organization_id": "9996114313562",
				"account_id": "tf-test-probe11-project",
				"service_account_email": "probe11-service_account@tf-test-probe11-project.iam.gserviceaccount.com",
				"outpost_scanner_service_account_email": "probe11-outpost_scanner_service_account@tf-test-probe11-project.iam.gserviceaccount.com",
				"audit_service_account_email": "probe11-audit_service_account@tf-test-probe11-project.iam.gserviceaccount.com",
				"audit_pubsub_subscription_id": "projects/tf-test-probe11-project/subscriptions/probe11-sub"
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.details)
			require.NoError(t, err)
			require.JSONEq(t, tt.want, string(body))

			var back types.ManualDetails
			require.NoError(t, json.Unmarshal([]byte(tt.want), &back))
			require.Equal(t, tt.details, back, "unmarshal must invert marshal")
		})
	}
}

// The read type must be able to express a GCP connector. No GCP read-back has
// ever been captured, so this asserts decodability, not observed traffic: the
// payload is the offer shape carrying plausible values.
func TestManualDetailsReadDecodesGCPFields(t *testing.T) {
	const body = `{
		"organization_id": "9996114313562",
		"account_id": "tf-test-probe11-project",
		"service_account_email": "svc@tf-test-probe11-project.iam.gserviceaccount.com",
		"outpost_scanner_service_account_email": "scanner@tf-test-probe11-project.iam.gserviceaccount.com",
		"audit_service_account_email": "audit@tf-test-probe11-project.iam.gserviceaccount.com",
		"audit_pubsub_subscription_id": "projects/tf-test-probe11-project/subscriptions/probe11-sub",
		"account_group": "folders/123456789"
	}`

	var got types.ManualDetailsRead
	require.NoError(t, json.Unmarshal([]byte(body), &got))

	require.Equal(t, "svc@tf-test-probe11-project.iam.gserviceaccount.com", derefStr(t, got.ServiceAccountEmail))
	require.Equal(t, "scanner@tf-test-probe11-project.iam.gserviceaccount.com", derefStr(t, got.OutpostScannerServiceAccountEmail))
	require.Equal(t, "audit@tf-test-probe11-project.iam.gserviceaccount.com", derefStr(t, got.AuditServiceAccountEmail))
	require.Equal(t, "projects/tf-test-probe11-project/subscriptions/probe11-sub", derefStr(t, got.AuditPubSubSubscriptionID))
	require.Equal(t, "folders/123456789", derefStr(t, got.AccountGroup))

	// Re-marshalling must reproduce the input: a field decoded into the wrong
	// tag would show up here even though the assertions above passed.
	out, err := json.Marshal(got)
	require.NoError(t, err)
	require.JSONEq(t, body, string(out))
}

// The contract documents gcp_workspace as carrying customer_ids alongside
// enabled. Only enabled has ever appeared in a reply, so customer_ids is
// modelled from the contract and must decode when it does arrive.
func TestInstanceGCPWorkspaceReadDecodesCustomerIDs(t *testing.T) {
	t.Run("enabled only, as captured", func(t *testing.T) {
		var got types.InstanceGCPWorkspaceRead
		require.NoError(t, json.Unmarshal([]byte(`{"enabled": false}`), &got))
		require.NotNil(t, got.Enabled)
		require.False(t, *got.Enabled)
		require.Nil(t, got.CustomerIDs, "customer_ids must stay absent when not sent")
	})

	t.Run("customer_ids as documented by the contract", func(t *testing.T) {
		var got types.InstanceGCPWorkspaceRead
		require.NoError(t, json.Unmarshal(
			[]byte(`{"enabled": true, "customer_ids": ["C01abcde", "C02fghij"]}`), &got))
		require.Equal(t, []string{"C01abcde", "C02fghij"}, got.CustomerIDs)
	})
}

// The two _mail-suffixed service-account keys belong to the identifiers object,
// a sibling of manual_details, and have never appeared inside manual_details
// itself. Modelling them here would invent fields, so this asserts their
// absence on both types and will fail if someone "aligns" the spellings.
func TestManualDetailsExcludesIdentifierMailKeys(t *testing.T) {
	write := jsonKeys(t, types.ManualDetails{})
	read := jsonKeys(t, types.ManualDetailsRead{})

	for _, key := range []string{
		"outpost_service_account_mail",
		"saas_collector_service_account_mail",
		"dspm_scanner_service_account_email",
		"registry_scanner_service_account_email",
		"serverless_scanner_service_account_email",
	} {
		require.False(t, write[key], "%s belongs to identifiers, not manual_details", key)
		require.False(t, read[key], "%s belongs to identifiers, not manual_details", key)
	}
}

// Guards the naming of the two keys most easily mistyped: the audit and
// scanner service accounts end in _email, not _mail.
func TestManualDetailsGCPTagsUseEmailSuffix(t *testing.T) {
	write := jsonKeys(t, types.ManualDetails{})

	for _, key := range []string{
		"service_account_email",
		"audit_service_account_email",
		"outpost_scanner_service_account_email",
	} {
		require.True(t, write[key], "%s must be spelled with the _email suffix", key)
		require.False(t, write[strings.TrimSuffix(key, "_email")+"_mail"],
			"the _mail spelling of %s must not be modelled", key)
	}
}

// derefStr fails the test rather than panicking when an expected field decoded
// as absent.
func derefStr(t *testing.T, p *string) string {
	t.Helper()
	require.NotNil(t, p)
	return *p
}
