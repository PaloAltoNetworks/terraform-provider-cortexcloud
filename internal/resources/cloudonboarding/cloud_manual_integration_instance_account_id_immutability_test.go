// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"strings"
	"testing"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The API contract fixes manual_details.account_id at creation. It says so
// twice: once on the member itself -- "account_id cannot be changed, provide it
// exactly as it was at creation" -- and again in the note listing the three
// fields an edit must carry unchanged, "scope, scan_mode, and
// manual_details.account_id".
//
// The tests below cover the rule stated there. They are written against
// assertImmutableFieldsUnchanged rather than through a live edit because the
// point is to refuse the plan before any request is sent: the edit endpoint
// applies a partial update and answers 200 whether or not it honoured the
// account_id it was given, so a change that reaches the platform is reported as
// applied and never shows up as a difference again.

// withManualDetailAccountID returns a copy of the model whose
// manual_details.account_id holds the supplied value.
func withManualDetailAccountID(t *testing.T, model models.CloudManualIntegrationInstanceModel, accountID attr.Value) models.CloudManualIntegrationInstanceModel {
	t.Helper()

	attributes := map[string]attr.Value{}
	for name, value := range model.ManualDetails.Attributes() {
		attributes[name] = value
	}
	attributes["account_id"] = accountID

	details, diags := types.ObjectValue(models.ManualDetailsWriteAttributeTypes(), attributes)
	if diags.HasError() {
		t.Fatalf("failed to rebuild manual_details: %v", diags.Errors())
	}
	model.ManualDetails = details

	return model
}

// TestManualInstanceAccountIDCannotBeChanged proves an update that moves
// manual_details.account_id to a different account is refused.
//
// Without this the change is silently lost. account_id carries no
// RequiresReplace, so Terraform plans an ordinary in-place update; the edit
// endpoint accepts the request and answers 200; and the connector goes on
// pointing at the account it was created against while Terraform records the
// new one. The practitioner is then told the connector onboards an account it
// does not onboard, and no later plan disagrees.
func TestManualInstanceAccountIDCannotBeChanged(t *testing.T) {
	t.Parallel()

	_, attributeTypes := manualResourceSchema(t)

	state := manualTestModel(t, attributeTypes, true)
	plan := withManualDetailAccountID(t, manualTestModel(t, attributeTypes, true), types.StringValue("111122223333"))

	var diagnostics diag.Diagnostics
	assertImmutableFieldsUnchanged(&diagnostics, state, plan)

	if !diagnostics.HasError() {
		t.Fatal("changing manual_details.account_id was accepted. The contract fixes this member at creation, and the edit endpoint answers 200 without honouring a change, so an accepted plan writes an account into state that the connector does not onboard")
	}

	detail := diagnostics.Errors()[0].Detail()
	for _, want := range []string{"account_id", "782785052462", "111122223333"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the diagnostic does not mention %q, so it does not tell the practitioner which value to restore: %s", want, detail)
		}
	}
}

// TestManualInstanceAccountIDUnchangedPlansCleanly is the control for the test
// above: it fails if the guard refuses every update rather than the one that
// changes the account.
func TestManualInstanceAccountIDUnchangedPlansCleanly(t *testing.T) {
	t.Parallel()

	_, attributeTypes := manualResourceSchema(t)

	state := manualTestModel(t, attributeTypes, true)
	plan := manualTestModel(t, attributeTypes, true)

	var diagnostics diag.Diagnostics
	assertImmutableFieldsUnchanged(&diagnostics, state, plan)

	if diagnostics.HasError() {
		t.Errorf("an update that leaves manual_details.account_id alone was refused: %v", diagnostics.Errors())
	}
}

// TestManualInstanceAccountIDGuardIgnoresNullManualDetails proves the guard
// does not fire on the first plan after an import.
//
// Import leaves manual_details null -- the platform never reports back several
// of its members, so the importer writes none of them -- and the practitioner
// must then declare the block. Reading that null-to-value move as a change of
// account would make every imported connector impossible to update, which is
// the same trap TestManualInstanceImportedStateDoesNotTripTheClearGuard exists
// to rule out for the neighbouring guard.
func TestManualInstanceAccountIDGuardIgnoresNullManualDetails(t *testing.T) {
	t.Parallel()

	_, attributeTypes := manualResourceSchema(t)

	imported := manualTestModel(t, attributeTypes, true)
	imported.ManualDetails = types.ObjectNull(models.ManualDetailsWriteAttributeTypes())

	plan := manualTestModel(t, attributeTypes, true)

	var diagnostics diag.Diagnostics
	assertImmutableFieldsUnchanged(&diagnostics, imported, plan)

	if diagnostics.HasError() {
		t.Errorf("the first plan after an import was refused as changing the account: %v. Import leaves manual_details null by design, so there is no prior account to compare against", diagnostics.Errors())
	}
}

// TestManualInstanceAccountIDGuardIgnoresUnsetPriorAccount proves the guard
// stays quiet when the prior state holds no account at all.
//
// account_id is optional and only AWS uses it, so a connector for another cloud
// carries a manual_details block in which the member is null. Comparing a null
// prior against a configured value would refuse an update that changes nothing
// the contract protects.
func TestManualInstanceAccountIDGuardIgnoresUnsetPriorAccount(t *testing.T) {
	t.Parallel()

	_, attributeTypes := manualResourceSchema(t)

	state := withManualDetailAccountID(t, manualTestModel(t, attributeTypes, true), types.StringNull())
	plan := manualTestModel(t, attributeTypes, true)

	var diagnostics diag.Diagnostics
	assertImmutableFieldsUnchanged(&diagnostics, state, plan)

	if diagnostics.HasError() {
		t.Errorf("an update was refused although the prior state held no account: %v", diagnostics.Errors())
	}
}
