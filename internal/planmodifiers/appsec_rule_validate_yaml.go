// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

//import (
//	"context"
//	"fmt"
//	"gopkg.in/yaml.v3"
//
//	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/api"
//	appSecApi "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/api/application_security"
//	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/application_security"
//
//	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
//	"github.com/hashicorp/terraform-plugin-framework/types"
//	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
//	//"github.com/hashicorp/terraform-plugin-framework/path"
//)
//
////var (
////	_ validator.String = NullIfAlsoSetPlanModifier{}
////	_ validator.Bool   = NullIfAlsoSetPlanModifier{}
////)
//
//func ValidateAppSecRuleYaml(client *api.CortexCloudAPIClient) planmodifier.String {
//	return &validateAppSecRuleYaml{
//        Client: client,
//    }
//}
//
//type validateAppSecRuleYaml struct {
//    Client *api.CortexCloudAPIClient
//}
//
//func (m *validateAppSecRuleYaml) Description(ctx context.Context) string {
//	return m.MarkdownDescription(ctx)
//}
//
//func (m *validateAppSecRuleYaml) MarkdownDescription(context.Context) string {
//	return ""
//}
//
//func (m *validateAppSecRuleYaml) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
//
//
//    var configYamlValue basetypes.StringValue
//    resp.Diagnostics.Append(req.Config.GetAttribute(ctx, req.Path, &configYamlValue)...)
//    if resp.Diagnostics.HasError() {
//        return
//    }
//
//    configYaml := configYamlValue.ValueString()
//    unmarshalledYaml := appSecApi.ApplicationSecurityRuleYaml{}
//    err := yaml.Unmarshal([]byte(configYaml), &unmarshalledYaml)
//    if err != nil {
//        resp.Diagnostics.AddAttributeError(
//            req.Path,
//            "Value Conversion Error",
//            fmt.Sprintf("Failed to convert rule definition \"%s\": %s", configYaml, err.Error()),
//        )
//        return
//    }
//
//    marshalledDefinitionYaml, err := yaml.Marshal(&unmarshalledYaml)
//    if err != nil {
//        resp.Diagnostics.AddAttributeError(
//            req.Path,
//            "Value Conversion Error",
//            fmt.Sprintf("Failed to convert rule definition \"%s\": %s", configYaml, err.Error()),
//        )
//        return
//    }
//
//    resp.Diagnostics.Append(req.Plan.SetAttribute(ctx, req.Path, types.StringValue(string(marshalledDefinitionYaml)))...)
//
//    var plan models.ApplicationSecurityRuleModel
//    resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
//    if resp.Diagnostics.HasError() {
//        return
//    }
//
//    validationRequest := plan.ToValidateRequest(ctx, &resp.Diagnostics)
//    if resp.Diagnostics.HasError() {
//        return
//    }
//
//    validationResponse := appSecApi.Validate(ctx, &resp.Diagnostics, m.Client, validationRequest)
//    if resp.Diagnostics.HasError() {
//        return
//    }
//
//    if (validationResponse.IsValid == nil || *validationResponse.IsValid == false) {
//        resp.Diagnostics.AddAttributeError(
//            req.Path,
//            "Validation Error",
//            "Rule definition failed API validation check",
//        )
//    }
//}
