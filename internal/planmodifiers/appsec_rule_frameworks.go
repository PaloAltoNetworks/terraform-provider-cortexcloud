// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

//import (
//	"context"
//
//	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
//	"github.com/hashicorp/terraform-plugin-framework/path"
//	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
//	"github.com/hashicorp/terraform-plugin-framework/types"
//
//	//"github.com/hashicorp/terraform-plugin-framework/attr"
//	//"github.com/hashicorp/terraform-plugin-framework/types"
//	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
//)
//
////var (
////	_ validator.Set = NullIfAlsoSetPlanModifier{}
////	_ validator.Bool   = NullIfAlsoSetPlanModifier{}
////)
//
//func HandleImplicitFrameworks() planmodifier.Set {
//	return &handleImplicitFrameworks{}
//}
//
//type handleImplicitFrameworks struct{}
//
//func (m *handleImplicitFrameworks) Description(ctx context.Context) string {
//	return m.MarkdownDescription(ctx)
//}
//
//func (m *handleImplicitFrameworks) MarkdownDescription(context.Context) string {
//	return ""
//}
//
//func (m *handleImplicitFrameworks) PlanModifySet(ctx context.Context, req planmodifier.SetRequest, resp *planmodifier.SetResponse) {
//	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || len(req.ConfigValue.Elements()) == 0 {
//		return
//	}
//
//	frameworkValues := req.ConfigValue.Elements()
//	var frameworkName basetypes.StringValue
//	for idx := range len(frameworkValues) {
//		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("frameworks").AtSetValue(frameworkValues[idx]).AtName("name"), &frameworkName)...)
//		if resp.Diagnostics.HasError() {
//			return
//		}
//
//		if frameworkName.ValueString() != util.AppSecRuleFrameworkNameEnumTerraform {
//			resp.PlanValue = req.ConfigValue
//		} else {
//			resp.PlanValue = types.SetUnknown(req.ConfigValue.ElementType(ctx))
//		}
//
//		// NOTE: this code all works, but the framework raises an error due
//		// to the config values count disagreeing with the plan values count.
//		//if frameworkName.ValueString() == models.AppSecRuleFrameworkNameEnumTerraform {
//		//    var tfFrameworkValue basetypes.ObjectValue
//		//    resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("frameworks").AtSetValue(frameworkValues[idx]), &tfFrameworkValue)...)
//		//    if resp.Diagnostics.HasError() {
//		//        return
//		//    }
//
//		//    tfPlanFrameworkValue := types.ObjectValueMust(
//		//        tfFrameworkValue.AttributeTypes(ctx),
//		//        map[string]attr.Value{
//		//            "name": types.StringValue(models.AppSecRuleFrameworkNameEnumTerraformPlan),
//		//            "definition": tfFrameworkValue.Attributes()["definition"],
//		//            "definition_link": tfFrameworkValue.Attributes()["definition_link"],
//		//            "remediation_description": tfFrameworkValue.Attributes()["remediation_description"],
//		//    })
//
//		//    frameworkValues = append(frameworkValues, tfPlanFrameworkValue)
//		//    resp.PlanValue = types.SetValueMust(req.ConfigValue.ElementType(ctx), frameworkValues)
//		//}
//	}
//}
