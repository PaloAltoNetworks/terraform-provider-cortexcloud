// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package planmodifiers

//import (
//	"context"
//	//"fmt"
//    //"slices"
//	////"strconv"
//	//"strings"
//
//	"github.com/hashicorp/terraform-plugin-framework/attr"
//	"github.com/hashicorp/terraform-plugin-framework/diag"
//	"github.com/hashicorp/terraform-plugin-framework/path"
//	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
//	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
//	"github.com/hashicorp/terraform-plugin-framework/types"
//	//"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
//)
//
////var (
////	_ validator.String = NullIfAlsoSetPlanModifier{}
////	_ validator.Bool   = NullIfAlsoSetPlanModifier{}
////)
//
//// NullIfAlsoSetPlanModifier is the underlying struct implementing AlsoRequiresOnValue.
//type NullIfAlsoSetPlanModifier struct {
//	//OnStringValues  []string
//	//OnBoolValues    []bool
//    OnValues []interface{}
//	PathExpressions path.Expressions
//}
//
//type NullIfAlsoSetPlanModifierRequest struct {
//    OnStringValues []string
//	OnBoolValues   []bool
//	Config         tfsdk.Config
//	ConfigValue    attr.Value
//	Plan           tfsdk.Plan
//	PlanValue      attr.Value
//	Path           path.Path
//	PathExpression path.Expression
//}
//
//type NullIfAlsoSetPlanModifierResponse struct {
//	Diagnostics diag.Diagnostics
//}
//
//// AlsoRequiresOnValues checks that a set of path.Expression has a non-null value,
//// if the current attribute or block is set to one of the values defined in onValues array.
////
//// Relative path.Expression will be resolved using the attribute or block
//// being validated.
//func NullIfAlsoSet(onValues []interface{}, expressions ...path.Expression) planmodifier.Int32 {
//	return NullIfAlsoSetPlanModifier{
//		OnValues:  onValues,
//		PathExpressions: expressions,
//	}
//}
//
////func NullIfAlsoSet(onValues []string, expressions ...path.Expression) planmodifier.String {
////	return NullIfAlsoSetPlanModifier{
////		OnStringValues:  onValues,
////		PathExpressions: expressions,
////	}
////}
//
////func NullIfAlsoSetStringValues(onValues []string, expressions ...path.Expression) planmodifier.String {
////	return NullIfAlsoSetPlanModifier{
////		OnStringValues:  onValues,
////		PathExpressions: expressions,
////	}
////}
////
////func NullIfAlsoSetBoolValues(onValues []bool, expressions ...path.Expression) planmodifier.Bool {
////	return NullIfAlsoSetPlanModifier{
////		OnBoolValues:    onValues,
////		PathExpressions: expressions,
////	}
////}
//
//// Description implements validator.String.
//func (m NullIfAlsoSetPlanModifier) Description(ctx context.Context) string {
//	return m.MarkdownDescription(ctx)
//}
//
//// MarkdownDescription implements validator.String.
//func (m NullIfAlsoSetPlanModifier) MarkdownDescription(context.Context) string {
//	//if len(v.OnStringValues) > 0 {
//	//	return fmt.Sprintf("If the current attribute is set to one of [%s], all of the following also need to be set: %q", strings.Join(v.OnStringValues, ","), v.PathExpressions)
//	//} else if len(v.OnBoolValues) > 0 {
//	//	boolValueArray := []string{}
//	//	for _, boolValue := range v.OnBoolValues {
//	//		boolValueArray = append(boolValueArray, strconv.FormatBool(boolValue))
//	//	}
//	//	return fmt.Sprintf("If the current attribute is set to one of [%v], all of the following also need to be set: %q", strings.Join(boolValueArray, ","), v.PathExpressions)
//	//}
//	return ""
//}
//
//func (m NullIfAlsoSetPlanModifier) PlanModify(ctx context.Context, req NullIfAlsoSetPlanModifierRequest, resp *NullIfAlsoSetPlanModifierResponse) {
//
//
//    expressions := req.PathExpression.MergeExpressions(m.PathExpressions...)
//
//	for _, expression := range expressions {
//		matchedPaths, diags := req.Config.PathMatches(ctx, expression)
//		resp.Diagnostics.Append(diags...)
//
//		// Collect all errors
//		if diags.HasError() {
//			continue
//		}
//
//		for _, mp := range matchedPaths {
//			// If the user specifies the same attribute this plan modifier is
//            // applied to as part of the input, skip it
//			if mp.Equal(req.Path) {
//				continue
//			}
//
//            var mpVal attr.Value
//            resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, mp, &mpVal)...)
//
//            switch mpVal.Type(ctx) {
//                case types.StringType:
//                    req.PlanValue = types.StringNull()
//                case types.BoolType:
//                    req.PlanValue = types.BoolNull()
//                case types.Int32Type:
//                    req.PlanValue = types.Int32Null()
//                // TODO: default
//            }
//
//                    //mpVal = types.StringNull()
//                    //if mpStringVal, ok := mpVal.(basetypes.StringValue); !ok {
//                    //    resp.Diagnostics.AddError("Value Conversion Error", "TODO")
//                    //    return
//                    //}
//                    //if (!mpStringVal.IsNull() && !mpStringVal.IsUnknown() && slices.Contains(req.) {
//                    //    req.PlanValue = types.StringNull()
//                    //}
//		}
//	}
//}
//
//// ValidateString implements validator.String.
//func (v NullIfAlsoSetPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
//	//valueMessageArr := []string{}
//	//for _, stringValue := range v.OnStringValues {
//	//	valueMessageArr = append(valueMessageArr, fmt.Sprintf("`%s`", stringValue))
//	//}
//
//	for _, value := range v.OnStringValues {
//		if value == req.ConfigValue.ValueString() {
//			validateReq := NullIfAlsoSetPlanModifierRequest{
//                PlanValue:      req.PlanValue,
//				Path:           req.Path,
//				PathExpression: req.PathExpression,
//			}
//			validateResp := &NullIfAlsoSetPlanModifierResponse{}
//
//			v.PlanModify(ctx, validateReq, validateResp)
//			resp.Diagnostics.Append(validateResp.Diagnostics...)
//			return
//		}
//	}
//}
//
//// ValidateBool implements validator.Bool.
//func (v NullIfAlsoSetPlanModifier) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
//	//valueMessageArr := []string{}
//	//for _, boolValue := range v.OnBoolValues {
//	//	valueMessageArr = append(valueMessageArr, fmt.Sprintf("`%t`", boolValue))
//	//}
//
//	for _, value := range v.OnBoolValues {
//		if value == req.ConfigValue.ValueBool() {
//			validateReq := NullIfAlsoSetPlanModifierRequest{
//                PlanValue:      req.PlanValue,
//				Path:           req.Path,
//				PathExpression: req.PathExpression,
//			}
//			validateResp := &NullIfAlsoSetPlanModifierResponse{}
//
//			v.PlanModify(ctx, validateReq, validateResp)
//			resp.Diagnostics.Append(validateResp.Diagnostics...)
//			return
//		}
//	}
//}
//
//// ValidateString implements validator.String.
//func (m NullIfAlsoSetPlanModifier) PlanModifyInt32(ctx context.Context, req planmodifier.Int32Request, resp *planmodifier.Int32Response) {
//
//
//	for _, value := range v.OnStringValues {
//		if value == req.ConfigValue.ValueInt32() {
//			validateReq := NullIfAlsoSetPlanModifierRequest{
//                PlanValue:      req.PlanValue,
//				Path:           req.Path,
//				PathExpression: req.PathExpression,
//			}
//			validateResp := &NullIfAlsoSetPlanModifierResponse{}
//
//			v.PlanModify(ctx, validateReq, validateResp)
//			resp.Diagnostics.Append(validateResp.Diagnostics...)
//			return
//		}
//	}
//}
//
//
////func (m NullIfAlsoSetPlanModifier) PlanModify(ctx context.Context, req NullIfAlsoSetPlanModifierRequest, resp *NullIfAlsoSetPlanModifierResponse) {
////	expressions := req.PathExpression.MergeExpressions(m.PathExpressions...)
////
////	for _, expression := range expressions {
////		matchedPaths, diags := req.Config.PathMatches(ctx, expression)
////		resp.Diagnostics.Append(diags...)
////
////		// Collect all errors
////		if diags.HasError() {
////			continue
////		}
////
////		for _, mp := range matchedPaths {
////			// If the user specifies the same attribute this plan modifier is
////            // applied to as part of the input, skip it
////			if mp.Equal(req.Path) {
////				continue
////			}
////
////            var mpVal attr.Value
////            resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, mp, &mpVal)...)
////
////            switch mpVal.Type(ctx) {
////                case types.StringType:
////                    req.PlanValue = types.StringNull()
////                case types.BoolType:
////                    req.PlanValue = types.BoolNull()
////                case types.Int32Type:
////                    req.PlanValue = types.Int32Null()
////                // TODO: default
////            }
////
////                    //mpVal = types.StringNull()
////                    //if mpStringVal, ok := mpVal.(basetypes.StringValue); !ok {
////                    //    resp.Diagnostics.AddError("Value Conversion Error", "TODO")
////                    //    return
////                    //}
////                    //if (!mpStringVal.IsNull() && !mpStringVal.IsUnknown() && slices.Contains(req.) {
////                    //    req.PlanValue = types.StringNull()
////                    //}
////		}
////	}
////}
////
////// ValidateString implements validator.String.
////func (v NullIfAlsoSetPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
////	//valueMessageArr := []string{}
////	//for _, stringValue := range v.OnStringValues {
////	//	valueMessageArr = append(valueMessageArr, fmt.Sprintf("`%s`", stringValue))
////	//}
////
////	for _, value := range v.OnStringValues {
////		if value == req.ConfigValue.ValueString() {
////			validateReq := NullIfAlsoSetPlanModifierRequest{
////                PlanValue:      req.PlanValue,
////				Path:           req.Path,
////				PathExpression: req.PathExpression,
////			}
////			validateResp := &NullIfAlsoSetPlanModifierResponse{}
////
////			v.PlanModify(ctx, validateReq, validateResp)
////			resp.Diagnostics.Append(validateResp.Diagnostics...)
////			return
////		}
////	}
////}
////
////// ValidateBool implements validator.Bool.
////func (v NullIfAlsoSetPlanModifier) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
////	//valueMessageArr := []string{}
////	//for _, boolValue := range v.OnBoolValues {
////	//	valueMessageArr = append(valueMessageArr, fmt.Sprintf("`%t`", boolValue))
////	//}
////
////	for _, value := range v.OnBoolValues {
////		if value == req.ConfigValue.ValueBool() {
////			validateReq := NullIfAlsoSetPlanModifierRequest{
////                PlanValue:      req.PlanValue,
////				Path:           req.Path,
////				PathExpression: req.PathExpression,
////			}
////			validateResp := &NullIfAlsoSetPlanModifierResponse{}
////
////			v.PlanModify(ctx, validateReq, validateResp)
////			resp.Diagnostics.Append(validateResp.Diagnostics...)
////			return
////		}
////	}
////}
////
////// ValidateString implements validator.String.
////func (v NullIfAlsoSetPlanModifier) PlanModifyInt32(ctx context.Context, req planmodifier.Int32Request, resp *planmodifier.Int32Response) {
////	for _, value := range v.OnStringValues {
////		if value == req.ConfigValue.ValueInt32() {
////			validateReq := NullIfAlsoSetPlanModifierRequest{
////                PlanValue:      req.PlanValue,
////				Path:           req.Path,
////				PathExpression: req.PathExpression,
////			}
////			validateResp := &NullIfAlsoSetPlanModifierResponse{}
////
////			v.PlanModify(ctx, validateReq, validateResp)
////			resp.Diagnostics.Append(validateResp.Diagnostics...)
////			return
////		}
////	}
////}
