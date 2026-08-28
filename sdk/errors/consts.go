// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package errors

const (
	// Error Codes/Messages
	CodePreRequestValidationFailure = "PreRequestArgumentValidationFailure"
	MsgPreRequestValidationFailure  = "Pre-request argument validation failed. See details for more information."

	// Error Detail Codes/Messages
	DetailCodeUnexpectedValidationError = "UnexpectedValiadationError"
	DetailMsgUnexpectedValidationError  = "Encountered unexpected error during validation. See \"Error\" field for more information."

	DetailCodeUnknownValidationTag = "UnknownValidationTag"
	DetailMsgUnknownValidationTag  = "Unable to validate field \"%s\": validation tag \"%s\" does not have any defined validation logic. See \"Error\" field for more information."

	DetailCodeMissingRequiredValue = "MissingRequiredValue"
	DetailMsgMissingRequiredValue  = "\"%s\" is a required value."

	DetailCodeMinimumNumberOfValues = "MinimumNumberOfValues"
	DetailMsgMinimumNumberOfValues  = "Field \"%s\" must have at least %s value(s) provided (recieved %d)."

	DetailCodeInvalidEnumValue = "InvalidEnumValue"
	DetailMsgInvalidEnumValue  = "Invalid %s value \"%v\" - expected one of: %s"

	CodeAPIResponseParsingFailure             = ""
	CodeSDKInitializationFailure              = ""
	CodeRequestSerializationFailure           = ""
	CodeURLConstructionFailure                = ""
	CodeContextCancellation                   = ""
	CodeHTTPRequestCreationFailure            = ""
	CodeAuthenticationHeaderGenerationFailure = ""
	CodeNetworkError                          = ""
	CodeNoResponseReceived                    = ""
	CodeResponseBodyReadFailure               = ""
	CodeResponseDeserializationFailure        = ""
)
