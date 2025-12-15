// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// PanicHandler is a global panic handler to catch all unexpected errors to
// prevent the provider from crashing.
//
// The crash stack is written into a local text file.
func PanicHandler(diagnostics *diag.Diagnostics) {
	if r := recover(); r != nil {
		programCounter, _, _, ok := runtime.Caller(2) // 1=the panic, 2=who called the panic

		programCounterFunc := runtime.FuncForPC(programCounter)
		if !ok {
			panic(r)
		}

		funcName := programCounterFunc.Name()
		message := fmt.Sprintf("An unexpected error occurred in %s.\n\n%v", funcName, r)

		// Write stack trace to disk so we don't dump on the console
		fileContents := fmt.Sprintf("%s\n\n%s", funcName, debug.Stack())
		file, err := os.CreateTemp("", "terraform_cortexcloud_crash_stack.*.txt")

		if err == nil {
			defer func() {
				closeErr := file.Close()
				if closeErr != nil {
					diagnostics.AddError(
						"File Close Error",
						fmt.Sprintf("error occured while attempting to close stack trace output file: %s", closeErr.Error()),
					)
					return
				}
			}()

			_, err := file.WriteString(fileContents)
			if err == nil {
				message = fmt.Sprintf("%s\n\nPlease report this issue to the provider developers and include this file if present: %s", message, file.Name())
			}
		}

		diagnostics.AddError(
			"Unexpected error in the Cortex Cloud provider",
			message,
		)
	}
}
