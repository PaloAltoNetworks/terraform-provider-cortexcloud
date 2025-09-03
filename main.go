// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"log"
	"runtime/debug"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
)

var (
	buildVersion string = "unknown"
	buildTime    string = "unknown"
	goVersion    string = "unknown"
)

func logBuildInfo() {
	if info, ok := debug.ReadBuildInfo(); ok {
		goVersion = info.GoVersion
	}

	log.Printf("{ \"buildVersion\": \"%s\", \"buildTime\": \"%s\", goVersion: \"%s\" }", buildVersion, buildTime, goVersion)
}

func main() {
	logBuildInfo()

	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers (e.g. delve)")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address:         "registry.terraform.io/PaloAltoNetworks/cortexcloud",
		Debug:           debug,
		ProtocolVersion: 6,
	}

	err := providerserver.Serve(context.Background(), provider.New(buildVersion), opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
