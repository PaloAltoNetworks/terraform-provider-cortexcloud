// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"log"
	//"runtime"
	//"runtime/debug"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
)

// var (
//
//	buildVersion string = "unknown"
//	buildTime    string = "unknown"
//	goVersion    string = "unknown"
//
// )
var (
	GitCommit           = "NOCOMMIT"
	CortexServerVersion = "UNKNOWN"
	CortexPAPIVersion   = "UNKNOWN"
	GoVersion           = "UNKNOWN"
	BuildDate           = "UNKNOWN"
)

func logBuildInfo() {
	//if info, ok := debug.ReadBuildInfo(); ok {
	//	goVersion = info.GoVersion
	//}

	log.Printf("{ \"GitCommit\": \"%s\", \"CortexServerVersion\": \"%s\", \"CortexServerVersion\": \"%s\", \"GoVersion\": \"%s\", \"BuildDate\": \"%s\"}", GitCommit, CortexServerVersion, CortexPAPIVersion, GoVersion, BuildDate)
}

func main() {
	logBuildInfo()

	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers (i.e. delve)")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address:         "registry.terraform.io/PaloAltoNetworks/cortexcloud",
		Debug:           debug,
		ProtocolVersion: 6,
	}

	err := providerserver.Serve(context.Background(), provider.New(GitCommit), opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
