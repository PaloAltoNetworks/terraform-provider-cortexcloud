schema_version = 1

project {
  license        = "MPL-2.0"
  copyright_holder = "Palo Alto Networks, Inc."
  copyright_year = 2025

  header_ignore = [
    # testing files
    "test/**",

    # depenedencies
    "vendor/**",

    # examples used within documentation (prose)
    "examples/**",

    # shell scripts
    "*.sh",

    # GitHub issue template configuration
    ".github/ISSUE_TEMPLATE/*.yml",

    # golangci-lint tooling configuration
    ".golangci.yml",

    # GoReleaser tooling configuration
    ".goreleaser.yml",
  ]
}
