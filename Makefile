# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

# CI execution flag
IS_CI_EXECUTION 	?= 0

# Terraform plugins directory
TF_PLUGINS_DIR 		?= "${HOME}/.terraform.d/plugins"

# Provider values
PROVIDER_HOSTNAME 	?= registry.terraform.io
PROVIDER_NAMESPACE 	?= PaloAltoNetworks
PROVIDER_NAME 		?= cortexcloud
PROVIDER_BINARY 	?= terraform-provider-${PROVIDER_NAME}
PROVIDER_VERSION 	?= 0.0.1

# Linker values
# TODO: parse the output from `go version -json -m .` within root dir
GIT_COMMIT 					:= $(shell git rev-parse HEAD)
CORTEX_SERVER_VERSION 		:= master-platform-v4.2.0-4877-g4886d-7fe3
CORTEX_PAPI_VERSION 		:= 1.3
BUILD_DATE 					?= $(shell TZ=UTC0 git show --quiet --date='format-local:%Y-%m-%dT%T%z' --format="%cd")
GO_VERSION 					:= $(shell go version)

# All target OS and architecture combinations for releases
# (Note: linux_amd64 is REQUIRED for usage in HCP Terraform)
ALL_TARGET_OS_ARCH = darwin_arm64 darwin_amd64 linux_amd64 linux_arm64 linux_arm windows_amd64
# Target OS and architecture for local development/`make build`
TARGET_OS_ARCH 		?= darwin_arm64


# -----------------------------------------------------------------------------
# System Values
# -----------------------------------------------------------------------------

# Target path for provider binary (without target OS/arch)
PROVIDER_PATH 	:= "${TF_PLUGINS_DIR}/${PROVIDER_HOSTNAME}/${PROVIDER_NAMESPACE}/${PROVIDER_NAME}/${PROVIDER_VERSION}/${TARGET_OS_ARCH}"

# Local operating system/architecture
OS 				:= $(shell uname -s | awk '{print tolower($0)}')
ARCH 			:= $(shell uname -m)

#------------------------------------------------------------------------------
# LDFLAGS (Linker Flags) Definitions
#------------------------------------------------------------------------------

define LDFLAGS
-s -w \
-X 'github.com/PaloAltoNetworks/terraform-provider-cortexcloud/main.GitCommit=$(GIT_COMMIT)' \
-X 'github.com/PaloAltoNetworks/terraform-provider-cortexcloud/main.CortexServerVersion=$(CORTEX_SERVER_VERSION)' \
-X 'github.com/PaloAltoNetworks/terraform-provider-cortexcloud/main.CortexPAPIVersion=$(CORTEX_PAPI_VERSION)' \
-X 'github.com/PaloAltoNetworks/terraform-provider-cortexcloud/main.BuildDate=$(BUILD_DATE)' \
-X 'github.com/PaloAltoNetworks/terraform-provider-cortexcloud/main.GoVersion=$(GO_VERSION)'
endef

define TEST_LDFLAGS
-s -w \
-X 'github.com/PaloAltoNetworks/terraform-provider-cortexcloud/main.GitCommit=$(TEST_GIT_COMMIT)' \
-X 'github.com/PaloAltoNetworks/terraform-provider-cortexcloud/main.CortexServerVersion=$(TEST_CORTEX_SERVER_VERSION)' \
-X 'github.com/PaloAltoNetworks/terraform-provider-cortexcloud/main.CortexPAPIVersion=$(TEST_CORTEX_PAPI_VERSION)' \
-X 'github.com/PaloAltoNetworks/terraform-provider-cortexcloud/main.BuildDate=$(TEST_BUILD_DATE)' \
-X 'github.com/PaloAltoNetworks/terraform-provider-cortexcloud/main.GoVersion=$(TEST_GO_VERSION)'
endef

#------------------------------------------------------------------------------
# Phony Targets
#------------------------------------------------------------------------------

.PHONY: format build copyright-check copyright docs test test-unit test-acc lint ci clean checkos

# -----------------------------------------------------------------------------
# Main Targets
# -----------------------------------------------------------------------------

default: build

# Format project Go files
format:
	@echo "Running gofmt..."
	@gofmt -l -w .
	@echo ""
	@echo "Done!"

# Build the provider binary and install it into the target directory
build:
	@echo "Creating output directory ${PROVIDER_PATH}"
	@mkdir -p ${PROVIDER_PATH}
	@echo "Building provider ${PROVIDER_BINARY}"
	@echo "  - Provider Version: ${PROVIDER_VERSION}"
	@echo "  - Git Commit: ${GIT_COMMIT}"
	@echo "  - Target Cortex Server Version: ${CORTEX_SERVER_VERSION}"
	@echo "  - Target Cortex PAPI Version: ${CORTEX_PAPI_VERSION}"
	@echo "  - Build Date: ${BUILD_DATE}"
	@echo "  - Go Version: ${GO_VERSION}"
	@go build -ldflags="${LDFLAGS}" -o ${PROVIDER_PATH}
	@echo ""
	@echo "Done!"

# Check for missing copyright headers
copyright-check:
	@echo "Checking for missing file headers..."
	@copywrite headers --config .copywrite.hcl --plan

# Add copywrite headers to all files
copyright:
	@echo "Adding any missing file headers..."
	@copywrite headers --config .copywrite.hcl

# Generate provider documentation
docs:
	@echo "Generating provider documentation with tfplugindocs..."
	@tfplugindocs generate --rendered-provider-name "Cortex Cloud Provider"
	@echo ""
	@echo "Done!"

# Run all tests
test: test-unit test-acc

# Run unit tests
test-unit:
	@echo "Running unit tests..."
	@go test -v -race $$(go list ./... | grep -v /vendor/ | grep -v /acceptance/ | grep models/provider)

# Run acceptance tests
test-acc: build
	@echo "Running acceptance tests..."
	@TF_ACC=1 TF_ACC_LOG=DEBUG go test -v -cover -race $$(go list ./... | grep /acceptance)

# Run linter
lint:
	@echo "Running linter..."
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.59.1 run . ./internal/... ./vendor/github.com/PaloAltoNetworks/cortex-cloud-go/...

# Run all CI checks
# TODO: add acceptance tests
ci: lint copyright-check test-unit

# -----------------------------------------------------------------------------
# Helper recipes
# -----------------------------------------------------------------------------

# Delete provider binary from plugin directory
clean:
	@echo "Deleting directory ${PROVIDER_PATH}"
	@rm -rf ${PROVIDER_PATH}
	@echo "Done!"


# Print warning message if target operating system architecture does not
# match the values returned by the system, or error message if this is
# being executed in a CI pipeline (dictated by the IS_CI_EXECTION value)
checkos:
	@true
ifneq ("${OS}_${ARCH}", "${TARGET_OS_ARCH}")
ifeq ($(IS_CI_EXECUTION), 0)
	$(info WARNING: Configured TARGET_OS_ARCH value "$(TARGET_OS_ARCH)" does not match the expected value for the detected operating system and architecture "$(OS)_$(ARCH)". This may result in Terraform being unable to find the provider binary.)
else ifeq ($(IS_CI_EXECUTION), 1)
	$(error Configured TARGET_OS_ARCH value "$(TARGET_OS_ARCH)" does not match the expected value for the detected operating system and architecture "$(OS)_$(ARCH)")
endif
else
	$(info Configured TARGET_OS_ARCH value "$(TARGET_OS_ARCH)" matches detected operating system and architecture.)
endif
