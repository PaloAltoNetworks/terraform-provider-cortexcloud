# Provider values
CC_PROVIDER_HOSTNAME = registry.terraform.io
CC_PROVIDER_NAMESPACE = PaloAltoNetworks
CC_PROVIDER_NAME = cortexcloud
CC_PROVIDER_BINARY = terraform-provider-${CC_PROVIDER_NAME}
CC_PROVIDER_VERSION = 0.0.1

# OS and architecture of the system that will run the provider
# Must follow the schema "os_architecture"
TARGET_OS_ARCH ?= darwin_arm64

plugin_directory_no_arch="${HOME}/.terraform.d/plugins/${CC_PROVIDER_HOSTNAME}/${CC_PROVIDER_NAMESPACE}/${CC_PROVIDER_NAME}/${CC_PROVIDER_VERSION}"
plugin_directory="${plugin_directory_no_arch}/${TARGET_OS_ARCH}"

IS_CI_EXECUTION=0

# Populate build flags
BUILD_VERSION := ${CC_PROVIDER_VERSION}
BUILD_TIME := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
BUILD_FLAGS := "-X main.buildVersion=${BUILD_VERSION} -X main.buildTime=${BUILD_TIME}"

# Retrieve operating system name and architecture 
os := $(shell uname -s | awk '{print tolower($0)}')
arch := $(shell uname -m)

# Strip whitespace from TARGET_OS_ARCH value
target_os_arch_stripped=$(shell echo "$(TARGET_OS_ARCH)" | xargs)

default: install

.PHONY: format
format:
	gofmt -l -w .

# Print warning message if target operating system architecture does not
# match the values returned by the system, or error message if this is
# being executed in a CI pipeline (dictated by the IS_CI_EXECTION value)
.PHONY: checkos
checkos:
ifneq ($(os)_$(arch), $(target_os_arch_stripped))
ifeq ($(IS_CI_EXECUTION), 0)
	$(info WARNING: Provided TARGET_OS_ARCH value "$(target_os_arch_stripped)" does not match the expected value for the detected operating system and architecture "$(os)_$(arch)". This may result in Terraform being unable to find the provider binary.)
else ifeq ($(IS_CI_EXECUTION), 1)
	$(error Provided OS_ARCH value "$(target_os_arch_stripped)" does not match the expected value for the detected operating system and architecture "$(os)_$(arch)".)
endif
endif

# Build provider binary
.PHONY: build
.ONESHELL:
build: checkos
	@echo "Build flags: ${BUILD_FLAGS}"
	@echo "Building provider ${CC_PROVIDER_BINARY}"
	@go build -mod=readonly -ldflags=${BUILD_FLAGS} -o ${CC_PROVIDER_BINARY}

# Build provider binary (skip checkos)
.PHONY: build-only
build-only:
	@go build -mod=readonly -ldflags=${BUILD_FLAGS} -o ${CC_PROVIDER_BINARY}
	@echo $?

# Build provider binary (skip checkos)
.PHONY: build-only-test
build-only-test:
	go build -mod=readonly -ldflags=${BUILD_FLAGS} -o ${HOME}/terraform-provider-mirror/providers/registry.terraform.io/PaloAltoNetworks/cortexcloud/0.0.0/darwin_arm64/terraform-provider-cortexcloud
	@echo $?

# Create plugin directory and move binary
.PHONY: install
install: build
	@echo "Creating plugin directory ${plugin_directory}"
	@mkdir -p ${plugin_directory}
	@echo "Moving binary to plugin directory..."
	@mv ${CC_PROVIDER_BINARY} ${plugin_directory}
	@echo "Done!"

# Delete provider binary from plugin directory
.PHONY: clean
clean:
	@echo "Deleting directory ${plugin_directory_no_arch}"
	@rm -rf ${plugin_directory_no_arch}
	@echo "Done!"

# Generate provider documentation
.PHONY: docs
docs:
	@echo "Adding any missing file headers..."
	@copywrite headers --config .copywrite.hcl
	@echo "Generating provider documentation with tfplugindocs..."
	@tfplugindocs generate --rendered-provider-name "Cortex Cloud Provider"
	@echo "Done!"

# Run all tests
.PHONY: test
test: test-unit test-acc

# Run unit tests
.PHONY: test-unit
test-unit:
	@echo "Running unit tests..."
	@TF_LOG=DEBUG go test -v -race -mod=readonly $$(go list -mod=readonly ./... | grep -v /vendor/ | grep -v /acceptance/ | grep models/provider)
#@go test -v -cover -race -mod=readonly $$(go list -mod=readonly ./... | grep -v /vendor/ | grep -v /acceptance/)
#@go test -v -cover -race -mod=vendor $$(go list ./... | grep -v /vendor/ | grep -v /acceptance/)

# Run acceptance tests
.PHONY: test-acc
test-acc: build
	@echo "Running acceptance tests..."
	@TF_ACC=1 go test -v -cover -race -mod=readonly $$(go list -mod=readonly ./... | grep /acceptance)
#@go test -v -cover -race -mod=vendor $$(go list ./... | grep /acceptance/)

# Run linter
.PHONY: lint
lint:
	@echo "Running linter..."
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.59.1 run . ./internal/... ./vendor/github.com/PaloAltoNetworks/cortex-cloud-go/...

# Check for missing copyright headers
.PHONY: copyright-check
copyright-check:
	@echo "Checking for missing file headers..."
	@copywrite headers --config .copywrite.hcl --plan

# Run all CI checks
.PHONY: ci
ci: lint copyright-check test-unit
