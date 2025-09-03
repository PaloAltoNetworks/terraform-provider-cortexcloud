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

# Build flags
BUILD_VERSION 		?= ${PROVIDER_VERSION}
BUILD_TIME 			?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

# Target OS and architecture the provider binary will be built for.
# Must follow the format "os_architecture".
TARGET_OS_ARCH 		?= darwin_arm64


# -----------------------------------------------------------------------------
# System Values
# -----------------------------------------------------------------------------

# Target path for provider binary (without target OS/arch)
PROVIDER_PATH 	:= "${TF_PLUGINS_DIR}/${PROVIDER_HOSTNAME}/" \
				   + "${PROVIDER_NAMESPACE}/${PROVIDER_HOSTNAME}" \
				   + "${PROVIDER_VERSION}"

# Local operating system/architecture
OS 				:= $(shell uname -s | awk '{print tolower($0)}')
ARCH 			:= $(shell uname -m)


# -----------------------------------------------------------------------------
# Main Recipes
# -----------------------------------------------------------------------------

default: install

.PHONY: format
format:
	@echo "Running gofmt..."
	@gofmt -l -w .
	@echo ""
	@echo "Done!"

# Build provider binary
.PHONY: build
build:
	@echo "Building provider ${PROVIDER_BINARY}"
	@echo "  - Version: ${PROVIDER_VERSION}"
	@echo "  - Build Time: ${BUILD_TIME}"
	@go build -ldflags="-X main.buildVersion=${PROVIDER_VERSION} -X main.buildTime=${BUILD_TIME}" -o ${PROVIDER_BINARY}
	@echo ""
	@echo "Done!"

# Create plugin directory and move binary
.PHONY: install
install: build
	@TARGET_DIR="${PROVIDER_PATH}/${TARGET_OS_ARCH}"
	@echo "Creating plugin directory ${TARGET_DIR}"
	@mkdir -p ${TARGET_DIR}
	@echo "Moving binary to plugin directory..."
	@mv ${PROVIDER_BINARY} ${TARGET_DIR}
	@echo ""
	@echo "Done!"

# Generate provider documentation
.PHONY: docs
docs:
	@echo "Adding any missing file headers..."
	@copywrite headers --config .copywrite.hcl
	@echo "Generating provider documentation with tfplugindocs..."
	@tfplugindocs generate --rendered-provider-name "Cortex Cloud Provider"
	@echo ""
	@echo "Done!"

# Run all tests
.PHONY: test
test: test-unit test-acc

# Run unit tests
.PHONY: test-unit
test-unit:
	@echo "Running unit tests..."
	@TF_LOG=DEBUG go test -v -race $$(go list ./... | grep -v /vendor/ | grep -v /acceptance/ | grep models/provider)

# Run acceptance tests
.PHONY: test-acc
test-acc: build
	@echo "Running acceptance tests..."
	@TF_ACC=1 go test -v -cover -race $$(go list ./... | grep /acceptance)

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

# -----------------------------------------------------------------------------
# Helper recipes
# -----------------------------------------------------------------------------

# Delete provider binary from plugin directory
.PHONY: clean
clean:
	@echo "Deleting directory ${PROVIDER_PATH}"
	@rm -rf ${PROVIDER_PATH}
	@echo "Done!"


# Print warning message if target operating system architecture does not
# match the values returned by the system, or error message if this is
# being executed in a CI pipeline (dictated by the IS_CI_EXECTION value)
.PHONY: checkos
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
