SUBMODULES = build_utils
SUBTARGETS = $(patsubst %,%/.git,$(SUBMODULES))

UTILS_PATH := build_utils
TEMPLATES_PATH := .

SERVICE_NAME := bouncer-policies
BUILD_IMAGE_TAG := 917afcdd0c0a07bf4155d597bbba72e962e1a34a
CALL_ANYWHERE := \
	submodules \
	manifest \
	test
CALL_W_CONTAINER := \
	validate

-include $(UTILS_PATH)/make_lib/utils_container.mk

SERVICE_IMAGE_TAG ?= $(shell git rev-parse HEAD)
SERVICE_IMAGE_PUSH_TAG ?= $(SERVICE_IMAGE_TAG)
BASE_IMAGE_NAME := openpolicyagent/opa
BASE_IMAGE_TAG := 0.24.0

-include $(UTILS_PATH)/make_lib/utils_image.mk

.PHONY: manifest test

VALIDATOR := $(CURDIR)/validator.escript
INSTANCES := $(wildcard test/test/*/fixtures/*.json)

.PHONY: $(VALIDATOR)

validate: $(VALIDATOR)
	$(foreach inst, $(INSTANCES), $(VALIDATOR) $(inst))

MANIFEST := $(CURDIR)/policies/.manifest
REVISION := $(SERVICE_IMAGE_TAG)

manifest: $(MANIFEST)

$(MANIFEST): $(MANIFEST).src
	jq '.revision = "$(REVISION)"' $< > $@

$(VALIDATOR):
	$(MAKE) TARGET=$(VALIDATOR) -C validator

TEST_IMAGE := $(BASE_IMAGE_NAME):$(BASE_IMAGE_TAG)
TEST_BUNDLES := policies test
TEST_VOLUMES := $(foreach bundle, $(TEST_BUNDLES), -v $(CURDIR)/$(bundle):/$(bundle):ro)
TEST_BUNDLE_DIRS := $(foreach bundle, $(TEST_BUNDLES), /$(bundle))

test: manifest
	$(DOCKER) run --rm $(TEST_VOLUMES) \
		$(TEST_IMAGE) test $(TEST_BUNDLE_DIRS) \
			--explain full \
			--ignore input.json
