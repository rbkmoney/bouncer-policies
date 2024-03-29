SUBMODULES = build_utils
SUBTARGETS = $(patsubst %,%/.git,$(SUBMODULES))

UTILS_PATH := build_utils
TEMPLATES_PATH := .

SERVICE_NAME := bouncer-policies
BUILD_IMAGE_NAME := build-erlang
BUILD_IMAGE_TAG := 1333d0926b203e00c47e4fad7e10d2252a020305
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
BASE_IMAGE_TAG := 0.26.0

-include $(UTILS_PATH)/make_lib/utils_image.mk

# CALL_ANYWHERE
$(SUBTARGETS): %/.git: %
	git submodule update --init $<
	touch $@

submodules: $(SUBTARGETS)

.PHONY: manifest test repl

VALIDATOR := $(CURDIR)/validator.escript
INSTANCES := $(shell find test/test/service -type f -path '*/fixtures/*/*.json')
ifeq ($(INSTANCES),)
$(error No fixtures to validate found, you probably need to update a search pattern)
endif

.PHONY: $(VALIDATOR)

INSTANCE_TARGETS := $(foreach inst, $(INSTANCES), $(inst).validate)
%.validate: %
	$(VALIDATOR) $^

validate: $(VALIDATOR) $(INSTANCE_TARGETS)

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
TEST_COVERAGE_THRESHOLD := 99

test: manifest
	$(DOCKER) run --rm $(TEST_VOLUMES) \
		$(TEST_IMAGE) test $(TEST_BUNDLE_DIRS) \
			--explain full \
			--ignore input.json

run_%:
	$(DOCKER) run --rm $(TEST_VOLUMES) \
		$(TEST_IMAGE) test $(TEST_BUNDLE_DIRS) \
			--explain full \
			--ignore input.json \
			-v \
			--run $*

RUN_TEST_COVERAGE = $(DOCKER) run --rm $(TEST_VOLUMES) $(TEST_IMAGE) test --coverage $(TEST_BUNDLE_DIRS)

test_coverage: manifest
	python3 test_coverage.py "$(RUN_TEST_COVERAGE)" $(TEST_COVERAGE_THRESHOLD)

repl: manifest
	$(DOCKER) run --rm -it -v $$PWD:$$PWD --workdir $$PWD $(TEST_IMAGE) run --watch --bundle policies --bundle test

