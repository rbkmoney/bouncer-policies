REBAR := $(shell which rebar3 2>/dev/null || which ./rebar3)

DEPS := \
	$(wildcard src/*) \
	rebar.lock

DEPS := $(foreach fn, $(DEPS), $(realpath $(fn)))

BINDIR = $(shell $(REBAR) path --bin)
SCRIPT = $(BINDIR)/validator
TARGET ?= validator

$(TARGET): $(DEPS)
	$(REBAR) escriptize
	$(MAKE) install

install: $(SCRIPT)
	@cp -v $< $(TARGET)

clean:
	$(if $(BINDIR),rm -rf $(BINDIR))
	rebar3 clean
