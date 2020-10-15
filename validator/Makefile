REBAR := $(shell which rebar3 2>/dev/null || which ./rebar3)

.PHONY: validator

validator:
	$(REBAR) escriptize
	$(MAKE) install

BINDIR = $(shell $(REBAR) path --bin)
SCRIPT = $(BINDIR)/validator
TARGET ?= validator

install: $(SCRIPT)
	@cp -v $< $(TARGET)

clean:
	$(if $(BINDIR),rm -rf $(BINDIR))
	rebar3 clean
