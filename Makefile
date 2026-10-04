APXS ?= apxs

SOURCES = src/mod_payloadshield.c src/payloadshield_envelope.c \
    $(filter-out crypto/aead_provider.h,$(wildcard crypto/*.c))

.PHONY: all install clean test

all: mod_payloadshield.la

mod_payloadshield.la: $(SOURCES) $(wildcard include/*.h crypto/*.h)
	$(APXS) -c -Wc,-Wall -Iinclude -Icrypto -lcrypto -o mod_payloadshield.la $(SOURCES)

install: all
	$(APXS) -i -n payloadshield mod_payloadshield.la

test:
	$(MAKE) -C tests test

clean:
	rm -rf .libs *.la *.lo *.slo src/*.lo src/*.slo src/*.o crypto/*.lo crypto/*.slo crypto/*.o
	$(MAKE) -C tests clean
