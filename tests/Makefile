CC ?= cc
CPPFLAGS += -I../include -I../crypto
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror
LDLIBS += -lcrypto

CRYPTO_SOURCES = $(filter-out ../crypto/aead_provider.h,$(wildcard ../crypto/*.c))
CRYPTO_HEADERS = $(wildcard ../include/*.h ../crypto/*.h)
TEST_BINARY = test_crypto

.PHONY: all test clean

all: $(TEST_BINARY)

$(TEST_BINARY): test_crypto.c $(CRYPTO_SOURCES) $(CRYPTO_HEADERS) ../src/payloadshield_envelope.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_crypto.c $(CRYPTO_SOURCES) ../src/payloadshield_envelope.c $(LDLIBS)

test: $(TEST_BINARY)
	./$(TEST_BINARY)

clean:
	rm -f $(TEST_BINARY)