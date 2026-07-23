CC           := gcc
SODIUM_PREFIX := $(shell brew --prefix libsodium)
CFLAGS       := -Wall -Wextra -Isrc -I$(SODIUM_PREFIX)/include
LDFLAGS      := -L$(SODIUM_PREFIX)/lib -lsodium

BUILD  := build
SRC    := src/crypto.c


TEST_SRCS := $(wildcard src/test_*.c)
TEST_BINS := $(patsubst src/%.c,$(BUILD)/%,$(TEST_SRCS))

.PHONY: all test clean

all: $(TEST_BINS)


$(BUILD)/test_%: src/test_%.c $(SRC)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)


test: $(TEST_BINS)
	@fail=0; \
	for t in $(TEST_BINS); do \
		echo "== $$t =="; \
		./$$t || fail=1; \
		echo; \
	done; \
	exit $$fail

clean:
	rm -rf $(BUILD)