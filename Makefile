CC ?= cc
CFLAGS ?= -std=c99 -Wall -Wextra -O2
SRC := src/main.c src/md5.c src/sha1.c src/sha256.c src/weaklist.c
BIN := hashcheck

.PHONY: all test clean

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC)

test: $(BIN)
	./tests/run_tests.sh

clean:
	rm -f $(BIN)
