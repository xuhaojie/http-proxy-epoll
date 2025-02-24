CC = /usr/bin/gcc
SHELL = /usr/bin/bash
CFLAGS = -B/usr/bin/ -Wall -Wextra --std=gnu11 -D_GNU_SOURCE
LFLAGS = -lpthread
SRC_FILES = main.c log.c util.c poll.c \
            proxy/connection.c proxy/accepted.c proxy/connecting.c proxy/link.c \
            lib/asyncaddrinfo/asyncaddrinfo.c
OUT_DIR = out
BIN = proxy

.PHONY: all debug dev prod clean

all: prod

# Verbose logging, debug symbols
debug: clean
	$(CC) $(CFLAGS) -g -o $(OUT_DIR)/$(BIN) $(SRC_FILES) $(LFLAGS)

# Less verbose logging, -O2, no debug symbols
dev: clean
	$(CC) $(CFLAGS) -DNO_DEBUG_LOG -O2 -o $(OUT_DIR)/$(BIN) $(SRC_FILES) $(LFLAGS)

# No logging, -O3, no debug symbols
prod: clean
	$(CC) $(CFLAGS) -DNO_LOG -DNO_DEBUG_LOG -O3 -o $(OUT_DIR)/$(BIN) $(SRC_FILES) $(LFLAGS)

clean:
	rm -rf $(OUT_DIR)
	mkdir -p $(OUT_DIR)
