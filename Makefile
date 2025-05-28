CC = gcc
CFLAGS = -Wall -g -D_FILE_OFFSET_BITS=64 `pkg-config fuse --cflags --libs` -lcrypto

TARGETS = mirror_fs

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
