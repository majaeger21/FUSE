CC = gcc
CFLAGS = -Wall -g -o mirror_fs mirror_fs.c -D_FILE_OFFSET_BITS=64 `pkg-config fuse --cflags --libs` -lcrypto

TARGETS = mirror_fs

all: $(TARGETS)

mirror_fs: mirror_fs.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
# CC = gcc
# CFLAGS = $(shell pkg-config fuse --cflags) -Wall -D_FILE_OFFSET_BITS=64
# LDFLAGS = $(shell pkg-config fuse --libs) -lcrypto -lssl

# TARGET = mirror_fs
# SOURCES = mirror_fs.c

# all: $(TARGET)

# $(TARGET): $(SOURCES)
# 	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

# clean:
# 	rm -f $(TARGET)

# .PHONY: all clean