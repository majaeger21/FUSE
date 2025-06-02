CC = gcc
CFLAGS = -Wall -std=gnu99
LDFLAGS = `pkg-config fuse --cflags --libs` -lcrypto

mirror_fs: mirror_fs.c mirror_fs.h
	$(CC) $(CFLAGS) mirror_fs.c -o mirror_fs $(LDFLAGS)

clean:
	rm -f mirror_fs
