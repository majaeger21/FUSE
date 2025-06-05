#ifndef MIRROR_FS_H
#define MIRROR_FS_H

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define TAG_LEN 16  // GCM tag length
#define IV_LEN 16   // 128-bit IV

typedef struct {
    char *mir_dir;
} MirData;

void mir_usage();
void mir_path(char fpath[PATH_MAX], const char *path);

// Encryption helper functions
void derive_key(const char *passphras);
int encrypt_data(const unsigned char *plaintext, int plaintext_len, 
                 unsigned char *ciphertext);
int decrypt_data(const unsigned char *ciphertext, int ciphertext_len,
                 unsigned char *plaintext);
#endif
