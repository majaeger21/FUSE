#ifndef MIRROR_FS_H
#define MIRROR_FS_H

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_LEN 32  // 256-bit key
#define SALT_LEN 16 // 16 bytes of random data
#define TAG_LEN 16  // GCM tag length
#define IV_LEN 16   // 128-bit IV

typedef struct {
    char *mir_dir;
    unsigned char key[KEY_LEN];  // Encryption key derived from passphrase
    unsigned char salt[SALT_LEN]; // Salt for key derivation
} MirData;

void mir_usage();
void mir_path(char fpath[PATH_MAX], const char *path);

// Encryption helper functions
int derive_key(const char *passphrase, const unsigned char *salt, unsigned char *key_out);
int encrypt_data(const unsigned char *plaintext, int plaintext_len, 
                 const unsigned char *key, unsigned char *ciphertext);
int decrypt_data(const unsigned char *ciphertext, int ciphertext_len,
                 const unsigned char *key, unsigned char *plaintext);
#endif
