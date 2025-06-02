/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    gcc -Wall `pkg-config fuse --cflags --libs` fusexmp.c -o fusexmp
*/

#define FUSE_USE_VERSION 26
#define ENC_HEADER "ENCFS"
#define ENC_HEADER_LEN 5

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include "mirror_fs.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

////////////////// FUSE OPERATIONS /////////////////

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    fprintf(stderr, "DEBUG: getattr called for: %s (mapped to: %s)\n", path, fpath);



    res = lstat(fpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_access(const char *path, int mask)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    res = access(fpath, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    res = readlink(fpath, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    (void) offset;
    (void) fi;

    dp = opendir(fpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        fprintf(stderr, "DEBUG: readdir found: %s\n", de->d_name);

        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(fpath, mode);
    else
        res = mknod(fpath, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    res = mkdir(fpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_unlink(const char *path)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    res = unlink(fpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rmdir(const char *path)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    res = rmdir(fpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
    int res;
    char from_fpath[PATH_MAX];
    char to_fpath[PATH_MAX];

    mir_path(from_fpath, from);
    mir_path(to_fpath, to);

    res = symlink(from_fpath, to_fpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(const char *from, const char *to)
{
    int res;
    char from_fpath[PATH_MAX];
    char to_fpath[PATH_MAX];

    mir_path(from_fpath, from);
    mir_path(to_fpath, to);

    res = rename(from_fpath, to_fpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_link(const char *from, const char *to)
{
    int res;
    char from_fpath[PATH_MAX];
    char to_fpath[PATH_MAX];

    mir_path(from_fpath, from);
    mir_path(to_fpath, to);

    res = link(from_fpath, to_fpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    res = chmod(fpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    res = lchown(fpath, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
    char fpath[PATH_MAX];
    struct fuse_context *ctx = fuse_get_context();
    MirData *m_data = (MirData *) ctx->private_data;

    mir_path(fpath, path);

    if (size == 0) {
        // For truncate to 0, just create empty encrypted file
        int fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd == -1)
            return -errno;
        
        unsigned char empty[1] = {0};
        unsigned char encrypted[IV_LEN + 1 + TAG_LEN];
        
        int encrypted_len = encrypt_data(empty, 0, m_data->key, encrypted);
        if (encrypted_len > 0) {
            write(fd, encrypted, encrypted_len);
        }
        close(fd);
        return 0;
    }
    
    return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);
    struct timeval tv[2];

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(fpath, tv);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    res = open(fpath, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    int fd, res;
    char fpath[PATH_MAX];
    struct fuse_context *ctx = fuse_get_context();
    MirData *m_data = (MirData *) ctx->private_data;

    mir_path(fpath, path);

    fprintf(stderr, "DEBUG: xmp_read path: %s → %s\n", path, fpath);

    (void) fi;
    fd = open(fpath, O_RDONLY);
    if (fd == -1)
        return -errno;

    // Get file size
    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return -errno;
    }

    unsigned char *encrypted_buf = malloc(st.st_size);
    if (!encrypted_buf) {
        close(fd);
        return -ENOMEM;
    }

    if (read(fd, encrypted_buf, st.st_size) != st.st_size) {
        free(encrypted_buf);
        close(fd);
        return -errno;
    }
    close(fd);

    unsigned char *decrypted_buf = malloc(st.st_size);
    if (!decrypted_buf) {
        free(encrypted_buf);
        return -ENOMEM;
    }

    int decrypted_len = decrypt_data(encrypted_buf, st.st_size, m_data->key, decrypted_buf);

    if (decrypted_len == -2) {
        fprintf(stderr, "DEBUG: passthrough triggered (no encryption header)\n");

        if (offset >= st.st_size) {
            free(encrypted_buf);
            free(decrypted_buf);
            return 0;
        }

        if (offset + size > st.st_size)
            size = st.st_size - offset;

        memcpy(buf, encrypted_buf + offset, size);
        res = size;

        free(encrypted_buf);
        free(decrypted_buf);
        return res;
    }


    if (decrypted_len < 0) {
        free(encrypted_buf);
        free(decrypted_buf);
        return -EIO;
    }

    if (offset < decrypted_len) {
        if (offset + size > decrypted_len)
            size = decrypted_len - offset;
        memcpy(buf, decrypted_buf + offset, size);
        res = size;
    } else {
        res = 0;
    }

    free(encrypted_buf);
    free(decrypted_buf);
    return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    fprintf(stderr, "DEBUG: xmp_write called for path: %s, size: %zu\n", path, size);

    int fd;
    int res;
    char fpath[PATH_MAX];
    struct fuse_context *ctx = fuse_get_context();
    MirData *m_data = (MirData *) ctx->private_data;

    mir_path(fpath, path);

    (void) fi;

    // Try to read existing file 
    unsigned char *file_contents = NULL;
    size_t file_size = 0;

    fd = open(fpath, O_WRONLY);
    if (fd != -1) {
        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size > 0) {
            unsigned char *encrypted_buf = malloc(st.st_size);
            if (encrypted_buf && read(fd, encrypted_buf, st.st_size) == st.st_size) {
                // Decrypt existing content
                unsigned char *decrypted_buf = malloc(st.st_size);
                if (decrypted_buf) {
                    int decrypted_len = decrypt_data(encrypted_buf, st.st_size, 
                                                   m_data->key, decrypted_buf);
                    if (decrypted_len > 0) {
                        file_contents = decrypted_buf;
                        file_size = decrypted_len;
                    } else {
                        free(decrypted_buf);
                    }
                }
                free(encrypted_buf);
            }
        }
        close(fd);
    }

    // Calculate new file size
    size_t new_size = offset + size;
    if (new_size < file_size)
        new_size = file_size;
    
    // Allocate buffer for modified content
    unsigned char *new_contents = calloc(1, new_size);
    if (!new_contents) {
        free(file_contents);
        return -ENOMEM;
    }
    
    // Copy existing content
    if (file_contents) {
        memcpy(new_contents, file_contents, file_size);
        free(file_contents);
    }
    
    // Apply the write
    memcpy(new_contents + offset, buf, size);
    
    // Encrypt the new content
    unsigned char *encrypted_buf = malloc(new_size + IV_LEN + TAG_LEN);
    if (!encrypted_buf) {
        free(new_contents);
        return -ENOMEM;
    }
    
    int encrypted_len = encrypt_data(new_contents, new_size, m_data->key, encrypted_buf);
    free(new_contents);
    
    if (encrypted_len < 0) {
        free(encrypted_buf);
        return -EIO;
    }
    
    // Write encrypted content to file
    fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        free(encrypted_buf);
        return -errno;
    }
    
    res = write(fd, encrypted_buf, encrypted_len);
    free(encrypted_buf);
    
    if (res != encrypted_len) {
        close(fd);
        return -errno;
    }

    close(fd);
    return size;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    res = statvfs(fpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) fi;
    return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
                     struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) isdatasync;
    (void) fi;
    return 0;
}

static struct fuse_operations xmp_oper = {
    .getattr	= xmp_getattr,
    .access	= xmp_access,
    .readlink	= xmp_readlink,
    .readdir	= xmp_readdir,
    .mknod	= xmp_mknod,
    .mkdir	= xmp_mkdir,
    .symlink	= xmp_symlink,
    .unlink	= xmp_unlink,
    .rmdir	= xmp_rmdir,
    .rename	= xmp_rename,
    .link	= xmp_link,
    .chmod	= xmp_chmod,
    .chown	= xmp_chown,
    .truncate	= xmp_truncate,
    .utimens	= xmp_utimens,
    .open	= xmp_open,
    .read	= xmp_read,
    .write	= xmp_write,
    .statfs	= xmp_statfs,
    .release	= xmp_release,
    .fsync	= xmp_fsync,
};

void mir_usage() {
    fprintf(
        stderr,
        "usage: mirror_fs [FUSE options] <mountpoint> <directory to mirror>\n"
    );
    exit(EXIT_FAILURE);    
}

/* Append path to mirror directory. Haven't tested this yet. */
void mir_path(char fpath[PATH_MAX], const char *path) {
    struct fuse_context *ctx = fuse_get_context();
    MirData *m_data = (MirData *) ctx->private_data;
    snprintf(fpath, PATH_MAX, "%s/%s", m_data->mir_dir, path);
}

////////////////// ENCRYPTION FUNCTIONS /////////////////
/** Documentations Used
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 * https://docs.openssl.org/3.3/man7/openssl-env/
 * https://docs.openssl.org/3.3/man7/evp/
 */

/** 
 * Take passphrase and salt
 * Use PBKDF2 with 100,000 iterations
 * Produce a 256 bit key for AES encryption 
 */
int derive_key(const char *passphrase, unsigned char *salt, unsigned char *key) {
    if (PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase),
                          salt, SALT_LEN,
                          100000,
                          EVP_sha256(),
                          KEY_LEN, key) != 1) {
        fprintf(stderr, "Key derivation failed\n");
        return -1;
    }
    return 0;
}

/** 
 * Use AES-256-GCM
 * Generate random IV for each encryption
 * Return [IV][Encrypted Data][Authentication Tag]
 * Tag ensures data hasn't been tampered with
 */
int encrypt_data(unsigned char *plaintext, int plaintext_len, 
                 unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];

    if (RAND_bytes(iv, IV_LEN) != 1) return -1;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Write header and IV
    memcpy(ciphertext, ENC_HEADER, ENC_HEADER_LEN);
    memcpy(ciphertext + ENC_HEADER_LEN, iv, IV_LEN);

    // Encrypt data
    if (EVP_EncryptUpdate(ctx, ciphertext + ENC_HEADER_LEN + IV_LEN, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ENC_HEADER_LEN + IV_LEN + ciphertext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    memcpy(ciphertext + ENC_HEADER_LEN + IV_LEN + ciphertext_len, tag, TAG_LEN);
    EVP_CIPHER_CTX_free(ctx);

    return ENC_HEADER_LEN + IV_LEN + ciphertext_len + TAG_LEN;
}

/** 
 * Get IV and tag from encrypted data 
 * Decrypt and verify authenticy 
 * Return -1 if data was modified 
 */
int decrypt_data(unsigned char *ciphertext, int ciphertext_len,
                 unsigned char *key, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];

    fprintf(stderr, "HEADER CHECK: Got '%.*s'\n", ENC_HEADER_LEN, ciphertext);
    for (int i = 0; i < ENC_HEADER_LEN; i++) {
        fprintf(stderr, "%02x ", ciphertext[i]);
    }
    fprintf(stderr, "\n");


    if (ciphertext_len < ENC_HEADER_LEN + IV_LEN + TAG_LEN) {
        fprintf(stderr, "Ciphertext too short\n");
        return -1;
    }

    fprintf(stderr, "HEADER CHECK: Got '%.*s'\n", ENC_HEADER_LEN, ciphertext);
    for (int i = 0; i < ENC_HEADER_LEN; i++) {
        fprintf(stderr, "%02x ", ciphertext[i]);
    }
    fprintf(stderr, "\n");


    if (memcmp(ciphertext, ENC_HEADER, ENC_HEADER_LEN) != 0) {
        fprintf(stderr, "File is not encrypted — passthrough\n"); // Not encrypted — tell caller to pass data through
        return -2;
    }

    // Extract IV from beginning of ciphertext
    memcpy(iv, ciphertext + ENC_HEADER_LEN, IV_LEN);
    
    // Extract tag from end of ciphertext
    memcpy(tag, ciphertext + ciphertext_len - TAG_LEN, TAG_LEN);
    
    // Actual ciphertext is between IV and tag
    int actual_ciphertext_len = ciphertext_len - ENC_HEADER_LEN - IV_LEN - TAG_LEN;
    
    // Create and initialize context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Failed to create cipher context\n");
        return -1;
    }
    
    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) {
        fprintf(stderr, "Failed to set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Initialize key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        fprintf(stderr, "Failed to set key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Decrypt the data
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + ENC_HEADER_LEN + IV_LEN, actual_ciphertext_len) != 1) {
        fprintf(stderr, "Failed to decrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    
    // Set expected tag value
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1) {
        fprintf(stderr, "Failed to set tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Finalize decryption and verify tag
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret > 0) {
        // Success: tag verified
        plaintext_len += len;
        return plaintext_len;
    } else {
        fprintf(stderr, "Authentication failed - data may be corrupted or tampered\n");
        return -1;
    }
}

////////////////// MAIN FUNCTION /////////////////

int main(int argc, char *argv[])
{
    printf(">>> DEBUG >>> COMPILED VERSION: passthrough test active herro <<<\n");

    MirData m_data;
    char passphrase[PATH_MAX];
 
    umask(0);
    if (argc < 3) {
        mir_usage();    
    } 

    // Get passphrase from user to be used to derive an encryption key
    printf("Please enter passphrase: ");
    scanf("%s", passphrase);

    fprintf(stderr, "DEBUG: Got passphrase\n"); //REMOVE


    // Get full path to mirror directory
    if (!(m_data.mir_dir = realpath(argv[argc-1], NULL))) {
        perror("realpath");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "DEBUG: Got mirror dir: %s\n", m_data.mir_dir); //REMOVE



    // Check if salt file exists, if not create one
    char salt_path[PATH_MAX];
    snprintf(salt_path, PATH_MAX, "%s/.salt", m_data.mir_dir);
    
    FILE *salt_file = fopen(salt_path, "rb");
    if (salt_file) {
        // Read existing salt
        if (fread(m_data.salt, 1, SALT_LEN, salt_file) != SALT_LEN) {
            fprintf(stderr, "Failed to read salt file\n");
            fclose(salt_file);
            exit(EXIT_FAILURE);
        }
        fclose(salt_file);
    } else {
        // Generate new salt
        if (RAND_bytes(m_data.salt, SALT_LEN) != 1) {
            fprintf(stderr, "Failed to generate salt\n");
            exit(EXIT_FAILURE);
        }
        
        // Save salt to file
        salt_file = fopen(salt_path, "wb");
        if (!salt_file || fwrite(m_data.salt, 1, SALT_LEN, salt_file) != SALT_LEN) {
            fprintf(stderr, "Failed to save salt\n");
            if (salt_file) fclose(salt_file);
            exit(EXIT_FAILURE);
        }
        fclose(salt_file);
        printf("Created new salt file\n");
    }

     // Remove newline from passphrase
    passphrase[strcspn(passphrase, "\n")] = '\0';

    // Derive encryption key from passphrase
    if (derive_key(passphrase, m_data.salt, m_data.key) != 0) {
        fprintf(stderr, "Failed to derive encryption key\n");
        exit(EXIT_FAILURE);
    }

    // Clear passphrase from memory
    memset(passphrase, 0, sizeof(passphrase));
    
    printf("Encryption initialized successfully\n");

    // Removes the mirror directory from argc/argv since fuse_main only takes mountpoint
    argv[argc-1] = NULL;
    argc--;

    int ret =  fuse_main(argc, argv, &xmp_oper, &m_data);

    // Clear data
    memset(m_data.key, 0, KEY_LEN);
    free(m_data.mir_dir);
    
    return ret;
}
