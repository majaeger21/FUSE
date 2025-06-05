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
#define IV_LEN 16

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include "mirror_fs.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

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

#define MAX_PW_LEN 256
unsigned char key[SHA256_DIGEST_LENGTH]; // GLOBAL KEY VAR

//////////////////// FUSE OPERATIONS ////////////////////

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    fprintf(stderr, "DEBUG: getattr called for %s -> %s\n", path, fpath);
    fflush(stderr);

    res = lstat(fpath, stbuf);
    if (res == -1) {
        return -errno;
    }
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
    int fd, res, enc_len;
    char fpath[PATH_MAX];
    mir_path(fpath, path);

    if (size != 0) {
        unsigned char *plaintext = NULL;
        size_t plain_len = 0;
        int fd, enc_len;

        int status = read_and_decrypt(fpath, &plaintext, &plain_len);
        if (status < 0) return status;

        if (size > plain_len) size = plain_len;  // clamp size to existing data

        unsigned char *new_plain = malloc(size);
        if (!new_plain) {
            free(plaintext);
            return -ENOMEM;
        }
        memcpy(new_plain, plaintext, size);
        free(plaintext);

        unsigned char *ciphertext = malloc(size + 1024); // padding for encryption
        if (!ciphertext) {
            free(new_plain);
            return -ENOMEM;
        }

        enc_len = encrypt_data(new_plain, size, ciphertext);
        free(new_plain);
        if (enc_len < 0) {
            free(ciphertext);
            return -EIO;
        }

        fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd == -1) {
            free(ciphertext);
            return -errno;
        }

        int res = write(fd, ciphertext, enc_len);
        close(fd);
        free(ciphertext);

        if (res != enc_len) return -EIO;

        return 0;
    }

    unsigned char dummy[1] = {0}; // empty plaintext
    unsigned char ciphertext[ENC_HEADER_LEN + IV_LEN + 128]; // just enough for header, IV, padding

    enc_len = encrypt_data(dummy, 0, ciphertext);
    if (enc_len < 0)
        return -EIO;

    fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1)
        return -errno;

    res = write(fd, ciphertext, enc_len);
    close(fd);

    if (res != enc_len)
        return -EIO;

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

    fprintf(stderr, "DEBUG: open called for %s -> %s\n", path, fpath);
    fflush(stderr);

    res = open(fpath, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static int read_and_decrypt(const char *fpath, unsigned char **plaintext_out, size_t *p_length_out) 
{
    int fd, decrypted_len;

    fd = open(fpath, O_RDONLY);
    if (fd == -1) 
        return -errno;

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return -errno;
    }

    unsigned char *file_data = malloc(st.st_size);
    if (!file_data) {
        close(fd);
        return -ENOMEM;
    }

    ssize_t rlen = read(fd, file_data, st.st_size);
    if (rlen!= st.st_size) {
        free(file_data);
        close(fd);
        return -errno;
    }
    close(fd);

    unsigned char *plaintext = malloc(st.st_size);  // ciphertext is always ≥ plaintext
    if (!plaintext) {
        free(file_data);
        return -ENOMEM;
    }

    decrypted_len = decrypt_data(file_data, rlen, plaintext);

    if (decrypted_len == -2) {
        // Plaintext passthrough - using original file_data as plaintext
        *plaintext_out = file_data;
        *p_length_out = st.st_size;
        free(plaintext);  
        return 1; // Special return value to indicate passthrough
    }

    free(file_data);  // No longer needed

    if (decrypted_len < 0) {
        free(plaintext);
        return -EIO;
    }

    *plaintext_out = plaintext;
    *p_length_out = decrypted_len;
    return 0;  // Success
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    char fpath[PATH_MAX];
    mir_path(fpath, path);
    (void) fi;

    unsigned char *plaintext = NULL;
    size_t plain_length = 0;

    int status = read_and_decrypt(fpath, &plaintext, &plain_length);
    if (status < 0)
        return status;

    // Bounds check
    if (offset < plain_length) {
        if (offset + size > plain_length)
            size = plain_length - offset;
        memcpy(buf, plaintext + offset, size);
    } else {
        size = 0;
    }

    if (status == 1) free(plaintext);  // Was passthrough (file_data)
    else free(plaintext);              // Was decrypted

    return size;
}

static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    int fd, res, enc_len;
    char fpath[PATH_MAX];
    mir_path(fpath, path);

    unsigned char *existing_plain = NULL;
    size_t existing_length = 0;
    unsigned char *new_plaintext;
    size_t plain_length = 0;

    // if appending
    if (offset > 0) {
        int status = read_and_decrypt(fpath, &existing_plain, &existing_length);
        if (status < 0) 
            return status;

        // get the combined (old and new) text into new_plaintext
        plain_length = existing_length + size; // total length
        new_plaintext = malloc(plain_length);
        if (!new_plaintext) {
            free(existing_plain);
            return -ENOMEM;
        }
        memcpy(new_plaintext, existing_plain, existing_length); // copies in old contents
        memcpy(new_plaintext + existing_length, buf, size);  // copies in the content we are appending
        free(existing_plain);

    // if overwriting, just set new_plaintext to the buffer
    } else {
        plain_length = size;
        new_plaintext = malloc(size);
        if (!new_plaintext) return -ENOMEM;
        memcpy(new_plaintext, buf, size);
    }

    unsigned char *ciphertext = malloc(plain_length + 1024); // Padding for header/IV/tag
    if (!ciphertext) {
        free(new_plaintext);
        return -ENOMEM;
    }

    enc_len = encrypt_data(new_plaintext, plain_length, ciphertext);
    free(new_plaintext);
    if (enc_len < 0) {
        free(ciphertext);
        return -EIO;
    }

    fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        free(ciphertext);
        return -errno;
    }

    res = write(fd, ciphertext, enc_len);
    close(fd);
    free(ciphertext);

    if (res != enc_len) return -EIO;
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

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
                        size_t size, int flags)
{
    int res = lsetxattr(path, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
                    size_t size)
{
    int res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
    int res = llistxattr(path, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
    int res = lremovexattr(path, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

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
#ifdef HAVE_SETXATTR
    .setxattr	= xmp_setxattr,
    .getxattr	= xmp_getxattr,
    .listxattr	= xmp_listxattr,
    .removexattr= xmp_removexattr,
#endif
};

void mir_usage() {
    fprintf(
        stderr,
        "usage: mirror_fs [FUSE options] <mountpoint> <directory to mirror>\n"
    );
    exit(EXIT_FAILURE);    
}

/* Append path to mirror directory */
void mir_path(char fpath[PATH_MAX], const char *path) {
    struct fuse_context *ctx = fuse_get_context();
    MirData *m_data = (MirData *) ctx->private_data;
    snprintf(fpath, PATH_MAX, "%s/%s", m_data->mir_dir, path);
}

//////////////////// ENCRYPT/DECRYPT OPERATIONS ////////////////////


int encrypt_data(const unsigned char *plaintext, int plaintext_len, 
                 unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    unsigned char iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len, ciphertext_len;

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Write header and IV to output
    memcpy(ciphertext, ENC_HEADER, ENC_HEADER_LEN);
    memcpy(ciphertext + ENC_HEADER_LEN, iv, IV_LEN);

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext + ENC_HEADER_LEN + IV_LEN, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize encryption (handles padding)
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ENC_HEADER_LEN + IV_LEN + ciphertext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ENC_HEADER_LEN + IV_LEN + ciphertext_len;
}

int decrypt_data(const unsigned char *ciphertext, int ciphertext_len,
                 unsigned char *plaintext) {
    if (ciphertext_len < ENC_HEADER_LEN + IV_LEN) {
        return -2;
    }

    // not encrypted — plaintext passthrough
    if (memcmp(ciphertext, ENC_HEADER, ENC_HEADER_LEN) != 0) {
        return -2; 
    }

    const unsigned char *iv = ciphertext + ENC_HEADER_LEN;
    const unsigned char *ct = iv + IV_LEN;
    int ct_len = ciphertext_len - ENC_HEADER_LEN - IV_LEN;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len, plaintext_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ct, ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // handle padding
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    }

    return -1;  // Decryption failed 
}

void  derive_key(const char *passphrase) {
    EVP_MD_CTX mdctx;
    if (!passphrase) {
        fprintf(stderr, "Passphrase must not be NULL\n");
        exit(EXIT_FAILURE);
    }
    if (strlen(passphrase) == 0) {
        fprintf(stderr, "Passphrase must be greater than ZERO characters\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestInit(&mdctx, EVP_sha256()) == 0) {
        fprintf(stderr, "Failed to set up digest context for SHA256\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestUpdate(&mdctx, passphrase, strlen(passphrase)) == 0) {
        fprintf(stderr, "Failed to hash passphrase data\n");
        exit(EXIT_FAILURE);
    }
    unsigned int bytes;
    if (EVP_DigestFinal(&mdctx, key, &bytes) == 0) {
        fprintf(stderr, "Failed to retreive digest value\n");
        exit(EXIT_FAILURE);
    }
    if (bytes != 32) {
        fprintf(stderr, "Key size is %d bits - should be 256 bits\n", bytes*8);
        exit(EXIT_FAILURE);
    }
}

//////////////////// MAIN FUNCTION ////////////////////

int main(int argc, char *argv[])
{
    MirData m_data;
    char passphrase[MAX_PW_LEN];
 
    umask(0);
    if (argc < 3) {
        mir_usage();    
    } 

    // Get passphrase from user to be used to derive an encryption key
    printf("Passphrase: ");
    if (fgets(passphrase, MAX_PW_LEN, stdin) == NULL && ferror(stdin)) {
        perror("fgets");
        exit(EXIT_FAILURE);
    } 
    passphrase[strcspn(passphrase, "\n")] = '\0';
    derive_key(passphrase);
    memset(passphrase, 0, sizeof(passphrase));

    // Get full path to mirror directory
    if (!(m_data.mir_dir = realpath(argv[argc-1], NULL))) {
        perror("realpath");
        exit(EXIT_FAILURE);
    } 

    // Removes the mirror directory from argc/argv since fuse_main only takes mountpoint
    argv[argc-1] = NULL;
    argc--;
    
    int ret =  fuse_main(argc, argv, &xmp_oper, &m_data);
    free(m_data.mir_dir);
    return ret;
}