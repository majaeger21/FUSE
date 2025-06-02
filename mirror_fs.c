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
#define TAG_LEN 16

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include "mirror_fs.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

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


//////////////////// FUSE OPERATIONS ////////////////////

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    fprintf(stderr, "DEBUG: getattr called for %s -> %s\n", path, fpath);
    fflush(stderr);

    res = lstat(fpath, stbuf);
    if (res == -1)
        fprintf(stderr, "DEBUG: lstat failed with errno = %d (%s)\n", errno, strerror(errno));
        fflush(stderr);
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
    int res;
    char fpath[PATH_MAX];

    mir_path(fpath, path);

    res = truncate(fpath, size);
    if (res == -1)
        return -errno;

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

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    int fd, res, decrypted_len;
    char fpath[PATH_MAX];
    mir_path(fpath, path);

    (void) fi;
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

    struct fuse_context *ctx = fuse_get_context();
    MirData *m_data = (MirData *) ctx->private_data;
    unsigned char *key = m_data->key;

    unsigned char *plaintext = malloc(st.st_size);  // ciphertext is always ≥ plaintext
    if (!plaintext) {
        free(file_data);
        return -ENOMEM;
    }

    decrypted_len = decrypt_data(file_data, rlen, key, plaintext);

    res = 0;
    if (decrypted_len == -2) {
        // Plaintext passthrough
        if (offset < st.st_size) {
            if (offset + size > st.st_size)
                size = st.st_size - offset;
            memcpy(buf, file_data + offset, size);
            res = size;
        }
    } else if (decrypted_len >= 0) {
        if (offset < decrypted_len) {
            if (offset + size > decrypted_len)
                size = decrypted_len - offset;
            memcpy(buf, plaintext + offset, size);
            res = size;
        }
    } else {
        res = -EIO;  // Decryption failed
    }

    free(file_data);
    free(plaintext);
    return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    int fd, res, enc_len;
    char fpath[PATH_MAX];
    mir_path(fpath, path);

    struct fuse_context *ctx = fuse_get_context();
    MirData *m_data = (MirData *) ctx->private_data;
    unsigned char *key = m_data->key;

    unsigned char *ciphertext = malloc(size + 1024); // Padding for header/IV/tag
    if (!ciphertext) return -ENOMEM;

    enc_len = encrypt_data((unsigned char *)buf, size, key, ciphertext);
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
                 const unsigned char *key, unsigned char *ciphertext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    unsigned char iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) return -1;

    int len, ciphertext_len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) return -1;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) return -1;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) return -1;

    // Write header and IV
    memcpy(ciphertext, ENC_HEADER, ENC_HEADER_LEN);
    memcpy(ciphertext + ENC_HEADER_LEN, iv, IV_LEN);

    if (EVP_EncryptUpdate(ctx, ciphertext + ENC_HEADER_LEN + IV_LEN, &len, plaintext, plaintext_len) != 1) return -1;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + ENC_HEADER_LEN + IV_LEN + ciphertext_len, &len) != 1) return -1;
    ciphertext_len += len;

    unsigned char tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) return -1;
    memcpy(ciphertext + ENC_HEADER_LEN + IV_LEN + ciphertext_len, tag, TAG_LEN);

    EVP_CIPHER_CTX_free(ctx);
    return ENC_HEADER_LEN + IV_LEN + ciphertext_len + TAG_LEN;
}

int decrypt_data(const unsigned char *ciphertext, int ciphertext_len,
                 const unsigned char *key, unsigned char *plaintext) {
    
    if (ciphertext_len < ENC_HEADER_LEN + IV_LEN + TAG_LEN) {
        return -2;
    }

    if (memcmp(ciphertext, ENC_HEADER, ENC_HEADER_LEN) != 0) {
        return -2; // Not encrypted — plaintext passthrough
    }

    const unsigned char *iv = ciphertext + ENC_HEADER_LEN;
    const unsigned char *ct = iv + IV_LEN;
    int ct_len = ciphertext_len - ENC_HEADER_LEN - IV_LEN - TAG_LEN;
    const unsigned char *tag = ciphertext + ciphertext_len - TAG_LEN;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len, plaintext_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ct, ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    }

    return -1;
}

int derive_key(const char *passphrase, const unsigned char *salt, unsigned char *key_out) {
    if (PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase),
                          salt, 16,
                          100000,
                          EVP_sha256(),
                          32, key_out) != 1) {
        fprintf(stderr, "Failed to derive encryption key\n");
        return -1;
    }
    return 0;
}

//////////////////// MAIN FUNCTION ////////////////////

int main(int argc, char *argv[])
{
    MirData m_data;
    char passphrase[PATH_MAX];
 
    umask(0);
    if (argc < 3) {
        mir_usage();    
    } 

    // Get passphrase from user to be used to derive an encryption key
    printf("Please enter passphrase: ");
    scanf("%s", passphrase);

    // Get full path to mirror directory
    if (!(m_data.mir_dir = realpath(argv[argc-1], NULL))) {
        perror("realpath");
        exit(EXIT_FAILURE);
    }

    // Salt logic
    unsigned char salt[16];
    char salt_path[PATH_MAX];
    snprintf(salt_path, PATH_MAX, "%s/.salt", m_data.mir_dir);

    FILE *salt_file = fopen(salt_path, "rb");
    if (salt_file) {
        if (fread(salt, 1, 16, salt_file) != 16) {
            fprintf(stderr, "Failed to read salt from file\n");
            fclose(salt_file);
            exit(EXIT_FAILURE);
        }
        fclose(salt_file);
    } else {
        if (RAND_bytes(salt, 16) != 1) {
            fprintf(stderr, "Failed to generate salt\n");
            exit(EXIT_FAILURE);
        }

        salt_file = fopen(salt_path, "wb");
        if (!salt_file || fwrite(salt, 1, 16, salt_file) != 16) {
            fprintf(stderr, "Failed to write salt to file\n");
            if (salt_file) fclose(salt_file);
            exit(EXIT_FAILURE);
        }
        fclose(salt_file);
    }

    if (derive_key(passphrase, salt, m_data.key) != 0) {
        exit(EXIT_FAILURE);
    }

    // Removes the mirror directory from argc/argv since fuse_main only takes mountpoint
    argv[argc-1] = NULL;
    argc--;

    int ret =  fuse_main(argc, argv, &xmp_oper, &m_data);
    free(m_data.mir_dir);
    memset(passphrase, 0, sizeof(passphrase));
    return ret;
}