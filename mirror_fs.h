#ifndef MIRROR_FS_H
#define MIRROR_FS_H

#include <limits.h>

typedef struct {
    char *mir_dir;
} MirData;

void mir_usage();
void mir_path(char fpath[PATH_MAX], const char *path);

#endif
