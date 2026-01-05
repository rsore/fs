#include <stdio.h>
#include <string.h>

#define FS_USE_SIMPLE_LOGGER
#define FS_IMPLEMENTATION
#include "../fs.h"

#if defined(_WIN32) && !defined(FS_WIN32_USE_FORWARDSLASH_SEPARATORS)
#define FS_EX_PATH_SEP "\\"
#else
#define FS_EX_PATH_SEP "/"
#endif

static void
fs_ex_path(char *buf, size_t cap, const char *a, const char *b)
{
    snprintf(buf, cap, "%s" FS_EX_PATH_SEP "%s", a, b);
}

int
main(void)
{
    const char *root = "fs_example_crc";

    if (fs_exists(root)) (void)fs_delete_tree(root);
    (void)fs_make_directory(root, FS_OP_REUSE_DIRS);

    char file_path[256];
    fs_ex_path(file_path, sizeof(file_path), root, "crc.txt");

    const char *msg = "123456789";
    if (fs_write_file(file_path, msg, strlen(msg)) != FS_ERROR_NONE) {
        if (fs_exists(root)) (void)fs_delete_tree(root);
        return 1;
    }

    uint32_t crc = 0;
    if (fs_crc32_file(file_path, &crc) != FS_ERROR_NONE) {
        if (fs_exists(root)) (void)fs_delete_tree(root);
        return 2;
    }

    printf("crc32: 0x%08X\n", crc);

    if (fs_exists(root)) (void)fs_delete_tree(root);
    return 0;
}

