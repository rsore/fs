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
    const char *root = "fs_example_info";

    if (fs_exists(root)) (void)fs_delete_tree(root);
    (void)fs_make_directory(root, FS_OP_REUSE_DIRS);

    char file_path[256];
    fs_ex_path(file_path, sizeof(file_path), root, "info.txt");

    (void)fs_write_file(file_path, "INFO\n", 5);

    Fs_FileInfo info = {0};
    if (fs_get_file_info(file_path, &info) != FS_ERROR_NONE) {
        if (fs_exists(root)) (void)fs_delete_tree(root);
        return 1;
    }

    printf("path: %s\n", info.path ? info.path : "(null)");
    printf("is_dir: %d\n", info.is_dir);
    printf("is_symlink: %d\n", info.is_symlink);
    printf("size: %llu\n", (unsigned long long)info.size);
    printf("mtime_sec: %llu\n", (unsigned long long)info.mtime_sec);
    printf("mode: 0x%X\n", info.mode);

    fs_file_info_free(&info);
    if (fs_exists(root)) (void)fs_delete_tree(root);
    return 0;
}

