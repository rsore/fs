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
    const char *root = "fs_example_copy_move";

    if (fs_exists(root)) (void)fs_delete_tree(root);
    (void)fs_make_directory(root, FS_OP_REUSE_DIRS);

    char file_a[256];
    char file_b[256];
    char file_c[256];

    fs_ex_path(file_a, sizeof(file_a), root, "a.txt");
    fs_ex_path(file_b, sizeof(file_b), root, "b.txt");
    fs_ex_path(file_c, sizeof(file_c), root, "c.txt");

    (void)fs_write_file(file_a, "ONE\n", 4);
    (void)fs_copy_file(file_a, file_b, FS_OP_NONE);

    if (fs_copy_file(file_a, file_b, FS_OP_NONE) != FS_ERROR_FILE_ALREADY_EXISTS) {
        if (fs_exists(root)) (void)fs_delete_tree(root);
        return 1;
    }

    (void)fs_write_file(file_a, "TWO\n", 4);
    if (fs_copy_file(file_a, file_b, FS_OP_OVERWRITE) != FS_ERROR_NONE) {
        if (fs_exists(root)) (void)fs_delete_tree(root);
        return 2;
    }

    if (fs_move_file(file_b, file_c, FS_OP_NONE) != FS_ERROR_NONE) {
        if (fs_exists(root)) (void)fs_delete_tree(root);
        return 3;
    }

    printf("moved to: %s\n", file_c);

    if (fs_exists(root)) (void)fs_delete_tree(root);
    return 0;
}

