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
    const char *root = "fs_example_delete";

    if (fs_exists(root)) (void)fs_delete_tree(root);
    (void)fs_make_directory(root, FS_OP_REUSE_DIRS);

    char file_a[256];
    fs_ex_path(file_a, sizeof(file_a), root, "a.txt");

    (void)fs_write_file(file_a, "DEL\n", 4);

    Fs_Error err = fs_delete_tree(root);
    if (err != FS_ERROR_NONE) {
        printf("delete failed: %s\n", fs_strerror(err));
        return 1;
    }

    printf("deleted: %s\n", root);
    return 0;
}
