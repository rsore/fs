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
    const char *root = "fs_example";

    if (fs_exists(root)) (void)fs_delete_tree(root);
    (void)fs_make_directory(root, FS_OP_REUSE_DIRS);

    char file_path[256];
    fs_ex_path(file_path, sizeof(file_path), root, "hello.txt");

    const char *msg = "Hello from fs.h\n";
    if (fs_write_file(file_path, msg, strlen(msg)) != FS_ERROR_NONE) {
        return 1;
    }

    void *data = NULL;
    size_t size = 0;
    if (fs_read_file(file_path, &data, &size) != FS_ERROR_NONE) {
        FS_FREE(data);
        return 2;
    }

    fwrite(data, 1, size, stdout);
    FS_FREE(data);

    if (fs_exists(root)) (void)fs_delete_tree(root);
    return 0;
}

