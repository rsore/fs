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

static void
fs_ex_path3(char *buf, size_t cap, const char *a, const char *b, const char *c)
{
    snprintf(buf, cap, "%s" FS_EX_PATH_SEP "%s" FS_EX_PATH_SEP "%s", a, b, c);
}

int
main(void)
{
    const char *root = "fs_example_walk";

    if (fs_exists(root)) (void)fs_delete_tree(root);
    (void)fs_make_directory(root, FS_OP_REUSE_DIRS);

    char sub_dir[256];
    char file_a[256];
    char file_b[256];

    fs_ex_path(sub_dir, sizeof(sub_dir), root, "sub");
    fs_ex_path(file_a, sizeof(file_a), root, "a.txt");
    fs_ex_path(file_b, sizeof(file_b), sub_dir, "b.txt");

    (void)fs_make_directory(sub_dir, FS_OP_NONE);
    (void)fs_write_file(file_a, "A\n", 2);
    (void)fs_write_file(file_b, "B\n", 2);

    FsWalker w = {0};
    if (!fs_walker_init(&w, root)) {
        if (fs_exists(root)) (void)fs_delete_tree(root);
        return 1;
    }

    int dir_count = 0;
    int file_count = 0;

    const FsFileInfo *fi = NULL;
    while ((fi = fs_walker_next(&w)) != NULL) {
        printf("%s%s\n", fi->path, fi->is_dir ? " [dir]" : "");
        if (fi->is_dir) {
            dir_count++;
        } else {
            file_count++;
        }
    }

    printf("dirs: %d, files: %d\n", dir_count, file_count);

    fs_walker_free(&w);
    if (fs_exists(root)) (void)fs_delete_tree(root);
    return 0;
}

