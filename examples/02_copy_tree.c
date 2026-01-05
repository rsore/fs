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

static void
print_tree(const char *root)
{
    FsWalker w = {0};
    if (!fs_walker_init(&w, root)) {
        return;
    }

    const FsFileInfo *fi = NULL;
    while ((fi = fs_walker_next(&w)) != NULL) {
        printf("%s%s\n", fi->path, fi->is_dir ? " [dir]" : "");
    }

    fs_walker_free(&w);
}

int
main(void)
{
    const char *src = "fs_example_src";
    const char *dst = "fs_example_dst";

    if (fs_exists(src)) (void)fs_delete_tree(src);
    if (fs_exists(dst)) (void)fs_delete_tree(dst);

    (void)fs_make_directory(src, FS_OP_REUSE_DIRS);

    char sub_dir[256];
    char file_a[256];
    char file_b[256];

    fs_ex_path(sub_dir, sizeof(sub_dir), src, "sub");
    fs_ex_path(file_a, sizeof(file_a), src, "root.txt");
    fs_ex_path(file_b, sizeof(file_b), sub_dir, "leaf.txt");

    (void)fs_make_directory(sub_dir, FS_OP_NONE);
    (void)fs_write_file(file_a, "ROOT\n", 5);
    (void)fs_write_file(file_b, "LEAF\n", 5);

    if (fs_copy_tree(src, dst, FS_OP_REUSE_DIRS) != FS_ERROR_NONE) {
        if (fs_exists(src)) (void)fs_delete_tree(src);
        return 1;
    }

    print_tree(dst);

    if (fs_exists(src)) (void)fs_delete_tree(src);
    if (fs_exists(dst)) (void)fs_delete_tree(dst);
    return 0;
}



