#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#define FS_IMPLEMENTATION
#include "../fs.h"

#include "minitest.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#if defined(_WIN32) && !defined(FS_WIN32_USE_FORWARDSLASH_SEPARATORS)
#define FS_TEST_PATH_SEP "\\"
#else
#define FS_TEST_PATH_SEP "/"
#endif

static void
fs_test_path(char *buf, size_t cap, const char *a, const char *b)
{
    snprintf(buf, cap, "%s" FS_TEST_PATH_SEP "%s", a, b);
}

static void
fs_test_path3(char *buf, size_t cap, const char *a, const char *b, const char *c)
{
    snprintf(buf, cap, "%s" FS_TEST_PATH_SEP "%s" FS_TEST_PATH_SEP "%s", a, b, c);
}

static void
fs_test_reset_root(const char *root)
{
    (void)fs_delete_tree(root);
    (void)fs_make_directory(root, FS_OP_REUSE_DIRS);
}

MT_DEFINE_TEST(file_write_read)
{
    char file_path[256];
    const char *msg = "hello";
    void *data = NULL;
    size_t size = 0;
    char small_buf[4];
    size_t bytes_read = 0;
    Fs_FileInfo info = FS_INTERNAL_ZERO_INIT;
    const char *root = "fs_test_out";

    fs_test_reset_root(root);
    fs_test_path(file_path, sizeof(file_path), root, "a.txt");

    MT_ASSERT_THAT(fs_write_file(file_path, msg, strlen(msg)) == FS_ERROR_NONE);

    MT_ASSERT_THAT(fs_read_file(file_path, &data, &size) == FS_ERROR_NONE);
    MT_CHECK_THAT(size == strlen(msg));
    MT_CHECK_THAT(memcmp(data, msg, size) == 0);
    FS_FREE(data);

    memset(small_buf, 0, sizeof(small_buf));
    MT_ASSERT_THAT(fs_read_file_into(file_path, small_buf, 3, &bytes_read) == FS_ERROR_NONE);
    MT_CHECK_THAT(bytes_read == 3);
    MT_CHECK_THAT(memcmp(small_buf, "hel", 3) == 0);

    MT_ASSERT_THAT(fs_get_file_info(file_path, &info) == FS_ERROR_NONE);
    MT_CHECK_THAT(info.is_dir == 0);
    MT_CHECK_THAT(info.size == (uint64_t)strlen(msg));
    MT_CHECK_THAT(info.path != NULL);
    fs_file_info_free(&info);

    MT_CHECK_THAT(fs_exists(file_path));
    MT_CHECK_THAT(fs_is_file(file_path));
    MT_CHECK_THAT(!fs_is_dir(file_path));
}

MT_DEFINE_TEST(empty_file_read)
{
    char file_path[256];
    void *data = NULL;
    size_t size = 1;
    const char *root = "fs_test_out";

    fs_test_reset_root(root);
    fs_test_path(file_path, sizeof(file_path), root, "empty.bin");

    MT_ASSERT_THAT(fs_write_file(file_path, "", 0) == FS_ERROR_NONE);

    MT_ASSERT_THAT(fs_read_file(file_path, &data, &size) == FS_ERROR_NONE);
    MT_CHECK_THAT(size == 0);
    FS_FREE(data);
}

MT_DEFINE_TEST(missing_file_errors)
{
    char file_path[256];
    void *data = NULL;
    size_t size = 0;
    Fs_Error err = FS_ERROR_NONE;
    Fs_FileInfo info = FS_INTERNAL_ZERO_INIT;
    const char *root = "fs_test_out";

    fs_test_reset_root(root);
    fs_test_path(file_path, sizeof(file_path), root, "missing.txt");

    err = fs_read_file(file_path, &data, &size);
    MT_CHECK_THAT(err == FS_ERROR_FILE_NOT_FOUND);
    FS_FREE(data);

    err = fs_delete_file(file_path);
    MT_CHECK_THAT(err == FS_ERROR_FILE_NOT_FOUND);

    err = fs_get_file_info(file_path, &info);
    MT_CHECK_THAT(err == FS_ERROR_FILE_NOT_FOUND);
    fs_file_info_free(&info);
}

MT_DEFINE_TEST(make_directory_errors)
{
    char nested[256];
    char sub[256];
    Fs_Error err = FS_ERROR_NONE;
    const char *root = "fs_test_out";

    fs_test_reset_root(root);

    snprintf(nested, sizeof(nested), "%s" FS_TEST_PATH_SEP "sub" FS_TEST_PATH_SEP "child", root);
    err = fs_make_directory(nested, FS_OP_NONE);
    MT_CHECK_THAT(err == FS_ERROR_FILE_NOT_FOUND);

    fs_test_path(sub, sizeof(sub), root, "sub");

    MT_ASSERT_THAT(fs_make_directory(sub, FS_OP_NONE) == FS_ERROR_NONE);
    MT_CHECK_THAT(fs_make_directory(sub, FS_OP_REUSE_DIRS) == FS_ERROR_NONE);
    MT_CHECK_THAT(fs_make_directory(sub, FS_OP_NONE) == FS_ERROR_DIRECTORY_ALREADY_EXISTS);
}

MT_DEFINE_TEST(copy_move_file)
{
    char file_a[256];
    char file_b[256];
    char file_c[256];
    Fs_Error err = FS_ERROR_NONE;
    void *data = NULL;
    size_t size = 0;
    const char *root = "fs_test_out";

    fs_test_reset_root(root);

    fs_test_path(file_a, sizeof(file_a), root, "a.txt");
    fs_test_path(file_b, sizeof(file_b), root, "b.txt");
    fs_test_path(file_c, sizeof(file_c), root, "c.txt");

    MT_ASSERT_THAT(fs_write_file(file_a, "A", 1) == FS_ERROR_NONE);
    MT_ASSERT_THAT(fs_copy_file(file_a, file_b, FS_OP_NONE) == FS_ERROR_NONE);

    err = fs_copy_file(file_a, file_b, FS_OP_NONE);
    MT_CHECK_THAT(err == FS_ERROR_FILE_ALREADY_EXISTS);

    MT_ASSERT_THAT(fs_write_file(file_a, "NEW", 3) == FS_ERROR_NONE);
    MT_ASSERT_THAT(fs_copy_file(file_a, file_b, FS_OP_OVERWRITE) == FS_ERROR_NONE);

    MT_ASSERT_THAT(fs_read_file(file_b, &data, &size) == FS_ERROR_NONE);
    MT_CHECK_THAT(size == 3);
    MT_CHECK_THAT(memcmp(data, "NEW", 3) == 0);
    FS_FREE(data);

    MT_ASSERT_THAT(fs_move_file(file_b, file_c, FS_OP_NONE) == FS_ERROR_NONE);
    MT_CHECK_THAT(!fs_exists(file_b));
    MT_CHECK_THAT(fs_is_file(file_c));
}

MT_DEFINE_TEST(copy_move_tree)
{
    char src_dir[256];
    char dst_dir[256];
    char mv_dir[256];
    char sub_dir[256];
    char src_file[256];
    char sub_file[256];
    char dst_leaf[256];
    const char *root = "fs_test_out";

    fs_test_reset_root(root);

    fs_test_path(src_dir, sizeof(src_dir), root, "src");
    fs_test_path(dst_dir, sizeof(dst_dir), root, "dst");
    fs_test_path(mv_dir, sizeof(mv_dir), root, "moved");
    fs_test_path(sub_dir, sizeof(sub_dir), src_dir, "sub");
    fs_test_path(src_file, sizeof(src_file), src_dir, "root.txt");
    fs_test_path(sub_file, sizeof(sub_file), sub_dir, "leaf.txt");

    MT_ASSERT_THAT(fs_make_directory(src_dir, FS_OP_NONE) == FS_ERROR_NONE);
    MT_ASSERT_THAT(fs_make_directory(sub_dir, FS_OP_NONE) == FS_ERROR_NONE);

    MT_ASSERT_THAT(fs_write_file(src_file, "ROOT", 4) == FS_ERROR_NONE);
    MT_ASSERT_THAT(fs_write_file(sub_file, "LEAF", 4) == FS_ERROR_NONE);

    MT_ASSERT_THAT(fs_copy_tree(src_dir, dst_dir, FS_OP_REUSE_DIRS) == FS_ERROR_NONE);

    fs_test_path3(dst_leaf, sizeof(dst_leaf), dst_dir, "sub", "leaf.txt");
    MT_CHECK_THAT(fs_is_file(dst_leaf));

    MT_ASSERT_THAT(fs_move_tree(src_dir, mv_dir, FS_OP_REUSE_DIRS) == FS_ERROR_NONE);
    MT_CHECK_THAT(!fs_exists(src_dir));
    MT_CHECK_THAT(fs_is_dir(mv_dir));
}

MT_DEFINE_TEST(walker_traversal)
{
    char sub_dir[256];
    char file_a[256];
    char file_b[256];
    Fs_Walker w = FS_INTERNAL_ZERO_INIT;
    int seen_root = 0;
    int file_count = 0;
    int dir_count = 0;
    int total = 0;
    const Fs_FileInfo *fi = NULL;
    const char *root = "fs_test_out";

    fs_test_reset_root(root);

    fs_test_path(sub_dir, sizeof(sub_dir), root, "sub");
    fs_test_path(file_a, sizeof(file_a), root, "a.txt");
    fs_test_path(file_b, sizeof(file_b), sub_dir, "b.txt");

    MT_ASSERT_THAT(fs_make_directory(sub_dir, FS_OP_NONE) == FS_ERROR_NONE);
    MT_ASSERT_THAT(fs_write_file(file_a, "A", 1) == FS_ERROR_NONE);
    MT_ASSERT_THAT(fs_write_file(file_b, "B", 1) == FS_ERROR_NONE);

    MT_ASSERT_THAT(fs_walker_init(&w, root));

    while ((fi = fs_walker_next(&w)) != NULL) {
        if (total == 0) {
            MT_CHECK_THAT(strcmp(fi->path, root) == 0);
        }
        if (fi->is_dir) {
            dir_count++;
        } else {
            file_count++;
        }
        if (strcmp(fi->path, root) == 0) {
            seen_root = 1;
        }
        total++;
    }

    MT_CHECK_THAT(seen_root);
    MT_CHECK_THAT(total >= 4);
    MT_CHECK_THAT(file_count >= 2);
    MT_CHECK_THAT(dir_count >= 1);

    fs_walker_free(&w);
}

MT_DEFINE_TEST(walker_skips_symlinked_dir)
{
    char real_dir[256];
    char real_file[256];
    char link_path[256];
    char link_file[256];
    int link_ok = 0;
    const char *root = "fs_test_out";

    fs_test_reset_root(root);

    fs_test_path(real_dir, sizeof(real_dir), root, "real");
    fs_test_path(real_file, sizeof(real_file), real_dir, "a.txt");
    fs_test_path(link_path, sizeof(link_path), root, "link");
    fs_test_path(link_file, sizeof(link_file), link_path, "a.txt");

    MT_ASSERT_THAT(fs_make_directory(real_dir, FS_OP_NONE) == FS_ERROR_NONE);
    MT_ASSERT_THAT(fs_write_file(real_file, "A", 1) == FS_ERROR_NONE);

#ifdef _WIN32
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif
    {
        DWORD flags = SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
        link_ok = CreateSymbolicLinkA(link_path, real_dir, flags) ? 1 : 0;
    }
#else
    link_ok = (symlink(real_dir, link_path) == 0) ? 1 : 0;
#endif

    if (!link_ok) {
        return; // Symlinks not available or not permitted on this platform.
    }

    {
        Fs_Walker w = FS_INTERNAL_ZERO_INIT;
        const Fs_FileInfo *fi = NULL;
        int saw_link = 0;
        int saw_link_file = 0;

        MT_ASSERT_THAT(fs_walker_init(&w, root));

        while ((fi = fs_walker_next(&w)) != NULL) {
            if (strcmp(fi->path, link_path) == 0) {
                saw_link = 1;
            }
            if (strcmp(fi->path, link_file) == 0) {
                saw_link_file = 1;
            }
        }

        fs_walker_free(&w);

        MT_CHECK_THAT(saw_link);
        MT_CHECK_THAT(!saw_link_file);
    }
}

MT_DEFINE_TEST(crc32_matches_known_value)
{
    char file_path[256];
    const char *msg = "123456789";
    uint32_t crc = 0;
    const char *root = "fs_test_out";

    fs_test_reset_root(root);
    fs_test_path(file_path, sizeof(file_path), root, "crc.txt");

    MT_ASSERT_THAT(fs_write_file(file_path, msg, strlen(msg)) == FS_ERROR_NONE);

    MT_ASSERT_THAT(fs_crc32_file(file_path, &crc) == FS_ERROR_NONE);
    MT_CHECK_THAT(crc == 0xCBF43926u);
}

int
main(void)
{
    MT_INIT();

    MT_RUN_TEST(file_write_read);
    MT_RUN_TEST(empty_file_read);
    MT_RUN_TEST(missing_file_errors);
    MT_RUN_TEST(make_directory_errors);
    MT_RUN_TEST(copy_move_file);
    MT_RUN_TEST(copy_move_tree);
    MT_RUN_TEST(walker_traversal);
    MT_RUN_TEST(walker_skips_symlinked_dir);
    MT_RUN_TEST(crc32_matches_known_value);

    MT_PRINT_SUMMARY();

    (void)fs_delete_tree("fs_test_out");
    return MT_EXIT_CODE;
}
