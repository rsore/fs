#include <stdio.h>
#include <string.h>

#define FS_USE_SIMPLE_LOGGER
#define FS_IMPLEMENTATION
#include "fs.h"

static void
my_log(unsigned int  level,
       const char   *msg,
       void         *user_data)
{
    if (level == FS_LOG_LEVEL_INFO) {
        printf("[INFO] %s\n", msg);
    } else if (level == FS_LOG_LEVEL_ERROR) {
        fprintf(stderr, "[ERROR] %s\n", msg);
    } else if (level == FS_LOG_LEVEL_TRACE) {
        fprintf(stderr, "[TRACE] %s\n", msg);
    }
}

int main(void) {
    const char *root = "fs_demo";
    const char *missing_file = "fs_demo/missing.txt";
    const char *file_a = "fs_demo/a.txt";
    const char *file_b = "fs_demo/b.txt";
    const char *file_c = "fs_demo/c.txt";
    const char *dir_sub = "fs_demo/sub";
    const char *dir_conflict = "fs_demo/conflict";
    const char *tree_copy = "fs_demo_copy";

    // Clean start (silent)
    fs_set_logger(my_log, NULL);
    (void)fs_delete_tree(root);

    // Re-enable logging (simple logger)
    // FS_USE_SIMPLE_LOGGER already wires FS_LOG to stderr.

    // Expected failures
    void *data = NULL;
    size_t size = 0;
    if (fs_read_file(missing_file, &data, &size) == FS_ERROR_NONE) {
        FS_FREE(data);
    }
    (void)fs_delete_file(missing_file);

    // Create root (success)
    (void)fs_make_directory(root, FS_OP_NONE);

    // Fail: create nested directory without parent
    (void)fs_make_directory("fs_demo/nested/child", FS_OP_NONE);

    // Create file and then collide with directory creation
    (void)fs_write_file(file_a, "hello", 5);
    (void)fs_make_directory(file_a, FS_OP_NONE);

    // Create subdir and then try to move file onto it
    (void)fs_make_directory(dir_sub, FS_OP_NONE);
    (void)fs_move_file(file_a, dir_sub, FS_OP_NONE);

    // Copy to existing file without overwrite
    (void)fs_write_file(file_b, "world", 5);
    (void)fs_copy_file(file_b, file_a, FS_OP_NONE);

    // Successful copy + move
    (void)fs_copy_file(file_b, file_c, FS_OP_OVERWRITE);
    (void)fs_move_file(file_c, "fs_demo/moved.txt", FS_OP_OVERWRITE);

    // Successful tree copy
    (void)fs_copy_tree(root, tree_copy, FS_OP_REUSE_DIRS);

    // Directory conflict: file where directory is expected
    (void)fs_write_file(dir_conflict, "not a dir", 9);
    (void)fs_copy_tree(root, dir_conflict, FS_OP_REUSE_DIRS);

    // Clean up
    (void)fs_delete_tree(tree_copy);
    (void)fs_delete_tree(root);
    return 0;
}
