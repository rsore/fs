#define FSAPI static inline
#define FS_WIN32_USE_FORWARDSLASH_SEPARATORS
#define FS_IMPLEMENTATION
#include "fs.h"

int
main(void)
{
    FsFileInfo file_info = FS_ZERO_INIT_;
    uint32_t err; uint64_t sys_err;
    if ((err = fs_get_file_info(".helloworld", &file_info, &sys_err)) != FS_ERROR_NONE) {
        fprintf(stderr, "Error %u: %s\n", (uint32_t)sys_err, fs_strerror(err));
        return 1;
    }
    printf("file_info::path       = %s\n", file_info.path);
    printf("file_info::is_dir     = %s\n", file_info.is_dir ? "true" : "false");
    printf("file_info::is_symlink = %s\n", file_info.is_symlink ? "true" : "false");
    printf("file_info::size = %zu\n", file_info.size);
    printf("file_info::mtime_sec = %zu\n", file_info.mtime_sec);
    printf("file_info::mode = ");
    if (file_info.mode & FS_MODE_READONLY) printf("| FS_MODE_READONLY |");
    if (file_info.mode & FS_MODE_HIDDEN)   printf("| FS_MODE_HIDDEN |");
    if (file_info.mode & FS_MODE_SYSTEM)   printf("| FS_MODE_SYSTEM |");
    printf("\n\n");
    fs_file_info_free(&file_info);

    FsWalker walker = FS_ZERO_INIT_;
    if (!fs_walker_init(&walker, "test/")) {
        printf("Error: %s\n", fs_strerror(walker.error));
        return 1;
    }
    const FsFileInfo *fi;
    while ((fi = fs_walker_next(&walker))) {
        if (!fi->is_dir && !fi->is_symlink) {
            printf("Filepath: %s\n", fi->path);
        }
    }
    if (walker.has_error) {
        printf("Error: %s\n", fs_strerror(walker.error));
        fs_walker_free(&walker);
        return 1;
    }

    fs_walker_free(&walker);

    char buf[4096];
    size_t buf_size = 4096;
    size_t bytes_read;
    if ((err = fs_read_file_into("main.c", buf, buf_size, &bytes_read, NULL)) != FS_ERROR_NONE) {
        fprintf(stderr, "Error: %s\n", fs_strerror(err));
    }

    fs_write_file("test - Copy", buf, bytes_read, NULL);

    uint32_t error; uint64_t sys_error;
    if ((error = fs_delete_tree("test - Copy", &sys_error)) != FS_ERROR_NONE) {
        printf("Error %u: %s\n", (unsigned int)sys_error, fs_strerror(error));
    }

    return 0;
}
