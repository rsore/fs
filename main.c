#define FSAPI static inline
#define FS_WIN32_USE_FORWARDSLASH_SEPARATORS
#define FS_IMPLEMENTATION
#include "fs.h"

int
main(void)
{
    FsWalker walker = {0};
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

    return 0;
}
