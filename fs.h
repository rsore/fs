/**
 * fs.h — Cross-platform API for file system interaction,
 *        targeting Windows and POSIX.
 *
 * ~~ LIBRARY INTEGRATION ~~
 * `fs.h` is a single-header C and C++ library, and can easily be integrated
 * in your project by defining FS_IMPLEMENTATION in translation unit before
 * including the header. This will prompt `fs.h` to include all function
 * definitions in that translation unit.
 *
 * ~~ CUSTOMIZATION ~~
 * Certain behavior of fs.h can be customized by defining some
 * preprocessor definitions before including the `fs.h`:
 *  - FS_IMPLEMENTATION ........................... Include all function definitions.
 *  - FSAPI ....................................... Prefixed to all functions.
 *                                                   Example: `#define FSAPI static inline`
 *                                                   Default: Nothing
 *  - FS_WIN32_USE_FORWARDSLASH_SEPARATORS ........ Use `/` as path separator on Windows,
 *                                                  instead of the default, which is '\'.
 *  - FS_REALLOC(ptr, new_size) && FS_FREE(size) .. Define custom allocators for `fs.h`.
 *                                                  Must match the semantics of libc realloc and free.
 *                                                   Default: `libc realloc` and `libc free`.
 *
 * ~~ LICENSE ~~
 * `fs.h` is licenses under the MIT license. Full license text is
 * at the end of this file.
 */

#ifndef FS_H_INCLUDED_
#define FS_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#ifndef FSAPI
#    define FSAPI
#endif

#if defined(FS_REALLOC) != defined(FS_FREE)
#error "IF YOU DEFINE ONE OF FS_REALLOC OR FS_FREE, THEN BOTH FS_REALLOC AND FS_FREE MUST BE DEFINED"
#endif
#ifndef FS_REALLOC
#define FS_REALLOC(ptr, new_size) realloc(ptr, new_size)
#endif
#ifndef FS_FREE
#define FS_FREE(ptr) free(ptr)
#endif

#define FS_MODE_READONLY  0x0001u
#define FS_MODE_HIDDEN    0x0002u
#define FS_MODE_SYSTEM    0x0004u

#define FS_ERROR_NONE           0x0000u
#define FS_ERROR_GENERIC        0x0001u
#define FS_ERROR_ACCESS_DENIED  0x0002u
#define FS_ERROR_OUT_OF_MEMORY  0x0004u
#define FS_ERROR_FILE_NOT_FOUND 0x0008u


#ifdef __cplusplus
extern "C" {
#endif


/**
 * Returns non-zero if `path` exists (file, dir, or symlink), 0 if it
 * definitely does not exist. On error (e.g. permissions), returns 0.
 *
 * For error details, use fs_get_file_info().
 */
FSAPI int fs_exists(const char *path);

/**
 * Returns non-zero if `path` exists and is a regular file.
 * On error or if not a file, returns 0.
 */
FSAPI int fs_is_file(const char *path);

/**
 * Returns non-zero if `path` exists and is a directory.
 * On error or if not a directory, returns 0.
 */
FSAPI int fs_is_dir(const char *path);


typedef struct {
    char *path;         // Dynamically allocated, freed by fs_file_info_free()

    int is_dir;         // non-zero if entry is a directory.
    int is_symlink;     // non-zero if entry is a symbolic link / reparse point.

    uint64_t size;      // File size in bytes
    uint64_t mtime_sec; // Last modification time (seconds since epoch)
    uint32_t mode;      // Bitfield of FS_MODE_* values
} FsFileInfo;

/**
 * Query metadata for a single path.
 *
 * On success:
 *  - returns FS_ERROR_NONE
 *  - *out is fully initialized
 *  - out->path is an allocated copy of `path`, normalized
 *
 * On failure:
 *  - returns an FS_ERROR_* bitmask (never FS_ERROR_NONE)
 *  - *out is zeroed
 *  - if sys_error_out != NULL, *sys_error_out is set to errno (POSIX)
 *    or GetLastError() (Windows), or 0 for OOM.
 */
FSAPI uint32_t fs_get_file_info(const char *path, FsFileInfo *out, uint64_t *sys_error_out);

/**
 * Cleanup all internal resources.
 * Safe to call:
 *  - With zero-initialized object
 *  - multiple times.
 *  - with NULL.
 */
FSAPI void fs_file_info_free(FsFileInfo *f);


/**
 * Recursively delete a directory tree at `root`.
 *
 * Returns an FS_ERROR_* code:
 *   - FS_ERROR_NONE           on success
 *   - FS_ERROR_ACCESS_DENIED  if unlink/rmdir/DeleteFile/RemoveDirectory fails with permission errors
 *   - FS_ERROR_FILE_NOT_FOUND if root does not exist
 *   - FS_ERROR_OUT_OF_MEMORY  if allocations fail
 *   - FS_ERROR_GENERIC        for all other failures
 *
 * If sys_error_out != NULL:
 *   *sys_error_out = the underlying errno or GetLastError(), or 0 on OOM.
 */
FSAPI uint32_t fs_delete_tree(const char *root, uint64_t *sys_error_out);

/**
 * FsWalker is used to walk a file-structure tree from
 * a root directory, retrieving an FsFileInfo object
 * for each entry.
 *
 * The walker performs a depth-first, pre-order traversal.
 *
 * On both Windows and POSIX, symbolic links / reparse-point directories
 * are not traversed into. They are reported as entries with is_symlink != 0,
 * but no recursion occurs into their targets.
 *
 * Example usage:
 *
 *    FsWalker walker = {0};
 *    if (!fs_walker_init(&walker, "root_directory/")) {
 *        // handle initialization failure (walker.has_error, walker.error, walker.sys_error)
 *        return;
 *    }
 *
 *    const FsFileInfo *fi;
 *    while ((fi = fs_walker_next(&walker))) {
 *        if (!fi->is_dir && !fi->is_symlink) {
 *            printf("Filepath: %s\n", fi->path);
 *        }
 *        // No per-iteration free; the walker owns fi->path.
 *    }
 *
 *    if (walker.has_error) {
 *        // distinguish "finished" vs "error" after loop:
 *        // walker.error has FS_ERROR_* bits, walker.sys_error has errno/GetLastError()
 *    }
 *
 *    fs_walker_free(&walker);
 */
typedef struct FsWalker {
#ifdef _WIN32
    struct FsWalkerFrameWin   *frames;
#else
    struct FsWalkerFramePosix *frames;
#endif
    size_t len;
    size_t cap;

    FsFileInfo root_info;
    FsFileInfo current;

    int yielded_root;

    int         has_error;
    uint32_t    error;      // FS_ERROR_* bits
    uint64_t    sys_error;  // errno or GetLastError(), implementation detail
} FsWalker;

/**
 * Initialize a walker rooted at `root`. Does not traverse yet.
 *
 * The FsWalker `w` should be zero-initialized (e.g. FsWalker w = {0};) or
 * previously cleaned with fs_walker_free().
 *
 * On success:
 *  - returns 1
 *  - w->has_error == 0
 *  - w->error     == FS_ERROR_NONE
 *
 * On failure:
 *  - returns 0
 *  - w->has_error != 0
 *  - w->error     contains one or more FS_ERROR_* bits
 *  - w->sys_error contains the underlying errno (POSIX) or GetLastError()
 *    value (Windows), or 0 for pure allocation failures.
 *
 * A failed walker must not be used with fs_walker_next(), but
 * fs_walker_free() is still safe.
 */
FSAPI int fs_walker_init(FsWalker *w, const char *root);

/**
 * Advance the walker and return the next entry.
 *
 * On success:
 *  - returns a non-NULL pointer to an internal FsFileInfo owned by `w`.
 *  - The returned pointer is valid until the next call to fs_walker_next(w)
 *    or until fs_walker_free(w) is called.
 *  - The caller must NOT call fs_file_info_free() on the returned pointer.
 *
 * When traversal is finished (no more entries):
 *  - returns NULL
 *  - w->has_error == 0
 *  - w->error     == FS_ERROR_NONE
 *
 * On error:
 *  - returns NULL
 *  - w->has_error != 0
 *  - w->error     contains one or more FS_ERROR_* bits
 *  - w->sys_error contains errno / GetLastError(), or 0 for pure allocation failures
 *  - the walker has been cleaned up internally and must not be reused
 *    (but fs_walker_free() is still safe).
 *
 * In both "finished" and "error" cases fs_walker_next() returns NULL; the
 * caller must inspect w->has_error (or w->error) to distinguish them.
 */
FSAPI FsFileInfo *fs_walker_next(FsWalker *w);

/**
 * Cleanup all internal resources associated with the walker.
 *
 * Safe to call on:
 *  - a zero-initialized FsWalker,
 *  - after a successful traversal,
 *  - after fs_walker_init() failure,
 *  - or after an error reported by fs_walker_next().
 *
 * Safe to call multiple times.
 */
FSAPI void fs_walker_free(FsWalker *w);


/**
 * Return string description of error `err`
 */
FSAPI char *fs_strerror(uint32_t err);

#ifdef __cplusplus
}
#endif



/**
 * Implementation details follows
 */
#ifdef FS_IMPLEMENTATION

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

// Ensure lstat is declared even in strict C modes
struct stat;
int lstat(const char *path, struct stat *buf);
#endif

#ifdef _WIN32
typedef struct FsWalkerFrameWin {
    HANDLE            handle;
    WIN32_FIND_DATAA  data;
    char             *dir_path; // FS_REALLOC'ed
    int               first;    // 1 = use 'data' from FindFirstFileA
} FsWalkerFrameWin;
#else
typedef struct FsWalkerFramePosix {
    DIR  *dir;
    char *dir_path;  // FS_REALLOC'ed
} FsWalkerFramePosix;
#endif


static inline char *
fs_strdup_(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *)FS_REALLOC(NULL, n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

static inline int
fs_is_sep_(char c)
{
#ifdef _WIN32
    return c == '\\' || c == '/';
#else
    return c == '/';
#endif
}


#if defined(_WIN32) && !defined(FS_WIN32_USE_FORWARDSLASH_SEPARATORS)
#    define FS_PATH_SEP '\\'
#else
#    define FS_PATH_SEP '/'
#endif

static inline char *
fs_join_(const char *a, const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);

    int need_sep = 1;
    if (la == 0) {
        need_sep = 0;
    } else if (fs_is_sep_(a[la - 1])) {
        // a already ends with '/' or '\' (both count on Windows)
        need_sep = 0;
    }

    size_t len = la + (need_sep ? 1 : 0) + lb + 1;
    char *p = (char *)FS_REALLOC(NULL, len);
    if (!p) return NULL;

    if (need_sep) {
        snprintf(p, len, "%s%c%s", a, FS_PATH_SEP, b);
    } else {
        snprintf(p, len, "%s%s", a, b);
    }

    return p;
}

static inline void
fs_normalize_seps_(char *p)
{
#ifdef _WIN32
    if (!p) return;
    for (; *p; ++p) {
        if (*p == '/' || *p == '\\') {
            *p = FS_PATH_SEP;
        }
    }
#else
    (void)p; // no-op on POSIX
#endif
}

#ifdef _WIN32
static uint32_t
fs_map_win32_error_(DWORD err)
{
    switch (err) {
    case ERROR_ACCESS_DENIED:
        return FS_ERROR_ACCESS_DENIED;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_DRIVE:
        return FS_ERROR_FILE_NOT_FOUND;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        return FS_ERROR_OUT_OF_MEMORY;
    default:
        return FS_ERROR_GENERIC;
    }
}
#else
static uint32_t
fs_map_errno_(int e)
{
    switch (e) {
    case EACCES:
    case EPERM:
        return FS_ERROR_ACCESS_DENIED;
    case ENOENT:
    case ENOTDIR:
        return FS_ERROR_FILE_NOT_FOUND;
    case ENOMEM:
        return FS_ERROR_OUT_OF_MEMORY;
    default:
        return FS_ERROR_GENERIC;
    }
}
#endif

#ifdef _WIN32
static uint64_t
fs_filetime_to_unix_seconds_(FILETIME ft)
{
    ULARGE_INTEGER t;
    t.HighPart = ft.dwHighDateTime;
    t.LowPart  = ft.dwLowDateTime;

    // FILETIME is 100-ns intervals since 1601-01-01 UTC
    const uint64_t EPOCH_DIFF = 11644473600ULL; // seconds between 1601 and 1970
    return (t.QuadPart / 10000000ULL) - EPOCH_DIFF;
}
#endif

static uint32_t
fs_fill_file_info_(const char *path,
                   FsFileInfo *out,
                   uint64_t   *sys_error_out)
{
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) {
        DWORD err = GetLastError();
        if (sys_error_out) *sys_error_out = (uint64_t)err;
        return fs_map_win32_error_(err);
    }

    memset(out, 0, sizeof *out);

    out->is_dir     = (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)     != 0;
    out->is_symlink = (fad.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

    ULARGE_INTEGER sz;
    sz.HighPart = fad.nFileSizeHigh;
    sz.LowPart  = fad.nFileSizeLow;
    out->size   = (uint64_t)sz.QuadPart;

    out->mtime_sec = fs_filetime_to_unix_seconds_(fad.ftLastWriteTime);

    out->mode = 0;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_READONLY) out->mode |= FS_MODE_READONLY;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)   out->mode |= FS_MODE_HIDDEN;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)   out->mode |= FS_MODE_SYSTEM;

    if (sys_error_out) *sys_error_out = 0;
    return FS_ERROR_NONE;
#else
    struct stat st;
    if (lstat(path, &st) < 0) {
        int e = errno;
        if (sys_error_out) *sys_error_out = (uint64_t)e;
        return fs_map_errno_(e);
    }

    memset(out, 0, sizeof *out);

    out->is_dir     = S_ISDIR(st.st_mode) != 0;
    out->is_symlink = S_ISLNK(st.st_mode) != 0;
    out->size       = (uint64_t)st.st_size;
    out->mtime_sec  = (uint64_t)st.st_mtime;

    out->mode = 0;

    // Read-only: no write bits for user/group/others
    if ((st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0) {
        out->mode |= FS_MODE_READONLY;
    }

    // Hidden: basename starts with '.'
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (base[0] == '.' && base[1] != '\0') {
        out->mode |= FS_MODE_HIDDEN;
    }

    if (sys_error_out) *sys_error_out = 0;
    return FS_ERROR_NONE;
#endif
}


#ifdef _WIN32
static void
fs_walker_set_sys_error_(FsWalker *w, DWORD err)
{
    w->has_error = 1;
    w->sys_error = (uint64_t)err;
    w->error    |= fs_map_win32_error_(err);
}
#else
static void
fs_walker_set_sys_error_(FsWalker *w, int e)
{
    w->has_error = 1;
    w->sys_error = (uint64_t)e;
    w->error    |= fs_map_errno_(e);
}
#endif

static void
fs_walker_set_oom_error_(FsWalker *w)
{
    w->has_error = 1;
    w->error    |= FS_ERROR_OUT_OF_MEMORY;
    // leave sys_error as 0 or set to a convention (e.g. ENOMEM)
}

// Grow frame stack if necessary to fit needed
static inline int
fs_walker_ensure_cap_(FsWalker *w, size_t needed)
{
    if (w->cap >= needed) return 1;
    size_t new_cap = w->cap ? w->cap * 2 : 8;
    if (new_cap < needed) new_cap = needed;

#ifdef _WIN32
    FsWalkerFrameWin *nf = (FsWalkerFrameWin *)FS_REALLOC(w->frames, new_cap * sizeof(FsWalkerFrameWin));
#else
    FsWalkerFramePosix *nf = (FsWalkerFramePosix *)FS_REALLOC(w->frames, new_cap * sizeof(FsWalkerFramePosix));
#endif
    if (!nf) return 0;
    w->frames = nf;
    w->cap    = new_cap;
    return 1;
}

// push a frame for a directory (may succeed without pushing if empty on Windows)
static int
fs_walker_push_frame_(FsWalker *w, const char *dir_path)
{
#ifdef _WIN32
    size_t  len     = strlen(dir_path);
    size_t  patlen  = len + 2 + 1; // dir + '\' + '*' + '\0'
    char   *pattern = (char *)FS_REALLOC(NULL, patlen);
    if (!pattern) {
        fs_walker_set_oom_error_(w);
        return 0;
    }
    snprintf(pattern, patlen, "%s\\*", dir_path);

    WIN32_FIND_DATAA fd;
    HANDLE           h = FindFirstFileA(pattern, &fd);
    FS_FREE(pattern);

    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) {
            // Empty directory; not an error
            return 1;
        }
        fs_walker_set_sys_error_(w, err);
        return 0;
    }

    if (!fs_walker_ensure_cap_(w, w->len + 1)) {
        FindClose(h);
        fs_walker_set_oom_error_(w);
        return 0;
    }

    FsWalkerFrameWin *f = &w->frames[w->len++];
    f->handle   = h;
    f->data     = fd;
    f->dir_path = fs_strdup_(dir_path);
    f->first    = 1;
    if (!f->dir_path) {
        FindClose(h);
        w->len -= 1;
        fs_walker_set_oom_error_(w);
        return 0;
    }
    return 1;

#else
    DIR *dir = opendir(dir_path);
    if (!dir) {
        fs_walker_set_sys_error_(w, errno);
        return 0;
    }

    if (!fs_walker_ensure_cap_(w, w->len + 1)) {
        fs_walker_set_oom_error_(w);
        closedir(dir);
        return 0;
    }

    FsWalkerFramePosix *f = &w->frames[w->len++];
    f->dir      = dir;
    f->dir_path = fs_strdup_(dir_path);
    if (!f->dir_path) {
        closedir(dir);
        w->len -= 1;
        fs_walker_set_oom_error_(w);
        return 0;
    }
    return 1;
#endif
}

static inline void
fs_walker_cleanup_(FsWalker *w)
{
    if (!w) return;

#ifdef _WIN32
    for (size_t i = 0; i < w->len; ++i) {
        FsWalkerFrameWin *f = &w->frames[i];
        if (f->handle != INVALID_HANDLE_VALUE && f->handle != NULL) {
            FindClose(f->handle);
        }
        FS_FREE(f->dir_path);
    }
#else
    for (size_t i = 0; i < w->len; ++i) {
        FsWalkerFramePosix *f = &w->frames[i];
        if (f->dir) closedir(f->dir);
        FS_FREE(f->dir_path);
    }
#endif

    FS_FREE(w->frames);
    w->frames = NULL;
    w->len    = w->cap = 0;

    fs_file_info_free(&w->root_info);
    fs_file_info_free(&w->current);

    w->yielded_root = 0;
}

FSAPI int
fs_exists(const char *path)
{
    if (!path) return 0;

    FsFileInfo fi;
    uint32_t err = fs_fill_file_info_(path, &fi, NULL);

    return err == FS_ERROR_NONE;
}

FSAPI int
fs_is_file(const char *path)
{
    if (!path) return 0;

    FsFileInfo fi;
    uint64_t sys = 0;
    uint32_t err = fs_fill_file_info_(path, &fi, &sys);

    return err == FS_ERROR_NONE && !fi.is_dir && !fi.is_symlink;
}

FSAPI int
fs_is_dir(const char *path)
{
    if (!path) return 0;

    FsFileInfo fi;
    uint64_t sys = 0;
    uint32_t err = fs_fill_file_info_(path, &fi, &sys);

    return err == FS_ERROR_NONE && fi.is_dir && !fi.is_symlink;
}


FSAPI uint32_t
fs_get_file_info(const char *path,
                 FsFileInfo *out,
                 uint64_t   *sys_error_out)
{
    if (sys_error_out) *sys_error_out = 0;
    if (!out) {
        return FS_ERROR_GENERIC;
    }

    memset(out, 0, sizeof *out);

    if (!path) {
        return FS_ERROR_GENERIC;
    }

    uint32_t err = fs_fill_file_info_(path, out, sys_error_out);
    if (err != FS_ERROR_NONE) {
        memset(out, 0, sizeof *out);
        return err;
    }

    out->path = fs_strdup_(path);
    if (!out->path) {
        fs_file_info_free(out);
        if (sys_error_out) *sys_error_out = 0;
        return FS_ERROR_OUT_OF_MEMORY;
    }
    fs_normalize_seps_(out->path);

    return FS_ERROR_NONE;
}

FSAPI void
fs_file_info_free(FsFileInfo *f)
{
    if (!f) return;
    FS_FREE(f->path);
    memset(f, 0, sizeof *f);
}

FSAPI uint32_t
fs_delete_tree(const char *root, uint64_t *sys_error_out)
{
    uint32_t err = FS_ERROR_NONE;
    uint64_t sys_err = 0;

    FsWalker w = {0};
    if (!fs_walker_init(&w, root)) {
        if (sys_error_out) *sys_error_out = w.sys_error;
        return w.error;
    }

    char **dirs = NULL;
    size_t ndirs = 0, cap = 0;

    const FsFileInfo *fi;
    while ((fi = fs_walker_next(&w))) {
        if (fi->is_symlink) {
            // Delete symlink itself
#ifdef _WIN32
            if (!DeleteFileA(fi->path)) {
                err |= FS_ERROR_GENERIC;
                sys_err = GetLastError();
            }
#else
            if (unlink(fi->path) != 0) {
                err |= fs_map_errno_(errno);
                sys_err = errno;
            }
#endif
            continue;
        }

        if (!fi->is_dir) {
            // Delete file immediately
#ifdef _WIN32
            if (!DeleteFileA(fi->path)) {
                err |= fs_map_win32_error_(GetLastError());
                sys_err = GetLastError();
            }
#else
            if (unlink(fi->path) != 0) {
                err |= fs_map_errno_(errno);
                sys_err = errno;
            }
#endif
        } else {
            // Store for later
            if (ndirs == cap) {
                size_t new_cap = cap ? cap*2 : 16;
                char **tmp = FS_REALLOC(dirs, new_cap * sizeof(*tmp));
                if (!tmp) {
                    err |= FS_ERROR_OUT_OF_MEMORY;
                    sys_err = 0;
                    break;
                }
                dirs = tmp;
                cap  = new_cap;
            }
            dirs[ndirs++] = fs_strdup_(fi->path);
            if (!dirs[ndirs - 1]) {
                err |= FS_ERROR_OUT_OF_MEMORY;
                sys_err = 0;
                break;
            }
        }
    }

    if (w.has_error) {
        err |= w.error;
        sys_err = w.sys_error;
    }

    // Delete directories in reverse order
    for (size_t i = ndirs; i > 0; --i) {
        char *d = dirs[i - 1];
#ifdef _WIN32
        if (!RemoveDirectoryA(d)) {
            err |= fs_map_win32_error_(GetLastError());
            sys_err = GetLastError();
        }
#else
        if (rmdir(d) != 0) {
            err |= fs_map_errno_(errno);
            sys_err = errno;
        }
#endif
        FS_FREE(d);
    }

    FS_FREE(dirs);
    fs_walker_free(&w);

    if (sys_error_out) *sys_error_out = sys_err;

    return err;
}

FSAPI int
fs_walker_init(FsWalker *w, const char *root)
{
    if (!w || !root) return 0;
    memset(w, 0, sizeof *w);

    FsFileInfo *ri = &w->root_info;
    uint64_t sys = 0;
    uint32_t err = fs_fill_file_info_(root, ri, &sys);
    if (err != FS_ERROR_NONE) {
        w->has_error = 1;
        w->error    |= err;
        w->sys_error = sys;
        fs_walker_cleanup_(w);
        return 0;
    }

    ri->path = fs_strdup_(root);
    if (!ri->path) {
        fs_walker_set_oom_error_(w);
        fs_walker_cleanup_(w);
        return 0;
    }
    fs_normalize_seps_(ri->path);

    if (ri->is_dir && !ri->is_symlink) {
        if (!fs_walker_push_frame_(w, ri->path)) {
            fs_walker_cleanup_(w);
            return 0;
        }
    }

    w->yielded_root = 0;
    w->has_error    = 0;
    return 1;
}


FSAPI FsFileInfo *
fs_walker_next(FsWalker *w)
{
    if (!w)           return NULL;
    if (w->has_error) return NULL;

    fs_file_info_free(&w->current);

    // First call: yield root
    if (!w->yielded_root) {
        w->yielded_root = 1;
        fs_file_info_free(&w->current);

        w->current = w->root_info; // Copy metadata
        w->current.path = fs_strdup_(w->root_info.path);
        if (!w->current.path) {
            fs_walker_set_oom_error_(w);
            fs_walker_cleanup_(w);
            return NULL;
        }
        return &w->current;
    }

    for (;;) {
        if (w->len == 0) {
            return NULL; // done
        }

#ifdef _WIN32
        FsWalkerFrameWin *frame = &w->frames[w->len - 1];
        WIN32_FIND_DATAA *fd    = &frame->data;

        for (;;) {
            if (frame->first) {
                frame->first = 0;
            } else {
                if (!FindNextFileA(frame->handle, fd)) {
                    DWORD err = GetLastError();
                    if (err == ERROR_NO_MORE_FILES) {
                        FindClose(frame->handle);
                        FS_FREE(frame->dir_path);
                        w->len--;
                        break;
                    }
                    fs_walker_set_sys_error_(w, err);
                    fs_walker_cleanup_(w);
                    return NULL;
                }
            }

            const char *name = fd->cFileName;
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                continue;
            }

            char *child = fs_join_(frame->dir_path, name);
            if (!child) {
                fs_walker_set_oom_error_(w);
                fs_walker_cleanup_(w);
                return NULL;
            }
            fs_normalize_seps_(child);

            uint64_t sys = 0;
            uint32_t err = fs_fill_file_info_(child, &w->current, &sys);
            if (err != FS_ERROR_NONE) {
                w->has_error = 1;
                w->error    |= err;
                w->sys_error = sys;
                FS_FREE(child);
                fs_walker_cleanup_(w);
                return NULL;
            }

            w->current.path = child;

            if (w->current.is_dir && !w->current.is_symlink) {
                if (!fs_walker_push_frame_(w, child)) {
                    w->current.path = NULL;
                    FS_FREE(child);
                    fs_walker_cleanup_(w);
                    return NULL;
                }
            }

            return &w->current;
        }

#else
        FsWalkerFramePosix *frame = &w->frames[w->len - 1];
        struct dirent *ent;

        while ((ent = readdir(frame->dir)) != NULL) {
            const char *name = ent->d_name;
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                continue;
            }

            char *child = fs_join_(frame->dir_path, name);
            if (!child) {
                fs_walker_set_oom_error_(w);
                fs_walker_cleanup_(w);
                return NULL;
            }
            fs_normalize_seps_(child);

            uint64_t sys = 0;
            uint32_t err = fs_fill_file_info_(child, &w->current, &sys);
            if (err != FS_ERROR_NONE) {
                w->has_error = 1;
                w->error    |= err;
                w->sys_error = sys;
                FS_FREE(child);
                fs_walker_cleanup_(w);
                return NULL;
            }

            w->current.path = child;

            if (w->current.is_dir) {
                if (!fs_walker_push_frame_(w, child)) {
                    w->current.path = NULL;
                    FS_FREE(child);
                    fs_walker_cleanup_(w);
                    return NULL;
                }
            }

            return &w->current;
        }

        closedir(frame->dir);
        FS_FREE(frame->dir_path);
        w->len -= 1;
#endif
    }
}

FSAPI void
fs_walker_free(FsWalker *w)
{
    if (!w) return;
    fs_walker_cleanup_(w);
    fs_file_info_free(&w->current);
    memset(w, 0, sizeof *w);
}

FSAPI char *
fs_strerror(uint32_t err)
{
    switch (err) {
        case FS_ERROR_NONE: return "No error";
        case FS_ERROR_GENERIC: return "Unknown error";
        case FS_ERROR_ACCESS_DENIED: return "Access denied";
        case FS_ERROR_OUT_OF_MEMORY: return "Out of memory";
        case FS_ERROR_FILE_NOT_FOUND: return "File not found";
    }
    return "";
}


#endif // FS_IMPLEMENTATION

#endif // FS_H_INCLUDED_

/**
 * MIT License
 *
 * Copyright (c) 2025 Ruben Sørensen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
