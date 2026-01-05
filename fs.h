/**
 * fs.h - Cross-platform API for file system interaction,
 *        targeting Windows and POSIX.
 *
 * Version: 1.0.0
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
 *  - FS_IMPLEMENTATION .......................... Include all function definitions.
 *  - FSDEF ...................................... Prefixed to all functions.
 *                                                 Example: `#define FSDEF static inline`
 *                                                 Default: Nothing
 *  - FS_WIN32_USE_FORWARDSLASH_SEPARATORS ....... Use `/` as path separator on Windows,
 *                                                 instead of the default, which is '\'.
 *  - FS_REALLOC(ptr, new_size) && FS_FREE(ptr) .. Define custom allocators for `fs.h`.
 *                                                 Must match the semantics of libc realloc and free.
 *                                                 Default: `libc realloc` and `libc free`.
 *  - FS_EMBED_LICENSE ........................... Embeds BSD-3-Clause license text
 *                                                 in the program binary.
 *  - FS_LOG(level, msg) ......................... If defined, used to log info and errors.
 *                                                 level is `FS_LOG_LEVEL_*` and msg is NUL-terminated cstr.
 *                                                 Example: `#define FS_LOG(level, msg) \
 *                                                               fprintf(stderr, "%s: %s\n", fs_log_level_to_str((level)), (msg))`
 *  - FS_USE_SIMPLE_LOGGER ...................... If defined, sets `FS_LOG(level, msg)` to a basic stderr logger.
 *
 * ~~ LICENSE ~~
 * `fs.h` is licensed under the 3-Clause BSD license. Full license text is
 * at the end of this file.
 */

#ifndef FS_H_INCLUDED_
#define FS_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#ifndef FSDEF
#    define FSDEF
#endif

#if defined(FS_REALLOC) != defined(FS_FREE)
#    error "IF YOU DEFINE ONE OF FS_REALLOC OR FS_FREE, THEN BOTH FS_REALLOC AND FS_FREE MUST BE DEFINED"
#else
#endif
#ifndef FS_REALLOC
#    define FS_REALLOC(ptr, new_size) realloc((ptr), (new_size))
#endif
#ifndef FS_FREE
#    define FS_FREE(ptr) free((ptr))
#endif

#define FS_MODE_READONLY  0x01u
#define FS_MODE_HIDDEN    0x02u
#define FS_MODE_SYSTEM    0x04u

// Error codes are single values (not a bitmask).
typedef enum {
    FS_ERROR_NONE                     = 0,
    FS_ERROR_GENERIC                  = 1,
    FS_ERROR_ACCESS_DENIED            = 2,
    FS_ERROR_OUT_OF_MEMORY            = 3,
    FS_ERROR_FILE_NOT_FOUND           = 4,
    FS_ERROR_FILE_ALREADY_EXISTS      = 5,
    FS_ERROR_FILE_IS_NOT_DIRECTORY    = 6,
    FS_ERROR_DIRECTORY_ALREADY_EXISTS = 7,
    FS_ERROR_SYMLINK_NOT_SUPPORTED    = 8,
} Fs_Error;

#define FS_LOG_LEVEL_TRACE    0x01u
#define FS_LOG_LEVEL_INFO     0x02u
#define FS_LOG_LEVEL_ERROR    0x04u
#define FS_LOG_LEVEL_ALL      (FS_LOG_LEVEL_TRACE | FS_LOG_LEVEL_INFO | FS_LOG_LEVEL_ERROR)

#if defined(FS_USE_SIMPLE_LOGGER) && !defined(FS_LOG)
#define FS_LOG(level, msg)    \
    do {                      \
        fputs((msg), stderr); \
        fputc('\n',  stderr); \
    } while (0)
#endif

#if defined(FS_LOG) && !defined(FS_INFO)
#define FS_INFO(msg) FS_LOG(FS_LOG_LEVEL_INFO, (msg))
#endif
#if defined(FS_LOG) && !defined(FS_ERR)
#define FS_ERR(msg) FS_LOG(FS_LOG_LEVEL_ERROR, (msg))
#endif

#define FS_OP_NONE       0x00u
#define FS_OP_OVERWRITE  0x01u
#define FS_OP_REUSE_DIRS 0x02u

#ifdef __cplusplus
extern "C" {
#endif

// Returns string description of error code.
FSDEF const char *fs_strerror(Fs_Error err);

typedef void (*Fs_LogFn)(unsigned int level, const char *msg, void *user_data);

// Sets a global logger for fs.h. Overrides FS_LOG(). Passing NULL disables logging.
// Note: Global and not thread-safe; configure at startup or guard with your own locks.
FSDEF void fs_set_logger(Fs_LogFn logger, void *user_data);

// Sets the runtime log mask. Default is FS_LOG_LEVEL_ALL.
FSDEF void fs_set_log_mask(unsigned int mask);

// Returns string description of log level.
FSDEF const char *fs_log_level_to_str(unsigned int level);

// Returns the BSD-3-Clause license text of fs.h as a NUL-terminated C string.
// The returned string has static storage duration and must not be freed.
// Returns NULL if the license text was not embedded
// (i.e. FS_EMBED_LICENSE was not defined in the FS_IMPLEMENTATION translation unit).
FSDEF const char *fs_license_text(void);


typedef struct {
    char *path;         // Dynamically allocated, freed by fs_file_info_free()

    int is_dir;         // non-zero if entry is a directory.
    int is_symlink;     // non-zero if entry is a symbolic link / reparse point.

    uint64_t size;      // File size in bytes
    uint64_t mtime_sec; // Last modification time (seconds since epoch)
    uint32_t mode;      // Bitfield of FS_MODE_* values
} Fs_FileInfo;

// Query metadata for a single path. On success, out->path is allocated and normalized.
FSDEF Fs_Error fs_get_file_info(const char *path, Fs_FileInfo *out);

// Frees Fs_FileInfo resources. Safe with NULL or zero-initialized structs.
FSDEF void fs_file_info_free(Fs_FileInfo *f);


// Returns non-zero if path exists (file/dir/symlink). On error, returns 0.
FSDEF int fs_exists(const char *path);

// Returns non-zero if path exists and is a regular file.
FSDEF int fs_is_file(const char *path);

// Returns non-zero if path exists and is a directory.
FSDEF int fs_is_dir(const char *path);


// Reads entire file into a newly allocated buffer. Buffer is binary (not NUL-terminated).
// Caller frees with FS_FREE(). Empty files return size 0 with a valid buffer.
FSDEF Fs_Error fs_read_file(const char *path, void **data_out, size_t *size_out);

// Reads up to buf_size bytes into buffer. Buffer is binary (not NUL-terminated).
FSDEF Fs_Error fs_read_file_into(const char *path, void *buffer, size_t buf_size, size_t *bytes_read_out);

// Writes size bytes to path. Overwrites or creates. Binary mode on all platforms.
FSDEF Fs_Error fs_write_file(const char *path, const void *data, size_t size);

// Moves a regular file from src to dst. Honors FS_OP_OVERWRITE.
FSDEF Fs_Error fs_move_file(const char *src, const char *dst, uint32_t flags);

// Copies a regular file from src to dst. Honors FS_OP_OVERWRITE.
FSDEF Fs_Error fs_copy_file(const char *src, const char *dst, uint32_t flags);

// Deletes a file or symlink at path.
FSDEF Fs_Error fs_delete_file(const char *path);

// Computes CRC-32 of a file.
FSDEF Fs_Error fs_crc32_file(const char *path, uint32_t *crc_out);


// Creates a single directory at path. Parents must already exist.
// Use FS_OP_REUSE_DIRS to treat existing directories as success.
FSDEF Fs_Error fs_make_directory(const char *path, uint32_t flags);

// Recursively moves a directory tree from src_dir to dst_dir.
// Honors FS_OP_OVERWRITE and FS_OP_REUSE_DIRS.
FSDEF Fs_Error fs_move_tree(const char *src_dir, const char *dst_dir, uint32_t flags);

// Recursively copies a directory tree from src_dir to dst_dir.
// Honors FS_OP_OVERWRITE and FS_OP_REUSE_DIRS.
FSDEF Fs_Error fs_copy_tree(const char *src_dir, const char *dst_dir, uint32_t flags);

// Recursively deletes a directory tree at root. Symlinked dirs are not followed.
FSDEF Fs_Error fs_delete_tree(const char *root);


// Walker for depth-first, pre-order traversal.
// Symlinked dirs are reported but not traversed.
typedef struct Fs_Walker {
#ifdef _WIN32
    struct Fs_WalkerFrameWin   *frames;
#else
    struct Fs_WalkerFramePosix *frames;
#endif
    size_t len;
    size_t cap;

    Fs_FileInfo root_info;
    Fs_FileInfo current;

    int yielded_root;

    int         has_error;
    Fs_Error    error;      // FS_ERROR_* code
} Fs_Walker;

// Initializes a walker rooted at root. Returns 1 on success, 0 on failure.
FSDEF int fs_walker_init(Fs_Walker *w, const char *root);

// Advances the walker and returns the next entry, or NULL on finish/error.
// Returned Fs_FileInfo is owned by the walker and valid until next call.
FSDEF Fs_FileInfo *fs_walker_next(Fs_Walker *w);

// Frees all walker resources. Safe to call multiple times.
FSDEF void fs_walker_free(Fs_Walker *w);


#ifdef __cplusplus
}
#endif



// Implementation details follows
#ifdef FS_IMPLEMENTATION

#ifdef __cplusplus
#    define FS_INTERNAL_ZERO_INIT {}
#else
#    define FS_INTERNAL_ZERO_INIT {0}
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

// Ensure lstat is declared even in strict C modes
struct stat;
int lstat(const char *path, struct stat *buf);
#endif

#ifdef _WIN32
typedef struct Fs_WalkerFrameWin {
    HANDLE            handle;
    WIN32_FIND_DATAA  data;
    char             *dir_path; // FS_REALLOC'ed
    int               first;    // 1 = use 'data' from FindFirstFileA
} Fs_WalkerFrameWin;
#else
typedef struct Fs_WalkerFramePosix {
    DIR  *dir;
    char *dir_path;  // FS_REALLOC'ed
} Fs_WalkerFramePosix;
#endif

static Fs_LogFn      fs_internal_global_log_fn        = NULL;
static void         *fs_internal_global_log_user_data = NULL;
static unsigned int  fs_internal_global_log_mask      = FS_LOG_LEVEL_ALL;

static inline void
fs_internal_log_emit(unsigned int  level,
                     const char   *msg)
{
    if (fs_internal_global_log_fn) {
        if (fs_internal_global_log_mask & level) {
            fs_internal_global_log_fn(level, msg, fs_internal_global_log_user_data);
        }
        return;
    }

#ifdef FS_LOG
    FS_LOG(level, msg);
#else
    (void)level;
    (void)msg;
#endif
}

static inline int
fs_internal_log_is_enabled(unsigned int level)
{
    if (fs_internal_global_log_fn) {
        return (fs_internal_global_log_mask & level) != 0;
    }
#ifdef FS_LOG
    (void)level;
    return 1;
#else
    (void)level;
    return 0;
#endif
}

static inline void
fs_internal_logf(unsigned int  level,
                 const char   *fmt,
                 ...)
{
    if (!fs_internal_log_is_enabled(level)) {
        return;
    }

    char stack_buf[1024];
    va_list args;

    // Attempt to format into stack buffer
    va_start(args, fmt);
    int needed = vsnprintf(stack_buf, sizeof stack_buf, fmt, args);
    va_end(args);

    if (needed < 0) {
        // Formatting failed
        fs_internal_log_emit(FS_LOG_LEVEL_ERROR, "fs: internal formatting error in fs_internal_logf");
        return;
    }

    if ((size_t)needed < sizeof stack_buf) {
        // Message fit into the stack buffer
        fs_internal_log_emit(level, stack_buf);
        return;
    }

    // Message was truncated, allocate a bigger buffer
    size_t  full_len    = (size_t)needed + 1;
    char   *dynamic_buf = (char *)FS_REALLOC(NULL, full_len);
    if (!dynamic_buf) {
        // OOM, fall back to truncated version
        fs_internal_log_emit(level, stack_buf);
        return;
    }

    // format full message
    va_start(args, fmt);
    vsnprintf(dynamic_buf, full_len, fmt, args);
    va_end(args);

    fs_internal_log_emit(level, dynamic_buf);

    FS_FREE(dynamic_buf);
}


static inline char *
fs_internal_strdup(const char *s)
{
    size_t  n = strlen(s) + 1;
    char   *p = (char *)FS_REALLOC(NULL, n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

static inline void
fs_internal_set_error_if_none(Fs_Error *dst,
                              Fs_Error  err)
{
    if (*dst == FS_ERROR_NONE) {
        *dst = err;
    }
}

static inline void
fs_internal_log_error_path(const char *context,
                           const char *path,
                           Fs_Error    err)
{
    if (err == FS_ERROR_NONE) {
        return;
    }
    if (path) {
        fs_internal_logf(FS_LOG_LEVEL_ERROR, "Failed to %s '%s': %s", context, path, fs_strerror(err));
    } else {
        fs_internal_logf(FS_LOG_LEVEL_ERROR, "Failed to %s: %s", context, fs_strerror(err));
    }
}

static inline void
fs_internal_log_error_path2(const char *context,
                            const char *path_a,
                            const char *path_b,
                            Fs_Error    err)
{
    if (err == FS_ERROR_NONE) {
        return;
    }
    if (path_a && path_b) {
        fs_internal_logf(FS_LOG_LEVEL_ERROR, "Failed to %s '%s' -> '%s': %s",
                 context, path_a, path_b, fs_strerror(err));
    } else if (path_a) {
        fs_internal_logf(FS_LOG_LEVEL_ERROR, "Failed to %s '%s': %s", context, path_a, fs_strerror(err));
    } else {
        fs_internal_logf(FS_LOG_LEVEL_ERROR, "Failed to %s: %s", context, fs_strerror(err));
    }
}

static inline void
fs_internal_log_info_path(const char *context,
                          const char *path)
{
    if (path) {
        fs_internal_logf(FS_LOG_LEVEL_INFO, "%s '%s'", context, path);
    } else {
        fs_internal_logf(FS_LOG_LEVEL_INFO, "%s", context);
    }
}

static inline void
fs_internal_log_trace_path(const char *context,
                           const char *path)
{
    if (path) {
        fs_internal_logf(FS_LOG_LEVEL_TRACE, "%s '%s'", context, path);
    } else {
        fs_internal_logf(FS_LOG_LEVEL_TRACE, "%s", context);
    }
}

static inline void
fs_internal_log_info_path2(const char *context,
                           const char *path_a,
                           const char *path_b)
{
    if (path_a && path_b) {
        fs_internal_logf(FS_LOG_LEVEL_INFO, "%s '%s' -> '%s'", context, path_a, path_b);
    } else if (path_a) {
        fs_internal_logf(FS_LOG_LEVEL_INFO, "%s '%s'", context, path_a);
    } else {
        fs_internal_logf(FS_LOG_LEVEL_INFO, "%s", context);
    }
}

static inline void
fs_internal_log_trace_path2(const char *context,
                            const char *path_a,
                            const char *path_b)
{
    if (path_a && path_b) {
        fs_internal_logf(FS_LOG_LEVEL_TRACE, "%s '%s' -> '%s'", context, path_a, path_b);
    } else if (path_a) {
        fs_internal_logf(FS_LOG_LEVEL_TRACE, "%s '%s'", context, path_a);
    } else {
        fs_internal_logf(FS_LOG_LEVEL_TRACE, "%s", context);
    }
}

static inline int
fs_internal_is_sep(char c)
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
fs_internal_join(const char *a,
                 const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);

    int need_sep = 1;
    if (la == 0) {
        need_sep = 0;
    } else if (fs_internal_is_sep(a[la - 1])) {
        // a already ends with '/' or '\' (both count on Windows)
        need_sep = 0;
    }

    size_t  len = la + (need_sep ? 1 : 0) + lb + 1;
    char   *p   = (char *)FS_REALLOC(NULL, len);
    if (!p) return NULL;

    if (need_sep) {
        snprintf(p, len, "%s%c%s", a, FS_PATH_SEP, b);
    } else {
        snprintf(p, len, "%s%s", a, b);
    }

    return p;
}

static inline void
fs_internal_normalize_seps(char *p)
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
static inline Fs_Error
fs_internal_win32_map_error(DWORD err)
{
    switch (err) {
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        return FS_ERROR_ACCESS_DENIED;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_DRIVE:
        return FS_ERROR_FILE_NOT_FOUND;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
        return FS_ERROR_FILE_ALREADY_EXISTS;
    case ERROR_DIRECTORY:
        return FS_ERROR_FILE_IS_NOT_DIRECTORY;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        return FS_ERROR_OUT_OF_MEMORY;
    default:
        return FS_ERROR_GENERIC;
    }
}
#else
static inline Fs_Error
fs_internal_posix_map_errno(int e)
{
    switch (e) {
    case EACCES:
    case EPERM:
        return FS_ERROR_ACCESS_DENIED;
    case ENOENT:
        return FS_ERROR_FILE_NOT_FOUND;
    case ENOTDIR:
        return FS_ERROR_FILE_IS_NOT_DIRECTORY;
    case EEXIST:
        return FS_ERROR_FILE_ALREADY_EXISTS;
    case ENOMEM:
        return FS_ERROR_OUT_OF_MEMORY;
    default:
        return FS_ERROR_GENERIC;
    }
}
#endif

#ifdef _WIN32
static inline uint64_t
fs_internal_win32_filetime_to_unix_seconds(FILETIME ft)
{
    ULARGE_INTEGER t;
    t.HighPart = ft.dwHighDateTime;
    t.LowPart  = ft.dwLowDateTime;

    // FILETIME is 100-ns intervals since 1601-01-01 UTC
    const uint64_t EPOCH_DIFF = 11644473600ULL; // seconds between 1601 and 1970
    return (t.QuadPart / 10000000ULL) - EPOCH_DIFF;
}
#endif

static inline Fs_Error
fs_internal_fill_file_info(const char  *path,
                           Fs_FileInfo *out)
{
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) {
        DWORD err = GetLastError();
        return fs_internal_win32_map_error(err);
    }

    memset(out, 0, sizeof *out);

    out->is_dir     = (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)     != 0;
    out->is_symlink = (fad.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

    ULARGE_INTEGER sz;
    sz.HighPart = fad.nFileSizeHigh;
    sz.LowPart  = fad.nFileSizeLow;
    out->size   = (uint64_t)sz.QuadPart;

    out->mtime_sec = fs_internal_win32_filetime_to_unix_seconds(fad.ftLastWriteTime);

    out->mode = 0;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_READONLY) out->mode |= FS_MODE_READONLY;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)   out->mode |= FS_MODE_HIDDEN;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)   out->mode |= FS_MODE_SYSTEM;

    return FS_ERROR_NONE;
#else
    struct stat st;
    if (lstat(path, &st) < 0) {
        int e = errno;
        return fs_internal_posix_map_errno(e);
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

    return FS_ERROR_NONE;
#endif
}

#ifdef _WIN32
static inline void
fs_internal_win32_walker_set_sys_error(Fs_Walker *w,
                                       DWORD      err)
{
    w->has_error = 1;
    fs_internal_set_error_if_none(&w->error, fs_internal_win32_map_error(err));
}
#else
static inline void
fs_internal_posix_walker_set_sys_error(Fs_Walker *w,
                                       int        e)
{
    w->has_error = 1;
    fs_internal_set_error_if_none(&w->error, fs_internal_posix_map_errno(e));
}
#endif

static inline void
fs_internal_walker_set_oom_error(Fs_Walker *w)
{
    w->has_error = 1;
    fs_internal_set_error_if_none(&w->error, FS_ERROR_OUT_OF_MEMORY);
}

// Grow frame stack if necessary to fit needed
static inline int
fs_internal_walker_ensure_cap(Fs_Walker *w,
                              size_t     needed)
{
    if (w->cap >= needed) return 1;
    size_t new_cap = w->cap ? w->cap * 2 : 8;
    if (new_cap < needed) new_cap = needed;

#ifdef _WIN32
    Fs_WalkerFrameWin *nf = (Fs_WalkerFrameWin *)FS_REALLOC(w->frames, new_cap * sizeof(Fs_WalkerFrameWin));
#else
    Fs_WalkerFramePosix *nf = (Fs_WalkerFramePosix *)FS_REALLOC(w->frames, new_cap * sizeof(Fs_WalkerFramePosix));
#endif
    if (!nf) return 0;
    w->frames = nf;
    w->cap    = new_cap;
    return 1;
}

// push a frame for a directory (may succeed without pushing if empty on Windows)
static inline int
fs_internal_walker_push_frame(Fs_Walker  *w,
                              const char *dir_path)
{
#ifdef _WIN32
    size_t  len     = strlen(dir_path);
    size_t  patlen  = len + 2 + 1; // dir + '\' + '*' + '\0'
    char   *pattern = (char *)FS_REALLOC(NULL, patlen);
    if (!pattern) {
        fs_internal_walker_set_oom_error(w);
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
        fs_internal_log_error_path("open directory", dir_path, fs_internal_win32_map_error(err));
        fs_internal_win32_walker_set_sys_error(w, err);
        return 0;
    }

    if (!fs_internal_walker_ensure_cap(w, w->len + 1)) {
        FindClose(h);
        fs_internal_walker_set_oom_error(w);
        fs_internal_log_error_path("open directory", dir_path, FS_ERROR_OUT_OF_MEMORY);
        return 0;
    }

    Fs_WalkerFrameWin *f = &w->frames[w->len++];
    f->handle   = h;
    f->data     = fd;
    f->dir_path = fs_internal_strdup(dir_path);
    f->first    = 1;
    if (!f->dir_path) {
        FindClose(h);
        w->len -= 1;
        fs_internal_walker_set_oom_error(w);
        fs_internal_log_error_path("open directory", dir_path, FS_ERROR_OUT_OF_MEMORY);
        return 0;
    }
    return 1;

#else
    DIR *dir = opendir(dir_path);
    if (!dir) {
        fs_internal_log_error_path("open directory", dir_path, fs_internal_posix_map_errno(errno));
        fs_internal_posix_walker_set_sys_error(w, errno);
        return 0;
    }

    if (!fs_internal_walker_ensure_cap(w, w->len + 1)) {
        fs_internal_walker_set_oom_error(w);
        closedir(dir);
        fs_internal_log_error_path("open directory", dir_path, FS_ERROR_OUT_OF_MEMORY);
        return 0;
    }

    Fs_WalkerFramePosix *f = &w->frames[w->len++];
    f->dir      = dir;
    f->dir_path = fs_internal_strdup(dir_path);
    if (!f->dir_path) {
        closedir(dir);
        w->len -= 1;
        fs_internal_walker_set_oom_error(w);
        fs_internal_log_error_path("open directory", dir_path, FS_ERROR_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
#endif
}

static inline void
fs_internal_walker_cleanup(Fs_Walker *w)
{
    if (!w) return;

#ifdef _WIN32
    for (size_t i = 0; i < w->len; ++i) {
        Fs_WalkerFrameWin *f = &w->frames[i];
        if (f->handle != INVALID_HANDLE_VALUE && f->handle != NULL) {
            FindClose(f->handle);
        }
        FS_FREE(f->dir_path);
    }
#else
    for (size_t i = 0; i < w->len; ++i) {
        Fs_WalkerFramePosix *f = &w->frames[i];
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

FSDEF const char *
fs_strerror(Fs_Error err)
{
    switch (err) {
        case FS_ERROR_NONE:                     return "No error";
        case FS_ERROR_GENERIC:                  return "Unknown error";
        case FS_ERROR_ACCESS_DENIED:            return "Access denied";
        case FS_ERROR_OUT_OF_MEMORY:            return "Out of memory";
        case FS_ERROR_FILE_NOT_FOUND:           return "File does not exist";
        case FS_ERROR_FILE_ALREADY_EXISTS:      return "File already exists";
        case FS_ERROR_DIRECTORY_ALREADY_EXISTS: return "Directory already exists";
        case FS_ERROR_FILE_IS_NOT_DIRECTORY:    return "File is not a directory";
        case FS_ERROR_SYMLINK_NOT_SUPPORTED:    return "Symlink not supported";
    }
    return "<unhandled error code>";
}

FSDEF void
fs_set_logger(Fs_LogFn  logger,
              void     *user_data)
{
    fs_internal_global_log_fn        = logger;
    fs_internal_global_log_user_data = user_data;
}

FSDEF void
fs_set_log_mask(unsigned int mask)
{
    fs_internal_global_log_mask = mask;
}

FSDEF const char *
fs_log_level_to_str(unsigned int level)
{
    switch (level) {
        case FS_LOG_LEVEL_TRACE:   return "TRACE";
        case FS_LOG_LEVEL_INFO:    return "INFO";
        case FS_LOG_LEVEL_ERROR:   return "ERROR";
    }
    return "UNKNOWN";
}

FSDEF int
fs_exists(const char *path)
{
    if (!path) return 0;

    fs_internal_log_trace_path("Check exists", path);

    Fs_FileInfo fi;
    Fs_Error err = fs_internal_fill_file_info(path, &fi);

    return err == FS_ERROR_NONE;
}

FSDEF int
fs_is_file(const char *path)
{
    if (!path) return 0;

    fs_internal_log_trace_path("Check is file", path);

    Fs_FileInfo fi;
    Fs_Error err = fs_internal_fill_file_info(path, &fi);

    return err == FS_ERROR_NONE && !fi.is_dir && !fi.is_symlink;
}

FSDEF int
fs_is_dir(const char *path)
{
    if (!path) return 0;

    fs_internal_log_trace_path("Check is dir", path);

    Fs_FileInfo fi;
    Fs_Error err = fs_internal_fill_file_info(path, &fi);

    return err == FS_ERROR_NONE && fi.is_dir && !fi.is_symlink;
}

FSDEF Fs_Error
fs_read_file(const char *path,
             void      **data_out,
             size_t     *size_out)
{
    if (data_out) *data_out = NULL;
    if (size_out) *size_out = 0;

    if (!path || !data_out || !size_out) {
        fs_internal_log_error_path("read file", path, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    fs_internal_log_trace_path("Reading file", path);

    Fs_FileInfo fi;
    memset(&fi, 0, sizeof fi);

    Fs_Error err = fs_internal_fill_file_info(path, &fi);
    if (err != FS_ERROR_NONE) {
        fs_internal_log_error_path("read file", path, err);
        return err;
    }

    if (fi.size > (uint64_t)SIZE_MAX) {
        // Too large to fit in a size_t
        fs_internal_log_error_path("read file", path, FS_ERROR_OUT_OF_MEMORY);
        return FS_ERROR_OUT_OF_MEMORY;
    }

    size_t sz = (size_t)fi.size;

    // Always allocate at least 1 byte so *data_out is never NULL on success.
    size_t  alloc_size = (sz == 0) ? 1 : sz;
    void   *buf        = FS_REALLOC(NULL, alloc_size);
    if (!buf) {
        fs_internal_log_error_path("read file", path, FS_ERROR_OUT_OF_MEMORY);
        return FS_ERROR_OUT_OF_MEMORY;
    }

    size_t bytes_read = 0;
    err = fs_read_file_into(path, buf, sz, &bytes_read);
    if (err != FS_ERROR_NONE) {
        FS_FREE(buf);
        if (data_out) *data_out = NULL;
        if (size_out) *size_out = 0;
        return err;
    }

    *data_out = buf;
    *size_out = bytes_read;
    return FS_ERROR_NONE;
}

FSDEF Fs_Error
fs_read_file_into(const char *path,
                  void       *buffer,
                  size_t      buf_size,
                  size_t     *bytes_read_out)
{
    if (bytes_read_out) *bytes_read_out = 0;

    if (!path || (!buffer && buf_size > 0) || !bytes_read_out) {
        fs_internal_log_error_path("read file", path, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    fs_internal_log_trace_path("Reading file", path);

#ifdef _WIN32
    HANDLE h = CreateFileA(path,
                           GENERIC_READ,
                           FILE_SHARE_READ,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        Fs_Error mapped = fs_internal_win32_map_error(err);
        fs_internal_log_error_path("read file", path, mapped);
        return mapped;
    }

    uint8_t *p        = (uint8_t *)buffer;
    size_t   remaining = buf_size;

    while (remaining > 0) {
        DWORD chunk    = 0;
        DWORD to_read  = (remaining > (size_t)0xFFFFFFFFu)
                                    ? 0xFFFFFFFFu
                                    : (DWORD)remaining;

        if (!ReadFile(h, p, to_read, &chunk, NULL)) {
            DWORD err = GetLastError();
            CloseHandle(h);
            Fs_Error mapped = fs_internal_win32_map_error(err);
            fs_internal_log_error_path("read file", path, mapped);
            return mapped;
        }

        if (chunk == 0) {
            // EOF
            break;
        }

        p         += chunk;
        remaining -= (size_t)chunk;
    }

    if (!CloseHandle(h)) {
        DWORD err = GetLastError();
        Fs_Error mapped = fs_internal_win32_map_error(err);
        fs_internal_log_error_path("read file", path, mapped);
        return mapped;
    }

    *bytes_read_out = buf_size - remaining;
    return FS_ERROR_NONE;

#else
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        int e = errno;
        Fs_Error mapped = fs_internal_posix_map_errno(e);
        fs_internal_log_error_path("read file", path, mapped);
        return mapped;
    }

    uint8_t *p        = (uint8_t *)buffer;
    size_t   remaining = buf_size;

    while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n < 0) {
            int e = errno;
            close(fd);
            Fs_Error mapped = fs_internal_posix_map_errno(e);
            fs_internal_log_error_path("read file", path, mapped);
            return mapped;
        }
        if (n == 0) {
            // EOF
            break;
        }

        p         += (size_t)n;
        remaining -= (size_t)n;
    }

    if (close(fd) < 0) {
        int e = errno;
        Fs_Error mapped = fs_internal_posix_map_errno(e);
        fs_internal_log_error_path("read file", path, mapped);
        return mapped;
    }

    *bytes_read_out = buf_size - remaining;
    return FS_ERROR_NONE;
#endif
}

FSDEF Fs_Error
fs_write_file(const char *path,
              const void *data,
              size_t      size)
{
    if (!path || (!data && size > 0)) {
        fs_internal_log_error_path("write file", path, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    fs_internal_log_trace_path("Writing file", path);

#ifdef _WIN32
    HANDLE h = CreateFileA(path,
                           GENERIC_WRITE,
                           0, // no sharing
                           NULL,
                           CREATE_ALWAYS, // overwrite or create
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        Fs_Error mapped = fs_internal_win32_map_error(err);
        fs_internal_log_error_path("write file", path, mapped);
        return mapped;
    }

    const uint8_t *p         = (const uint8_t *)data;
    size_t         remaining = size;

    while (remaining > 0) {
        DWORD chunk     = 0;
        const DWORD limit   = 0xFFFFFFFFu;
        DWORD       to_write = (remaining > (size_t)limit)
                                          ? limit
                                          : (DWORD)remaining;

        if (!WriteFile(h, p, to_write, &chunk, NULL)) {
            DWORD err = GetLastError();
            CloseHandle(h);
            Fs_Error mapped = fs_internal_win32_map_error(err);
            fs_internal_log_error_path("write file", path, mapped);
            return mapped;
        }

        if (chunk == 0) {
            // Shouldn't happen unless the filesystem is weird/full
            CloseHandle(h);
            fs_internal_log_error_path("write file", path, FS_ERROR_GENERIC);
            return FS_ERROR_GENERIC;
        }

        p         += chunk;
        remaining -= (size_t)chunk;
    }

    if (!CloseHandle(h)) {
        DWORD err = GetLastError();
        Fs_Error mapped = fs_internal_win32_map_error(err);
        fs_internal_log_error_path("write file", path, mapped);
        return mapped;
    }

    fs_internal_log_info_path("Wrote file", path);
    return FS_ERROR_NONE;

#else
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        int e = errno;
        Fs_Error mapped = fs_internal_posix_map_errno(e);
        fs_internal_log_error_path("write file", path, mapped);
        return mapped;
    }

    const uint8_t *p         = (const uint8_t *)data;
    size_t         remaining = size;

    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            int e = errno;
            close(fd);
            Fs_Error mapped = fs_internal_posix_map_errno(e);
            fs_internal_log_error_path("write file", path, mapped);
            return mapped;
        }
        if (n == 0) {
            // Shouldn't happen under normal circumstances
            close(fd);
            fs_internal_log_error_path("write file", path, FS_ERROR_GENERIC);
            return FS_ERROR_GENERIC;
        }

        p         += (size_t)n;
        remaining -= (size_t)n;
    }

    if (close(fd) < 0) {
        int e = errno;
        Fs_Error mapped = fs_internal_posix_map_errno(e);
        fs_internal_log_error_path("write file", path, mapped);
        return mapped;
    }

    fs_internal_log_info_path("Wrote file", path);
    return FS_ERROR_NONE;
#endif
}

FSDEF Fs_Error
fs_move_file(const char *src,
             const char *dst,
             uint32_t    flags)
{
    if (!src || !dst) {
        fs_internal_log_error_path2("move file", src, dst, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    fs_internal_log_trace_path2("Moving file", src, dst);

#ifdef _WIN32
    // If overwrite is disallowed, fail early when dst exists.
    if (!(flags & FS_OP_OVERWRITE)) {
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesExA(dst, GetFileExInfoStandard, &fad)) {
            fs_internal_log_error_path2("move file", src, dst, FS_ERROR_FILE_ALREADY_EXISTS);
            return FS_ERROR_FILE_ALREADY_EXISTS;
        } else {
            DWORD err = GetLastError();
            if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
                Fs_Error mapped = fs_internal_win32_map_error(err);
                fs_internal_log_error_path2("move file", src, dst, mapped);
                return mapped;
            }
        }
    }

    DWORD move_flags = MOVEFILE_COPY_ALLOWED; // allow cross-volume moves
    if (flags & FS_OP_OVERWRITE) {
        move_flags |= MOVEFILE_REPLACE_EXISTING;
    }

    if (!MoveFileExA(src, dst, move_flags)) {
        DWORD err = GetLastError();
        Fs_Error mapped = fs_internal_win32_map_error(err);
        fs_internal_log_error_path2("move file", src, dst, mapped);
        return mapped;
    }

    fs_internal_log_info_path2("Moved file", src, dst);
    return FS_ERROR_NONE;

#else
    // POSIX: try rename() first.
    if (!(flags & FS_OP_OVERWRITE)) {
        struct stat st;
        if (lstat(dst, &st) == 0) {
            // Destination exists
            fs_internal_log_error_path2("move file", src, dst, FS_ERROR_FILE_ALREADY_EXISTS);
            return FS_ERROR_FILE_ALREADY_EXISTS;
        } else if (errno != ENOENT) {
            int e = errno;
            Fs_Error mapped = fs_internal_posix_map_errno(e);
            fs_internal_log_error_path2("move file", src, dst, mapped);
            return mapped;
        }
    }

    if (rename(src, dst) == 0) {
        fs_internal_log_info_path2("Moved file", src, dst);
        return FS_ERROR_NONE;
    }

    int e = errno;
    if (e != EXDEV) {
        // Some non-cross-device error
        Fs_Error mapped = fs_internal_posix_map_errno(e);
        fs_internal_log_error_path2("move file", src, dst, mapped);
        return mapped;
    }

    // Cross-device move: copy, then unlink.
    Fs_Error err = fs_copy_file(src, dst, flags);
    if (err != FS_ERROR_NONE) {
        return err;
    }

    if (unlink(src) < 0) {
        int ue = errno;
        Fs_Error mapped = fs_internal_posix_map_errno(ue);
        fs_internal_log_error_path2("move file", src, dst, mapped);
        return mapped;
    }

    fs_internal_log_info_path2("Moved file", src, dst);
    return FS_ERROR_NONE;
#endif
}

FSDEF Fs_Error
fs_copy_file(const char *src,
             const char *dst,
             uint32_t    flags)
{
    if (!src || !dst) {
        fs_internal_log_error_path2("copy file", src, dst, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    fs_internal_log_trace_path2("Copying file", src, dst);

#ifdef _WIN32
    BOOL fail_if_exists = (flags & FS_OP_OVERWRITE) ? FALSE : TRUE;

    if (!CopyFileA(src, dst, fail_if_exists)) {
        DWORD err = GetLastError();
        Fs_Error mapped = fs_internal_win32_map_error(err);
        fs_internal_log_error_path2("copy file", src, dst, mapped);
        return mapped;
    }

    fs_internal_log_info_path2("Copied file", src, dst);
    return FS_ERROR_NONE;

#else
    // POSIX: streaming copy
    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0) {
        int e = errno;
        Fs_Error mapped = fs_internal_posix_map_errno(e);
        fs_internal_log_error_path2("copy file", src, dst, mapped);
        return mapped;
    }

    int oflags = O_WRONLY | O_CREAT;
    if (flags & FS_OP_OVERWRITE) {
        oflags |= O_TRUNC;
    } else {
        oflags |= O_EXCL;   // fail if destination exists
    }

    int dst_fd = open(dst, oflags, 0666);
    if (dst_fd < 0) {
        int e = errno;
        close(src_fd);
        Fs_Error mapped = fs_internal_posix_map_errno(e);
        fs_internal_log_error_path2("copy file", src, dst, mapped);
        return mapped;
    }

    const size_t BUF_SIZE = 64 * 1024;
    uint8_t *buf = (uint8_t *)FS_REALLOC(NULL, BUF_SIZE);
    if (!buf) {
        // pure allocation failure; no meaningful errno
        close(src_fd);
        close(dst_fd);
        fs_internal_log_error_path2("copy file", src, dst, FS_ERROR_OUT_OF_MEMORY);
        return FS_ERROR_OUT_OF_MEMORY;
    }

    Fs_Error result = FS_ERROR_NONE;

    for (;;) {
        ssize_t n = read(src_fd, buf, BUF_SIZE);
        if (n < 0) {
            int e = errno;
            result = fs_internal_posix_map_errno(e);
            fs_internal_log_error_path2("copy file", src, dst, result);
            break;
        }
        if (n == 0) {
            // EOF
            break;
        }

        size_t written = 0;
        while (written < (size_t)n) {
            ssize_t w = write(dst_fd, buf + written, (size_t)n - written);
            if (w < 0) {
                int e = errno;
                result = fs_internal_posix_map_errno(e);
                fs_internal_log_error_path2("copy file", src, dst, result);
                goto copy_cleanup;
            }
            if (w == 0) {
                // Shouldn't happen, but treat as generic failure
                result = FS_ERROR_GENERIC;
                fs_internal_log_error_path2("copy file", src, dst, result);
                goto copy_cleanup;
            }
            written += (size_t)w;
        }
    }

copy_cleanup:
    FS_FREE(buf);

    int eclose = 0;
    if (close(src_fd) < 0) eclose = errno;
    if (close(dst_fd) < 0) eclose = errno;

    if (result == FS_ERROR_NONE && eclose) {
        result = fs_internal_posix_map_errno(eclose);
        fs_internal_log_error_path2("copy file", src, dst, result);
    }

    if (result != FS_ERROR_NONE) {
        // Best-effort cleanup of partial destination
        (void)unlink(dst);
    }

    if (result == FS_ERROR_NONE) {
        fs_internal_log_info_path2("Copied file", src, dst);
    }
    return result;
#endif
}

FSDEF Fs_Error
fs_delete_file(const char *path)
{
    if (!path) {
        fs_internal_log_error_path("delete file", path, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    fs_internal_log_trace_path("Deleting file", path);

#ifdef _WIN32
    if (DeleteFileA(path)) {
        fs_internal_log_info_path("Deleted file", path);
        return FS_ERROR_NONE;
    }

    DWORD err = GetLastError();
    Fs_Error mapped = fs_internal_win32_map_error(err);
    fs_internal_log_error_path("delete file", path, mapped);
    return mapped;
#else
    if (unlink(path) == 0) {
        fs_internal_log_info_path("Deleted file", path);
        return FS_ERROR_NONE;
    }

    int      e      = errno;
    Fs_Error mapped = fs_internal_posix_map_errno(e);
    fs_internal_log_error_path("delete file", path, mapped);
    return mapped;
#endif
}

FSDEF Fs_Error
fs_crc32_file(const char *path,
              uint32_t   *crc_out)
{
    if (crc_out) *crc_out             = 0;
    if (!path || !crc_out) {
        fs_internal_log_error_path("compute CRC32 for file", path, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    fs_internal_log_trace_path("Computing CRC32 for file", path);

    // Build CRC32 (IEEE) table locally each call (small + avoids global init races)
    uint32_t table[256];
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (uint32_t k = 0; k < 8; ++k) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        table[i] = c;
    }

    const size_t BUF_SIZE = 64 * 1024;
    uint8_t *buf = (uint8_t *)FS_REALLOC(NULL, BUF_SIZE);
    if (!buf) {
        // pure allocation failure; no meaningful errno/GetLastError
        fs_internal_log_error_path("compute CRC32 for file", path, FS_ERROR_OUT_OF_MEMORY);
        return FS_ERROR_OUT_OF_MEMORY;
    }

    Fs_Error result = FS_ERROR_NONE;
    uint32_t crc    = 0xFFFFFFFFu;

#ifdef _WIN32
    HANDLE h = CreateFileA(path,
                           GENERIC_READ,
                           FILE_SHARE_READ,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                           NULL);

    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        FS_FREE(buf);
        Fs_Error mapped = fs_internal_win32_map_error(e);
        fs_internal_log_error_path("compute CRC32 for file", path, mapped);
        return mapped;
    }

    for (;;) {
        DWORD n = 0;
        if (!ReadFile(h, buf, (DWORD)BUF_SIZE, &n, NULL)) {
            DWORD e = GetLastError();
            result = fs_internal_win32_map_error(e);
            fs_internal_log_error_path("compute CRC32 for file", path, result);
            break;
        }
        if (n == 0) {
            // EOF
            break;
        }

        for (DWORD i = 0; i < n; ++i) {
            crc = table[(crc ^ buf[i]) & 0xFFu] ^ (crc >> 8);
        }
    }

    DWORD eclose = 0;
    if (!CloseHandle(h)) eclose = GetLastError();

    if (result == FS_ERROR_NONE && eclose) {
        result = fs_internal_win32_map_error(eclose);
        fs_internal_log_error_path("compute CRC32 for file", path, result);
    }

#else
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        int e = errno;
        FS_FREE(buf);
        Fs_Error mapped = fs_internal_posix_map_errno(e);
        fs_internal_log_error_path("compute CRC32 for file", path, mapped);
        return mapped;
    }

    for (;;) {
        ssize_t n = read(fd, buf, BUF_SIZE);
        if (n < 0) {
            int e = errno;
            result = fs_internal_posix_map_errno(e);
            fs_internal_log_error_path("compute CRC32 for file", path, result);
            break;
        }
        if (n == 0) {
            // EOF
            break;
        }

        for (ssize_t i = 0; i < n; ++i) {
            crc = table[(crc ^ buf[(size_t)i]) & 0xFFu] ^ (crc >> 8);
        }
    }

    int eclose = 0;
    if (close(fd) < 0) eclose = errno;

    if (result == FS_ERROR_NONE && eclose) {
        result = fs_internal_posix_map_errno(eclose);
        fs_internal_log_error_path("compute CRC32 for file", path, result);
    }
#endif

    FS_FREE(buf);

    if (result != FS_ERROR_NONE) {
        *crc_out = 0;
        return result;
    }

    *crc_out = (crc ^ 0xFFFFFFFFu);
    return FS_ERROR_NONE;
}

FSDEF Fs_Error
fs_make_directory(const char *path,
                  uint32_t    flags)
{
    if (!path) {
        fs_internal_log_error_path("create directory", path, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    fs_internal_log_trace_path("Creating directory", path);

#ifdef _WIN32
    if (CreateDirectoryA(path, NULL)) {
        fs_internal_log_info_path("Created directory", path);
        return FS_ERROR_NONE;
    }

    DWORD err = GetLastError();

    if (err == ERROR_ALREADY_EXISTS) {
        DWORD attrs = GetFileAttributesA(path);
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            // We thought it existed, but now we can't stat it.
            DWORD attr_err = GetLastError();
            {
                Fs_Error mapped = fs_internal_win32_map_error(attr_err);
                fs_internal_log_error_path("create directory", path, mapped);
                return mapped;
            }
        }

        if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
            if (flags & FS_OP_REUSE_DIRS) {
                return FS_ERROR_NONE;
            } else {
                fs_internal_log_error_path("create directory", path, FS_ERROR_DIRECTORY_ALREADY_EXISTS);
                return FS_ERROR_DIRECTORY_ALREADY_EXISTS;
            }
        } else {
            // A non-directory exists at this path.
            fs_internal_log_error_path("create directory", path, FS_ERROR_FILE_ALREADY_EXISTS);
            return FS_ERROR_FILE_ALREADY_EXISTS;
        }
    }

    {
        Fs_Error mapped = fs_internal_win32_map_error(err);
        fs_internal_log_error_path("create directory", path, mapped);
        return mapped;
    }

#else
    if (mkdir(path, 0777) == 0) {
        fs_internal_log_info_path("Created directory", path);
        return FS_ERROR_NONE;
    }

    int e = errno;

    if (e == EEXIST) {
        struct stat st;
        if (stat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (flags & FS_OP_REUSE_DIRS) {
                    return FS_ERROR_NONE;
                } else {
                    fs_internal_log_error_path("create directory", path, FS_ERROR_DIRECTORY_ALREADY_EXISTS);
                    return FS_ERROR_DIRECTORY_ALREADY_EXISTS;
                }
            } else {
                // A non-directory exists at this path.
                fs_internal_log_error_path("create directory", path, FS_ERROR_FILE_ALREADY_EXISTS);
                return FS_ERROR_FILE_ALREADY_EXISTS;
            }
        } else {
            // mkdir said EEXIST but stat failed; just map the stat error.
            int st_e = errno;
            {
                Fs_Error mapped = fs_internal_posix_map_errno(st_e);
                fs_internal_log_error_path("create directory", path, mapped);
                return mapped;
            }
        }
    }

    {
        Fs_Error mapped = fs_internal_posix_map_errno(e);
        fs_internal_log_error_path("create directory", path, mapped);
        return mapped;
    }
#endif
}

FSDEF Fs_Error
fs_move_tree(const char *src_dir,
             const char *dst_dir,
             uint32_t    flags)
{
    if (!src_dir || !dst_dir) {
        fs_internal_log_error_path2("move directory tree", src_dir, dst_dir, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    fs_internal_log_trace_path2("Moving directory tree", src_dir, dst_dir);

    // Make sure src_dir exists and is actually a directory.
    Fs_FileInfo info     = FS_INTERNAL_ZERO_INIT;
    Fs_Error    info_err = fs_get_file_info(src_dir, &info);
    if (info_err != FS_ERROR_NONE) {
        return info_err;
    }
    if (!info.is_dir) {
        fs_file_info_free(&info);
        fs_internal_log_error_path("move directory tree", src_dir, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }
    fs_file_info_free(&info);

    // Step 1: copy tree
    Fs_Error copy_err = fs_copy_tree(src_dir, dst_dir, flags);
    if (copy_err != FS_ERROR_NONE) {
        return copy_err;
    }

    // Step 2: delete original tree
    Fs_Error del_err = fs_delete_tree(src_dir);
    if (del_err != FS_ERROR_NONE) {
        return del_err;
    }

    fs_internal_log_info_path2("Moved directory tree", src_dir, dst_dir);
    return FS_ERROR_NONE;
}

#ifndef _WIN32
static inline Fs_Error
fs_internal_posix_copy_symlink(const char *src,
                               const char *dst)
{
    size_t cap = 256;
    char *buf = NULL;

    for (;;) {
        char *nbuf = (char *)FS_REALLOC(buf, cap);
        if (!nbuf) {
            FS_FREE(buf);
            return FS_ERROR_OUT_OF_MEMORY;
        }
        buf = nbuf;

        ssize_t len = readlink(src, buf, cap - 1);
        if (len < 0) {
            Fs_Error mapped = fs_internal_posix_map_errno(errno);
            FS_FREE(buf);
            return mapped;
        }
        if ((size_t)len < cap - 1) {
            buf[len] = '\0';
            break;
        }
        cap *= 2;
    }

    if (symlink(buf, dst) != 0) {
        Fs_Error mapped = fs_internal_posix_map_errno(errno);
        FS_FREE(buf);
        return mapped;
    }

    FS_FREE(buf);
    return FS_ERROR_NONE;
}
#endif

FSDEF Fs_Error
fs_copy_tree(const char *src_dir,
             const char *dst_dir,
             uint32_t    flags)
{
    if (!src_dir || !dst_dir) {
        fs_internal_log_error_path2("copy directory tree", src_dir, dst_dir, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    fs_internal_log_trace_path2("Copying directory tree", src_dir, dst_dir);

    // Check that src_dir exists and is a directory
    Fs_FileInfo src_info = FS_INTERNAL_ZERO_INIT;
    Fs_Error    err      = fs_get_file_info(src_dir, &src_info);
    if (err != FS_ERROR_NONE) {
        return err;
    }
    if (!src_info.is_dir) {
        fs_file_info_free(&src_info);
        fs_internal_log_error_path("copy directory tree", src_dir, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    // Check / create dst_dir
    Fs_FileInfo dst_info = FS_INTERNAL_ZERO_INIT;
    Fs_Error    dst_err  = fs_internal_fill_file_info(dst_dir, &dst_info);

    if (dst_err == FS_ERROR_NONE) {
        // Destination exists
        if (!dst_info.is_dir) {
            fs_file_info_free(&src_info);
            fs_file_info_free(&dst_info);
            fs_internal_log_error_path("copy directory tree", dst_dir, FS_ERROR_FILE_IS_NOT_DIRECTORY);
            return FS_ERROR_FILE_IS_NOT_DIRECTORY;
        }
        if (!(flags & FS_OP_REUSE_DIRS)) {
            // Caller doesn't want to reuse existing directories
            fs_file_info_free(&src_info);
            fs_file_info_free(&dst_info);
            fs_internal_log_error_path("copy directory tree", dst_dir, FS_ERROR_DIRECTORY_ALREADY_EXISTS);
            return FS_ERROR_DIRECTORY_ALREADY_EXISTS;
        }
    } else if (dst_err == FS_ERROR_FILE_NOT_FOUND) {
        // Need to create the root destination directory
        Fs_Error mkerr = fs_make_directory(dst_dir, (flags & FS_OP_REUSE_DIRS) ? FS_OP_REUSE_DIRS
                                                                               : FS_OP_NONE);
        if (mkerr != FS_ERROR_NONE) {
            fs_file_info_free(&src_info);
            return mkerr;
        }
    } else {
        // Some other error querying dst_dir
        fs_file_info_free(&src_info);
        return dst_err;
    }

    fs_file_info_free(&src_info);
    fs_file_info_free(&dst_info);

    // Initialize walker on src_dir
    Fs_Walker w = FS_INTERNAL_ZERO_INIT;
    if (!fs_walker_init(&w, src_dir)) {
        // fs_walker_init fills w.error
        Fs_Error we = w.error ? w.error : FS_ERROR_GENERIC;
        fs_walker_free(&w);
        return we;
    }

    // Length of the root path, used to compute relative paths
    const char *root_path = w.root_info.path;
    size_t      root_len  = root_path ? strlen(root_path) : 0;

    Fs_Error result = FS_ERROR_NONE;

    const Fs_FileInfo *fi;
    while ((fi = fs_walker_next(&w)) != NULL) {
        const char *full_src = fi->path;

        // Compute relative path from src root
        const char *rel = full_src + root_len;
        if (rel[0] == '/' || rel[0] == '\\') {
            rel++;
        }

        // For the root itself, rel will be "" -> map directly to dst_dir
        char *dst_path = NULL;
        if (rel[0] == '\0') {
            // Entry is the root directory
            dst_path = fs_internal_strdup(dst_dir);
            if (!dst_path) {
                result = FS_ERROR_OUT_OF_MEMORY;
                break;
            }
        } else {
            dst_path = fs_internal_join(dst_dir, rel);
            if (!dst_path) {
                result = FS_ERROR_OUT_OF_MEMORY;
                break;
            }
        }
        fs_internal_normalize_seps(dst_path);

        if (fi->is_symlink) {
#ifdef _WIN32
            fs_internal_log_error_path("copy directory tree", full_src, FS_ERROR_SYMLINK_NOT_SUPPORTED);
            result = FS_ERROR_SYMLINK_NOT_SUPPORTED;
            FS_FREE(dst_path);
            break;
#else
            Fs_Error lerr = fs_internal_posix_copy_symlink(full_src, dst_path);
            if (lerr != FS_ERROR_NONE) {
                result = lerr;
                FS_FREE(dst_path);
                break;
            }
            FS_FREE(dst_path);
            continue;
#endif
        }

        if (fi->is_dir) {
            if (rel[0] == '\0') {
                // Root already ensured above; don't re-create it.
                FS_FREE(dst_path);
                continue;
            }
            Fs_Error mkerr = fs_make_directory(dst_path, (flags & FS_OP_REUSE_DIRS) ? FS_OP_REUSE_DIRS
                                                                                    : FS_OP_NONE);
            if (mkerr != FS_ERROR_NONE) {
                result = mkerr;
                FS_FREE(dst_path);
                break;
            }
            FS_FREE(dst_path);
        } else {
            // Copy regular file (and symlinks as files at their target)
            Fs_Error cperr = fs_copy_file(full_src, dst_path, flags);
            if (cperr != FS_ERROR_NONE) {
                result = cperr;
                FS_FREE(dst_path);
                break;
            }
            FS_FREE(dst_path);
        }
    }

    if (w.has_error && result == FS_ERROR_NONE) {
        // Walker itself encountered a filesystem error
        result = w.error ? w.error : FS_ERROR_GENERIC;
    }

    fs_walker_free(&w);
    if (result == FS_ERROR_NONE) {
        fs_internal_log_info_path2("Copied directory tree", src_dir, dst_dir);
    }
    return result;
}


FSDEF Fs_Error
fs_get_file_info(const char  *path,
                 Fs_FileInfo *out)
{
    if (!out) {
        fs_internal_log_error_path("get file info", path, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    if (!path) {
        fs_internal_log_error_path("get file info", path, FS_ERROR_GENERIC);
        return FS_ERROR_GENERIC;
    }

    if (out->path) {
        FS_FREE(out->path);
        out->path = NULL;
    }

    memset(out, 0, sizeof *out);

    fs_internal_log_trace_path("Get file info", path);

    Fs_Error err = fs_internal_fill_file_info(path, out);
    if (err != FS_ERROR_NONE) {
        memset(out, 0, sizeof *out);
        fs_internal_log_error_path("get file info", path, err);
        return err;
    }

    out->path = fs_internal_strdup(path);
    if (!out->path) {
        fs_file_info_free(out);
        fs_internal_log_error_path("get file info", path, FS_ERROR_OUT_OF_MEMORY);
        return FS_ERROR_OUT_OF_MEMORY;
    }
    fs_internal_normalize_seps(out->path);

    return FS_ERROR_NONE;
}

FSDEF void
fs_file_info_free(Fs_FileInfo *f)
{
    if (!f) return;
    FS_FREE(f->path);
    memset(f, 0, sizeof *f);
}

FSDEF Fs_Error
fs_delete_tree(const char *root)
{
    Fs_Error err = FS_ERROR_NONE;

    Fs_Walker w = FS_INTERNAL_ZERO_INIT;
    if (!fs_walker_init(&w, root)) {
        fs_internal_log_error_path("delete directory tree", root, w.error);
        return w.error;
    }

    fs_internal_log_trace_path("Deleting directory tree", root);

    char **dirs = NULL;
    size_t ndirs = 0, cap = 0;

    const Fs_FileInfo *fi;
    while ((fi = fs_walker_next(&w))) {
        if (fi->is_symlink) {
            // Delete symlink itself
#ifdef _WIN32
            if (fi->is_dir) {
                if (!RemoveDirectoryA(fi->path)) {
                    DWORD    last   = GetLastError();
                    Fs_Error mapped = fs_internal_win32_map_error(last);
                    fs_internal_set_error_if_none(&err, mapped);
                    fs_internal_log_error_path("delete directory", fi->path, mapped);
                }
            } else {
                if (!DeleteFileA(fi->path)) {
                    DWORD    last   = GetLastError();
                    Fs_Error mapped = fs_internal_win32_map_error(last);
                    fs_internal_set_error_if_none(&err, mapped);
                    fs_internal_log_error_path("delete file", fi->path, mapped);
                }
            }
#else
            if (unlink(fi->path) != 0) {
                Fs_Error mapped = fs_internal_posix_map_errno(errno);
                fs_internal_set_error_if_none(&err, mapped);
                fs_internal_log_error_path("delete file", fi->path, mapped);
            }
#endif
            continue;
        }

        if (!fi->is_dir) {
            // Delete file immediately
#ifdef _WIN32
            if (!DeleteFileA(fi->path)) {
                DWORD last = GetLastError();
                Fs_Error mapped = fs_internal_win32_map_error(last);
                fs_internal_set_error_if_none(&err, mapped);
                fs_internal_log_error_path("delete file", fi->path, mapped);
            }
#else
            if (unlink(fi->path) != 0) {
                Fs_Error mapped = fs_internal_posix_map_errno(errno);
                fs_internal_set_error_if_none(&err, mapped);
                fs_internal_log_error_path("delete file", fi->path, mapped);
            }
#endif
        } else {
            // Store for later
            if (ndirs == cap) {
                size_t new_cap = cap ? cap*2 : 16;
                char **tmp = (char **)FS_REALLOC(dirs, new_cap * sizeof(*tmp));
                if (!tmp) {
                    fs_internal_set_error_if_none(&err, FS_ERROR_OUT_OF_MEMORY);
                    fs_internal_log_error_path("delete directory tree", root, FS_ERROR_OUT_OF_MEMORY);
                    break;
                }
                dirs = tmp;
                cap  = new_cap;
            }
            dirs[ndirs++] = fs_internal_strdup(fi->path);
            if (!dirs[ndirs - 1]) {
                fs_internal_set_error_if_none(&err, FS_ERROR_OUT_OF_MEMORY);
                fs_internal_log_error_path("delete directory tree", root, FS_ERROR_OUT_OF_MEMORY);
                break;
            }
        }
    }

    if (w.has_error) {
        fs_internal_set_error_if_none(&err, w.error);
    }

    // Delete directories in reverse order
    for (size_t i = ndirs; i > 0; --i) {
        char *d = dirs[i - 1];
#ifdef _WIN32
        if (!RemoveDirectoryA(d)) {
            DWORD last = GetLastError();
            Fs_Error mapped = fs_internal_win32_map_error(last);
            fs_internal_set_error_if_none(&err, mapped);
            fs_internal_log_error_path("delete directory", d, mapped);
        }
#else
        if (rmdir(d) != 0) {
            Fs_Error mapped = fs_internal_posix_map_errno(errno);
            fs_internal_set_error_if_none(&err, mapped);
            fs_internal_log_error_path("delete directory", d, mapped);
        }
#endif
        FS_FREE(d);
    }

    FS_FREE(dirs);
    fs_walker_free(&w);

    if (err != FS_ERROR_NONE) {
        fs_internal_log_error_path("delete directory tree", root, err);
    }
    if (err == FS_ERROR_NONE) {
        fs_internal_log_info_path("Deleted directory tree", root);
    }
    return err;
}

FSDEF int
fs_walker_init(Fs_Walker  *w,
               const char *root)
{
    if (!w || !root) return 0;
    memset(w, 0, sizeof *w);

    fs_internal_log_trace_path("Walking directory", root);

    Fs_FileInfo *ri  = &w->root_info;
    Fs_Error     err = fs_internal_fill_file_info(root, ri);
    if (err != FS_ERROR_NONE) {
        w->has_error = 1;
        fs_internal_set_error_if_none(&w->error, err);
        fs_internal_log_error_path("walk directory", root, err);
        fs_internal_walker_cleanup(w);
        return 0;
    }

    ri->path = fs_internal_strdup(root);
    if (!ri->path) {
        fs_internal_walker_set_oom_error(w);
        fs_internal_log_error_path("walk directory", root, FS_ERROR_OUT_OF_MEMORY);
        fs_internal_walker_cleanup(w);
        return 0;
    }
    fs_internal_normalize_seps(ri->path);

    if (ri->is_dir && !ri->is_symlink) {
        if (!fs_internal_walker_push_frame(w, ri->path)) {
            fs_internal_walker_cleanup(w);
            return 0;
        }
    }

    w->yielded_root = 0;
    w->has_error    = 0;
    return 1;
}


FSDEF Fs_FileInfo *
fs_walker_next(Fs_Walker *w)
{
    if (!w)           return NULL;
    if (w->has_error) return NULL;

    fs_file_info_free(&w->current);

    // First call: yield root
    if (!w->yielded_root) {
        w->yielded_root = 1;
        fs_file_info_free(&w->current);

        w->current = w->root_info; // Copy metadata
        w->current.path = fs_internal_strdup(w->root_info.path);
        if (!w->current.path) {
            fs_internal_walker_set_oom_error(w);
            fs_internal_walker_cleanup(w);
            return NULL;
        }
        return &w->current;
    }

    for (;;) {
        if (w->len == 0) {
            return NULL; // done
        }

#ifdef _WIN32
        Fs_WalkerFrameWin *frame = &w->frames[w->len - 1];
        WIN32_FIND_DATAA  *fd    = &frame->data;

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
                    fs_internal_win32_walker_set_sys_error(w, err);
                    fs_internal_walker_cleanup(w);
                    return NULL;
                }
            }

            const char *name = fd->cFileName;
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                continue;
            }

            char *child = fs_internal_join(frame->dir_path, name);
            if (!child) {
                fs_internal_walker_set_oom_error(w);
                fs_internal_walker_cleanup(w);
                return NULL;
            }
            fs_internal_normalize_seps(child);

            Fs_Error err = fs_internal_fill_file_info(child, &w->current);
            if (err != FS_ERROR_NONE) {
                w->has_error = 1;
                fs_internal_set_error_if_none(&w->error, err);
                fs_internal_log_error_path("get file info", child, err);
                FS_FREE(child);
                fs_internal_walker_cleanup(w);
                return NULL;
            }

            w->current.path = child;

            if (w->current.is_dir && !w->current.is_symlink) {
                if (!fs_internal_walker_push_frame(w, child)) {
                    w->current.path = NULL;
                    FS_FREE(child);
                    fs_internal_walker_cleanup(w);
                    return NULL;
                }
            }

            return &w->current;
        }

#else
        Fs_WalkerFramePosix *frame = &w->frames[w->len - 1];
        struct dirent *ent;

        while ((ent = readdir(frame->dir)) != NULL) {
            const char *name = ent->d_name;
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                continue;
            }

            char *child = fs_internal_join(frame->dir_path, name);
            if (!child) {
                fs_internal_walker_set_oom_error(w);
                fs_internal_walker_cleanup(w);
                return NULL;
            }
            fs_internal_normalize_seps(child);

            Fs_Error err = fs_internal_fill_file_info(child, &w->current);
            if (err != FS_ERROR_NONE) {
                w->has_error = 1;
                fs_internal_set_error_if_none(&w->error, err);
                fs_internal_log_error_path("get file info", child, err);
                FS_FREE(child);
                fs_internal_walker_cleanup(w);
                return NULL;
            }

            w->current.path = child;

            if (w->current.is_dir && !w->current.is_symlink) {
                if (!fs_internal_walker_push_frame(w, child)) {
                    w->current.path = NULL;
                    FS_FREE(child);
                    fs_internal_walker_cleanup(w);
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

FSDEF void
fs_walker_free(Fs_Walker *w)
{
    if (!w) return;
    fs_internal_walker_cleanup(w);
    fs_file_info_free(&w->current);
    memset(w, 0, sizeof *w);
}

#if defined(FS_EMBED_LICENSE)
/**
 * LICENSE EMBEDDING
 * If FS_EMBED_LICENSE is defined in the same translation unit as
 * FS_IMPLEMENTATION, fs.h embeds its BSD-3-Clause license text into the
 * final program binary (as a static string).
 *
 * This can make it easier to satisfy license notice requirements for
 * binary distributions. You are still responsible for complying with the
 * BSD-3-Clause terms for your distribution.
 *
 * The author of this library considers embedding this notice in the
 * binary to be an acceptable way of reproducing the license text.
 */


// Must be implementation TU
#  if !defined(FS_IMPLEMENTATION)
#    error "FS_EMBED_LICENSE must be defined in the same translation unit as FS_IMPLEMENTATION."
#  endif

// Toolchain check
#  if !defined(_MSC_VER) && !defined(__clang__) && !defined(__GNUC__)
#    error "FS_EMBED_LICENSE is not supported on this toolchain (supported: MSVC, clang, GCC)."
#  endif


// toolchain / platform attributes
#  if defined(_MSC_VER)
#    pragma section(".fs_lic", read)
#    define FS_INTERNAL_ALLOCATE_LICENSE __declspec(allocate(".fs_lic"))
#    define FS_INTERNAL_USED
#    ifdef __cplusplus
#      define FS_INTERNAL_DEF extern "C"
#    else
#      define FS_INTERNAL_DEF extern
#    endif
#    if defined(_M_IX86)
#      pragma comment(linker, "/INCLUDE:_fs_embedded_license")
#      pragma comment(linker, "/INCLUDE:_fs_embedded_license_ptr")
#    else
#      pragma comment(linker, "/INCLUDE:fs_embedded_license")
#      pragma comment(linker, "/INCLUDE:fs_embedded_license_ptr")
#    endif
#  else /* GCC / Clang */
#    if defined(__APPLE__) || defined(__MACH__)
#      define FS_INTERNAL_ALLOCATE_LICENSE __attribute__((section("__DATA,__fs_lic"), used))
#    else
#      define FS_INTERNAL_ALLOCATE_LICENSE __attribute__((section(".fs_lic"), used))
#    endif
#    define FS_INTERNAL_USED __attribute__((used))
#    define FS_INTERNAL_DEF
#  endif

#  ifdef __cplusplus
extern "C" {
#  endif

FS_INTERNAL_DEF FS_INTERNAL_ALLOCATE_LICENSE
const char fs_embedded_license[] =
    "BSD-3-CLAUSE LICENSE\n"
    "\n"
    "Copyright 2025 rsore\n"
    "\n"
    "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n"
    "\n"
    "1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.\n"
    "\n"
    "2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.\n"
    "\n"
    "3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.\n"
    "\n"
    "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n";

FS_INTERNAL_DEF FS_INTERNAL_USED
const char *fs_embedded_license_ptr = fs_embedded_license;

#  ifdef __cplusplus
} /* extern "C" */
#  endif

#endif // FS_EMBED_LICENSE

FSDEF const char *
fs_license_text(void)
{
#ifdef FS_EMBED_LICENSE
    return fs_embedded_license;
#else
    return NULL;
#endif
}


#endif // FS_IMPLEMENTATION

#endif // FS_H_INCLUDED_


/**
 * BSD-3-CLAUSE LICENSE
 *
 * Copyright 2025 rsore
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
