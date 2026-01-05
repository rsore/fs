# fs.h

[![CI](https://github.com/rsore/fs/actions/workflows/test.yml/badge.svg)](https://github.com/rsore/fs/actions/workflows/test.yml)
[![CI](https://github.com/rsore/fs/actions/workflows/build_examples.yml/badge.svg)](https://github.com/rsore/fs/actions/workflows/build_examples.yml)

`fs.h` is a single-header C and C++ library implementing a small,
cross-platform API for file system interaction, with no external dependencies,
targeting Windows and POSIX systems.

The library focuses on predictable file and directory operations with a minimal
surface area and direct mappings to platform behavior.

---

## Project integration

`fs.h` is a single-header library, so integrating it into your project is
straight-forward. Drop the header file into your project tree and, in exactly
**one** of your translation units, define `FS_IMPLEMENTATION` before including it:

```c
#define FS_IMPLEMENTATION
#include "fs.h"
```

This causes `fs.h` to emit its function definitions into that translation unit.
In all other files that include `fs.h`, only the public API declarations are visible.

This works for both C and C++ translation units.

---

## Example

```c
#define FS_IMPLEMENTATION
#include "fs.h"

int main(void)
{
    const char *path = "hello.txt";
    const char *msg  = "Hello from fs.h\n";

    if (fs_write_file(path, msg, 17) != FS_ERROR_NONE) return 1;

    void *data = NULL;
    size_t size = 0;
    if (fs_read_file(path, &data, &size) != FS_ERROR_NONE) return 2;

    fwrite(data, 1, size, stdout);
    FS_FREE(data);

    return 0;
}
```

---

## Logging and diagnostics

By default, `fs.h` performs **no logging and produces no stdout/stderr output** of its own.
All informational and error messages are disabled unless explicitly enabled by the user.

Logging can be enabled by defining one of the following macros **before** including `fs.h`,
in the **same** translation unit as you define `FS_IMPLEMENTATION`:

```c
#define FS_LOG(level, msg) fprintf(stderr, "%s: %s\n", fs_log_level_to_str(level), msg)
```

Or use the built-in simple logger:

```c
#define FS_USE_SIMPLE_LOGGER
```

At runtime you can also provide a logger:

```c
fs_set_logger(my_logger_fn, my_user_data);
```

---

## Tested platforms and compilers

### Linux
- **Compilers:** GCC 14, Clang 20
- **C standards:** C99, C11, C17, C23
- **C++ standards:** C++11, C++14, C++17, C++20, C++23, C++26
- **Flags:** `-Wall -Wextra -Werror -pedantic-errors`

### Windows
- **Compiler:** MSVC 2022 (cl)
- **C standards:** C11, C17
- **C++ standards:** C++14, C++17, C++20, C++latest
- **Flags:** `/W4 /WX`

### macOS
- **Compiler:** Apple Clang (latest)
- **C standards:** C99, C11, C17, C2x
- **C++ standards:** C++11, C++14, C++17, C++20, C++2b
- **Flags:** `-Wall -Wextra -Werror -pedantic-errors`

---

## License

`fs.h` is licensed under the 3-Clause BSD license.
See the `LICENSE` file for details.

If you want to embed the license text in your binary, define
`FS_EMBED_LICENSE` in the same translation unit as `FS_IMPLEMENTATION`
and call `fs_license_text()` to retrieve it at runtime.
