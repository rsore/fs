#!/bin/bash

set -xe

THIS_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
pushd "$THIS_DIR"

CC="cc"
CFLAGS="-Wall -Wextra -pedantic -ggdb"

$CC $CFLAGS -o 01_basic       01_basic.c
$CC $CFLAGS -o 02_copy_tree   02_copy_tree.c
$CC $CFLAGS -o 03_file_info   03_file_info.c
$CC $CFLAGS -o 04_crc32       04_crc32.c
$CC $CFLAGS -o 05_walk_tree   05_walk_tree.c
$CC $CFLAGS -o 06_copy_move   06_copy_move.c
$CC $CFLAGS -o 07_delete_tree 07_delete_tree.c

popd
