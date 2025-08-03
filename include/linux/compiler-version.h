#ifndef __LINUX_COMPILER_VERSION_H
#define __LINUX_COMPILER_VERSION_H

/* Minimal shim for builds that -include this file */
#ifdef __clang__
# define LINUX_COMPILER_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
# define LINUX_COMPILER_IS_CLANG 1
#else
# define LINUX_COMPILER_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
# define LINUX_COMPILER_IS_GCC 1
#endif

#endif /* __LINUX_COMPILER_VERSION_H */
