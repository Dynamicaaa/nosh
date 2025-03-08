#ifndef NOSH_H
#define NOSH_H

#include "version.h"

// Platform-specific includes
#ifdef _WIN32
    #include <windows.h>
    // Remove PATH_MAX definition since it's already defined
    #include <direct.h>
    #define getcwd _getcwd
    #define chdir _chdir
    #define popen _popen
    #define pclose _pclose
    #define unlink _unlink
    // Windows glob emulation
    #define GLOB_NOMATCH 3
    typedef struct {
        size_t gl_pathc;
        char **gl_pathv;
        size_t gl_offs;
    } glob_t;
    int glob(const char *pattern, int flags, void *errfunc, glob_t *pglob);
    void globfree(glob_t *pglob);
#else
    #include <unistd.h>
    #include <glob.h>
    #include <sys/wait.h>
    #include <limits.h>
    #ifndef PATH_MAX
        #define PATH_MAX 4096
    #endif
#endif

// Global configuration and limits.
#define MAX_ARGS 64
#define MAX_HISTORY 100
#define MAX_ALIASES 10

// ANSI color codes for prompt customization.
#define COLOR_BLUE "\033[1;34m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_RESET "\033[0m"

// ANSI escape sequence to clear screen (including scrollback, works on macOS Terminal).
#define CLEAR_SEQUENCE "\033[H\033[2J\033[3J"

// Shell initialization and cleanup (if needed in the future).
void init_shell(void);
void cleanup_shell(void);
void shell_loop(void);

#endif // NOSH_H
