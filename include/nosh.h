#ifndef NOSH_H
#define NOSH_H

#include "version.h"  // Add this line at the top

// Platform-specific includes
#ifdef _WIN32
    #include <windows.h>
    #define PATH_MAX MAX_PATH
    #define strdup _strdup
    #include <direct.h>
    #define getcwd _getcwd
    #define chdir _chdir
    #define popen _popen
    #define pclose _pclose
    #define unlink _unlink
#else
    #include <unistd.h>
    #include <glob.h>
    #include <sys/wait.h>
    #include <limits.h>  // For PATH_MAX on Unix systems
    #ifndef PATH_MAX
        #define PATH_MAX 4096 // Fallback value if not defined
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
