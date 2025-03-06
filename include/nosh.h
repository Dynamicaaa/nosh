#ifndef NOSH_H
#define NOSH_H

#include <limits.h>

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

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#endif

// Shell initialization and cleanup (if needed in the future).
void init_shell(void);
void cleanup_shell(void);
void shell_loop(void);

#endif // NOSH_H
