#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include "nosh.h"
#include "builtins.h"
#include "executor.h"
#include "history.h"
#include "aliases.h"
#include "password.h"
#include "environment.h"

#ifdef _WIN32
#include <editline/readline.h>
#else
#include <readline/readline.h>
#include <readline/history.h>
#endif

// This flag ensures we only clear the screen on actual exit, not on errors
static int actually_exiting = 0;

void cleanup_on_exit(void) {
    // Clear terminal scrollback buffer only if actually exiting and in XNU mode
    if (actually_exiting && is_xnu_mode_enabled()) {
        printf("%s", CLEAR_SEQUENCE);
        fflush(stdout);
    }

    // Always clear any sensitive data from memory
    clear_master_key();
}

// Print version information and exit
void print_version(void) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    int current_year = tm->tm_year + 1900;
    
    printf("nosh version %s\n", NOSH_VERSION);
    printf("A secure, customizable shell with privacy features\n");
    printf("Copyright (c) %d Dynamicaaa\n", current_year);
}

int main(int argc, char *argv[]) {
    // Process command-line arguments first
    for (int i = 1; i < argc; i++) {
        // Check for version flag
        if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            print_version();
            return 0;
        }
    }

    char hostname[256];
    char *username = getlogin();
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strncpy(hostname, "unknown", sizeof(hostname));
        hostname[sizeof(hostname)-1] = '\0';
    }
    if (username == NULL) {
        username = "unknown";
    }

    // Register cleanup handler for memory sanitization only
    atexit(cleanup_on_exit);

    // Load XNU mode state first
    load_xnu_mode();

    // Load noshrc configuration
    load_noshrc();

    // Process command-line arguments
    if (argc > 1 && strcmp(argv[1], "--xnu") == 0) {
        if (!is_xnu_mode_enabled()) {
            enable_xnu_mode(); // Only toggle if not already enabled
        }
    }

    // Load aliases only if XNU mode is not enabled
    if (!is_xnu_mode_enabled()) {
        load_aliases();
    }

    // Custom prompt
    rl_set_prompt("\033[1;32mnosh\033[0m$ ");

    while (1) {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            strncpy(cwd, "unknown", sizeof(cwd));
            cwd[sizeof(cwd)-1] = '\0';
        }

        // Display user info
        printf("\033[1;32m%s@%s\033[0m:\033[1;34m%s\033[0m", username, hostname, cwd);

        // Show XNU mode indicator if enabled
        if (is_xnu_mode_enabled()) {
            printf(" \033[1;31m[XNU]\033[0m");
        }
        printf("\n");

        // Input prompt
        char *input = readline("$ ");

        if (input == NULL) {
            // Set the flag for actual exit
            actually_exiting = 1;
            break;
        }

        // Only add to history if not in XNU mode
        if (strlen(input) > 0 && !is_xnu_mode_enabled()) {
            nosh_add_history(input);
            add_history(input);
        }

        // Handle exit command
        if (strcmp(input, "exit") == 0) {
            // Set the flag for actual exit before clearing screen
            actually_exiting = 1;
            free(input);
            break;
        }

        // Handle XNU toggle directly
        if (strcmp(input, "xnu") == 0) {
            enable_xnu_mode();
            free(input);
            continue;
        }

        // Only do alias substitution if not in XNU mode
        if (!is_xnu_mode_enabled()) {
            substitute_alias(input);
        }

        // Process other builtins or execute command
        if (handle_builtin(input)) {
            free(input);
            continue;
        }

        execute_command(input);
        free(input);
    }

    return 0;
}
