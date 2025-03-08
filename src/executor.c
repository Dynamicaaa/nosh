#include "nosh.h"  // Must be first to get platform-specific headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "executor.h"
#include "builtins.h"

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#include <glob.h>  // Only include glob.h on non-Windows platforms
#endif

#define MAX_ARGS 64

static int expand_wildcards(char *arg, char **expanded_args, int max_args, int *arg_count) {
    glob_t globbuf;
    memset(&globbuf, 0, sizeof(glob_t));

    // Use GLOB_TILDE to expand ~ to home directory
    int ret = glob(arg, GLOB_TILDE, NULL, &globbuf);

    if (ret == GLOB_NOMATCH || globbuf.gl_pathc == 0) {
        // No matches found, use the original argument
        expanded_args[(*arg_count)++] = arg;
        globfree(&globbuf);
        return 0;
    } else if (ret != 0) {
        // Error in globbing, use the original argument
        expanded_args[(*arg_count)++] = arg;
        return 0;
    }

    // Found matches, copy them to expanded_args
    int expanded = 0;
    for (size_t i = 0; i < globbuf.gl_pathc && *arg_count < max_args; i++) {
        expanded_args[(*arg_count)++] = strdup(globbuf.gl_pathv[i]);
        expanded = 1;
    }

    globfree(&globbuf);
    return expanded;
}

static char* sanitize_command(const char* input) {
  char* sanitized = strdup(input);
  if (!sanitized) return NULL;

    // In XNU mode, replace potentially dangerous shell operators
    if (is_xnu_mode_enabled()) {
      for (char* p = sanitized; *p; p++) {
        // Remove shell metacharacters that could be used for command chaining/injection
        if (*p == ';' || *p == '|' || *p == '&' ||
          *p == '`' || *p == '$' ||
          (*p == '>' && *(p-1) != '2') || *p == '<') {
            *p = ' ';
          }
      }
    }

    return sanitized;
}

static char* expand_env_vars(const char* input) {
    static char expanded[1024];
    char temp[1024];
    strncpy(temp, input, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    size_t i = 0, j = 0;

    while (temp[i] && j < sizeof(expanded) - 1) {
        if (temp[i] == '$' && temp[i+1] != '\0' && temp[i+1] != ' ' && temp[i+1] != '\t') {
            i++; // Skip the $

            // Extract variable name
            char var_name[256] = {0};
            size_t name_len = 0;

            while (temp[i] && temp[i] != ' ' && temp[i] != '\t' &&
                   temp[i] != '/' && temp[i] != '$' && name_len < 255) {
                var_name[name_len++] = temp[i++];
            }
            var_name[name_len] = '\0';

            // Lookup and substitute the environment variable
            char *var_value = getenv(var_name);
            if (var_value) {
                size_t value_len = strlen(var_value);
                if (j + value_len < sizeof(expanded) - 1) {
                    strcpy(expanded + j, var_value);
                    j += value_len;
                }
            }
        } else {
            expanded[j++] = temp[i++];
        }
    }

    expanded[j] = '\0';
    return expanded;
}

void execute_command(char *input) {
    // First sanitize the command if in XNU mode
    char *sanitized_input = NULL;
    char *working_input = input;

    if (is_xnu_mode_enabled()) {
        sanitized_input = sanitize_command(input);
        if (sanitized_input) {
            working_input = sanitized_input;
        }
    }

    working_input = expand_env_vars(working_input);

    char input_copy[1024];
    strncpy(input_copy, working_input, sizeof(input_copy));
    input_copy[1023] = '\0';
    int background = 0;
    size_t len = strlen(input_copy);
    if (len > 0 && input_copy[len - 1] == '&') {
        background = 1;
        input_copy[len - 1] = '\0';  // Remove '&'
    }

    // First, tokenize the input into arguments
    char *tokens[MAX_ARGS];
    int token_count = 0;
    char *token;
    char *saveptr;
    token = strtok_r(input_copy, " \t", &saveptr);
    while (token && token_count < MAX_ARGS - 1) {
        tokens[token_count++] = token;
        token = strtok_r(NULL, " \t", &saveptr);
    }
    if (token_count == 0) {
        if (sanitized_input) free(sanitized_input);
        return;
    }

    // Now expand wildcards in each argument
    char *args[MAX_ARGS];
    int argc = 0;
    int expanded = 0;

    for (int i = 0; i < token_count && argc < MAX_ARGS - 1; i++) {
        // Try to expand wildcards for all arguments
        int result = expand_wildcards(tokens[i], args, MAX_ARGS - 1, &argc);
        expanded |= result;
    }
    args[argc] = NULL;
    if (argc == 0) {
        if (sanitized_input) free(sanitized_input);
        return;
    }

    // Execute the command with expanded arguments
#ifdef _WIN32
    // Windows implementation remains the same
    int mode = background ? _P_NOWAIT : _P_WAIT;
    int ret = _spawnvp(mode, args[0], args);
    if (ret == -1) {
        if (errno == ENOENT) {
            fprintf(stderr, "nosh: %s: command not found\n", args[0]);
        } else {
            fprintf(stderr, "nosh: %s: %s\n", args[0], strerror(errno));
        }
    }
#else
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        if (sanitized_input) free(sanitized_input);
        return;
    }
    if (pid == 0) {
        if (execvp(args[0], args) < 0) {
            // Customize error message based on errno
            if (errno == ENOENT) {
                fprintf(stderr, "nosh: %s: command not found\n", args[0]);
            } else {
                fprintf(stderr, "nosh: %s: %s\n", args[0], strerror(errno));
            }
            exit(EXIT_FAILURE);
        }
    } else {
        if (!background) {
            int status;
            waitpid(pid, &status, 0);
        } else {
            printf("Process %d running in background\n", pid);
        }
    }
#endif

    // Free duplicated strings if we expanded any wildcards
    if (expanded) {
        for (int i = 0; i < argc; i++) {
            if (args[i] != tokens[i]) {  // This is a duplicated string from expansion
                free(args[i]);
            }
        }
    }
    if (sanitized_input) {
        free(sanitized_input);
    }
}
