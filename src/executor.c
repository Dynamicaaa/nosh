#define GLOB_IMPLEMENTATION  // Only define implementation in one file
#include "nosh.h"  // Must be first to get platform-specific headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>  // Add for struct stat
#include <sys/types.h> // Add for uid_t
#ifndef NO_PWD_H
#include <pwd.h>
#else
// Windows alternatives
#include <windows.h>
#include <shlobj.h>
#endif
#include <time.h>      // Add this for time() and ctime()
#include "executor.h"
#include "builtins.h"

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <pwd.h>
#include <unistd.h>
#endif

// Update the XNU config structure
static struct {
    int block_path_traversal;     // Block ../../../ patterns
    int enforce_file_perms;       // Check file permissions
    int restrict_net_access;      // Restrict network access
    int audit_enabled;            // Enable audit logging
} xnu_config = {1, 1, 1, 0};      // Audit disabled by default

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

// Add path traversal check function
static int contains_path_traversal(const char *path) {
    if (!path) return 0;
    
    const char *p = path;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\\'))
            return 1;
        p++;
    }
    return 0;
}

// Add audit logging function
static void audit_log(const char *cmd, const char *result) {
    if (!xnu_config.audit_enabled) return;
    
    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp)-1] = 0; // Remove newline
    
    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/.nosh/audit.log", getenv("HOME"));
    FILE *log = fopen(log_path, "a");
    if (log) {
        fprintf(log, "[%s] CMD: %s | RESULT: %s\n", timestamp, cmd, result);
        fclose(log);
    }
}

// Add enhanced security checks to command execution

static int check_command_security(const char *cmd) {
    if (!is_xnu_mode_enabled()) {
        // Log regular commands to command history log
        time_t now = time(NULL);
        char *timestamp = ctime(&now);
        timestamp[strlen(timestamp)-1] = 0; // Remove newline
        
        char log_path[PATH_MAX];
        snprintf(log_path, sizeof(log_path), "%s/.nosh/command_history.log", getenv("HOME"));
        FILE *log = fopen(log_path, "a");
        if (log) {
            fprintf(log, "[%s] %s\n", timestamp, cmd);
            fclose(log);
        }
        return 1;
    }

    // XNU mode security checks
    if (xnu_config.block_path_traversal && contains_path_traversal(cmd)) {
        fprintf(stderr, "Error: Path traversal attempts blocked in XNU mode\n");
        return 0;
    }

    // Add file permission checks
    if (xnu_config.enforce_file_perms) {
#ifdef _WIN32
    // Windows-specific user check
    HANDLE hToken;
    DWORD dwSize = 0;
    PTOKEN_USER pTokenUser = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        // Get the required buffer size
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
        if (dwSize) {
            pTokenUser = (PTOKEN_USER)malloc(dwSize);
            if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
                // Use pTokenUser->User.Sid to check permissions
                BOOL isAdmin = FALSE;
                SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
                PSID adminGroup;
                
                if (AllocateAndInitializeSid(&NtAuthority, 2,
                    SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                    0, 0, 0, 0, 0, 0, &adminGroup)) {
                    CheckTokenMembership(NULL, adminGroup, &isAdmin);
                    FreeSid(adminGroup);
                }
                
                if (!isAdmin) {
                    // Non-admin user, perform security check
                    // Add your security logic here
                }
            }
            free(pTokenUser);
        }
        CloseHandle(hToken);
    }
#else
    uid_t uid = getuid();
        struct stat st;
        if (stat(cmd, &st) == 0) {
            // Only allow execution of files owned by root or current user
            if (st.st_uid != 0 && st.st_uid != uid) {
                fprintf(stderr, "Error: XNU mode restricts execution to root/user owned files\n");
                return 0;
            }
        }
#endif
    }

    return 1;
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
    int mode = background ? _P_NOWAIT : _P_WAIT;
    // Cast args to the correct type for _spawnvp
    int ret = _spawnvp(mode, args[0], (const char* const*)args);
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
        if (!check_command_security(args[0])) {
            exit(EXIT_FAILURE);
        }
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
            // Log the result of the command execution
            audit_log(args[0], WIFEXITED(status) && WEXITSTATUS(status) == 0 ? "SUCCESS" : "FAILURE");
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
