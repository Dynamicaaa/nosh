#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "environment.h"

// Handle platform-specific environment functions
#ifdef _WIN32
    #include <windows.h>
    #define setenv(name, value, overwrite) _putenv_s(name, value)
    extern char **_environ;
    #define environ _environ
#else
    extern char **environ;
#endif

// Load .noshrc configuration file
void load_noshrc(void) {
    char noshrc_path[PATH_MAX];
    char *home = getenv("HOME");

    if (!home) return;

    snprintf(noshrc_path, sizeof(noshrc_path), "%s/.noshrc", home);

    FILE *fp = fopen(noshrc_path, "r");
    if (!fp) return; // No .noshrc file exists yet

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n')
            line[len-1] = '\0';

        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\0')
            continue;

        // Handle export commands in .noshrc
        if (strncmp(line, "export ", 7) == 0) {
            handle_export(line + 7);
        }
    }

    fclose(fp);
}

// Add or update an environment variable
int handle_export(const char *export_str) {
    char var_name[256] = {0};
    char var_value[1024] = {0};

    // Handle the case of just variable name without value
    if (strchr(export_str, '=') == NULL) {
        // Just print the current value if it exists
        printf("%s=%s\n", export_str, getenv(export_str) ? getenv(export_str) : "");
        return 1;
    }

    // Parse VAR=VALUE format
    int i = 0, j = 0;
    while (export_str[i] && export_str[i] != '=' && i < 255) {
        var_name[i] = export_str[i];
        i++;
    }
    var_name[i] = '\0';

    // Skip the equals sign
    if (export_str[i] == '=') i++;

    // Get the value part
    while (export_str[i] && j < 1023) {
        var_value[j++] = export_str[i++];
    }
    var_value[j] = '\0';

    // Set the environment variable
    if (var_name[0] != '\0') {
        #ifdef _WIN32
        if (_putenv_s(var_name, var_value) != 0) {
            perror("export: _putenv_s");
            return 0;
        }
        #else
        if (setenv(var_name, var_value, 1) != 0) {
            perror("export: setenv");
            return 0;
        }
        #endif
    }

    return 1;
}

// Print all environment variables
void print_environment(void) {
    char **env = environ;

    while (*env) {
        printf("%s\n", *env);
        env++;
    }
}

// Get current shell's PATH
char *get_path(void) {
    return getenv("PATH");
}
