#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "builtins.h"
#include "aliases.h"
#include "history.h"
#include "nosh.h"
#include "password.h"
#include "network.h"
#include "environment.h"

#define MAX_ARGS 64

static int xnu_mode = 0;
static char xnu_file_path[PATH_MAX] = "";

// Saves the XNU mode state to a configuration file
static void update_xnu_mode_file(void) {
    if (xnu_file_path[0] == '\0') {
        char *home = getenv("HOME");
        if (home)
            snprintf(xnu_file_path, sizeof(xnu_file_path), "%s/.nosh_xnu_mode", home);
        else
            return;
    }

    if (xnu_mode) {
        // Create the file if XNU mode is enabled
        FILE *fp = fopen(xnu_file_path, "w");
        if (fp) {
            fprintf(fp, "enabled\n");
            fclose(fp);
        }
    } else {
        // Remove the file if XNU mode is disabled
        remove(xnu_file_path);
    }
}

// Loads the XNU mode state from configuration file
void load_xnu_mode(void) {
    char *home = getenv("HOME");
    if (!home) return;

    snprintf(xnu_file_path, sizeof(xnu_file_path), "%s/.nosh_xnu_mode", home);
    FILE *fp = fopen(xnu_file_path, "r");
    if (fp) {
        // File exists, enable XNU mode
        xnu_mode = 1;
        fclose(fp);
    } else {
        // File doesn't exist, disable XNU mode
        xnu_mode = 0;
    }
}

void enable_xnu_mode(void) {
  xnu_mode = !xnu_mode;  // Toggle XNU mode
  update_xnu_mode_file(); // Save the current XNU mode state

    if (xnu_mode) {
      printf("XNU mode enabled: Enhanced privacy and security features activated.\n");
      printf("- Command history disabled\n");
      printf("- Aliases disabled\n");
      printf("- Command sanitization enabled\n");
      printf("- History file access restricted\n");
    } else {
      printf("XNU mode disabled: Normal shell behavior restored.\n");
    }
}

int is_xnu_mode_enabled(void) {
    return xnu_mode;
}

int handle_secure_wipe(int argc, char **args) {
  if (argc < 2) {
    printf("Usage: wipe <file1> [file2 ...]\n");
    return 1;
  }

    for (int i = 1; i < argc; i++) {
      struct stat st;
      if (stat(args[i], &st) != 0) {
        perror("wipe: stat");
        continue;
      }

        // Only wipe regular files
        if (!S_ISREG(st.st_mode)) {
          printf("wipe: %s: Not a regular file\n", args[i]);
          continue;
        }

        int fd = open(args[i], O_WRONLY);
        if (fd < 0) {
          perror("wipe: open");
          continue;
        }

        // Get file size
        off_t size = st.st_size;

        // Allocate a buffer of zeros
        const int BLOCK_SIZE = 4096;
        char *zeros = calloc(1, BLOCK_SIZE);
        if (!zeros) {
          close(fd);
          perror("wipe: calloc");
          continue;
        }

        // Overwrite file with zeros
        printf("Securely wiping %s (%ld bytes)...\n", args[i], (long)size);
        for (off_t offset = 0; offset < size; offset += BLOCK_SIZE) {
          ssize_t to_write = (size - offset < BLOCK_SIZE) ? (size - offset) : BLOCK_SIZE;
          if (write(fd, zeros, to_write) != to_write) {
            perror("wipe: write");
            break;
          }
        }

        // Free buffer and close file
        free(zeros);
        close(fd);

        // Finally, unlink (delete) the file
        if (unlink(args[i]) != 0) {
          perror("wipe: unlink");
        } else {
          printf("File %s securely wiped and deleted.\n", args[i]);
        }
    }

    return 1;
}

int handle_builtin(char *input) {
    char *args[MAX_ARGS];
    int argc = 0;
    char *token;
    char *saveptr;
    char temp[1024];
    strncpy(temp, input, sizeof(temp));
    temp[1023] = '\0';
    token = strtok_r(temp, " \t", &saveptr);
    while (token && argc < MAX_ARGS - 1) {
        args[argc++] = token;
        token = strtok_r(NULL, " \t", &saveptr);
    }
    args[argc] = NULL;
    if (argc == 0) return 0;

    if (strcmp(args[0], "cd") == 0) {
        char *dir = (argc > 1) ? args[1] : getenv("HOME");
        if (chdir(dir) != 0) {
            perror("cd");
        }
        return 1;
    }
    if (strcmp(args[0], "pwd") == 0) {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            printf("%s\n", cwd);
        } else {
            perror("pwd");
        }
        return 1;
    }
    if (strcmp(args[0], "clear") == 0) {
        printf("%s", CLEAR_SEQUENCE);
        fflush(stdout);
        return 1;
    }
    if (strcmp(args[0], "help") == 0) {
        printf("nosh - a secure, customizable shell\n\n");

        printf("Basic Commands:\n");
        printf("  cd [dir]           : Change directory (default HOME)\n");
        printf("  pwd                : Print current working directory\n");
        printf("  clear              : Clear the terminal\n");
        printf("  history            : Show command history\n");
        printf("  clear-history      : Clear command history\n");
        printf("  alias [name] [cmd] : Define an alias or list all if no args\n");
        printf("  unalias [name]     : Remove an alias\n");
        printf("  version            : Show shell version\n");
        printf("  help               : Display this help message\n");
        printf("  exit               : Exit the shell\n\n");

        printf("Environment Commands:\n");
        printf("  export VAR=VALUE   : Set an environment variable\n");
        printf("  export VAR         : Display an environment variable\n");
        printf("  export             : List all environment variables\n");
        printf("  env                : Show all environment variables\n");
        printf("  echo [args...]     : Display arguments with expansion\n\n");

        printf("Wildcard Support:\n");
        printf("  *                  : Matches any sequence of characters\n");
        printf("  ?                  : Matches any single character\n");
        printf("  [...]              : Matches any character in brackets\n");
        printf("  ~                  : Expands to HOME directory\n");
        printf("  Examples: ls *.txt, echo /etc/*.conf, cat ~/README*\n\n");

        printf("Security Commands:\n");
        printf("  xnu                : Toggle XNU hardened security mode\n");
        printf("  wipe <file>        : Securely erase and delete a file\n");
        printf("  citrus init        : Initialize password manager\n");
        printf("  citrus add s u     : Add password for service/username\n");
        printf("  citrus get s u     : Retrieve password for service/username\n");
        printf("  citrus list        : List all stored services\n");
        printf("  network ports      : List open ports on your system\n");
        printf("  network connections: Show active network connections\n");
        printf("  network suspicious : Check for suspicious network activity\n");
        printf("  network scan       : Run a basic network security scan\n");
        printf("  network interfaces : Show network interface information\n");
        printf("  network firewall   : Check firewall status\n\n");

        printf("XNU Mode Features:\n");
        printf("  - Disables command history (incognito mode)\n");
        printf("  - Disables alias substitution\n");
        printf("  - Sanitizes commands to prevent injection attacks\n");
        printf("  - Persists settings across shell sessions\n");
        printf("  - Clears terminal on exit\n\n");

        printf("Security Best Practices:\n");
        printf("  1. Use XNU mode when entering sensitive commands\n");
        printf("  2. Use 'wipe' instead of 'rm' for sensitive files\n");
        printf("  3. Check network security regularly with 'network scan'\n");
        printf("  4. Use the password manager for secure credentials\n");
        printf("  5. Run 'clear-history' after sensitive operations\n");

        return 1;
    }
    if (strcmp(args[0], "history") == 0) {
        if (!xnu_mode) {
            print_history();
        } else {
            printf("History is disabled in XNU mode.\n");
        }
        return 1;
    }
    if (strcmp(args[0], "clear-history") == 0) {
        if (!xnu_mode) {
            clear_history();
        } else {
            printf("History is disabled in XNU mode.\n");
        }
        return 1;
    }
    if (strcmp(args[0], "alias") == 0) {
        if (xnu_mode) {
            printf("Aliases are disabled in XNU mode.\n");
            return 1;
        }
        if (argc == 1) {
            print_aliases();
        } else if (argc >= 3) {
            char value[1024] = "";
            for (int i = 2; i < argc; i++) {
                strcat(value, args[i]);
                if (i < argc - 1)
                    strcat(value, " ");
            }
            add_alias(args[1], value);
        } else {
            printf("Usage: alias name value\n");
        }
        return 1;
    }
    if (strcmp(args[0], "unalias") == 0) {
        if (xnu_mode) {
            printf("Aliases are disabled in XNU mode.\n");
            return 1;
        }
        if (argc != 2) {
            printf("Usage: unalias name\n");
        } else {
            remove_alias(args[1]);
        }
        return 1;
    }
    if (strcmp(args[0], "version") == 0) {
        printf("nosh version 1.0\n");
        return 1;
    }
    if (strcmp(args[0], "xnu") == 0) {
        enable_xnu_mode();
        return 1;
    }
    if (strcmp(args[0], "wipe") == 0) {
      return handle_secure_wipe(argc, args);
    }
    if (strcmp(args[0], "citrus") == 0) {
        if (argc < 2) {
            printf("Usage: citrus [init|add|get|list]\n");
            return 1;
        }

        if (strcmp(args[1], "init") == 0) {
            initialize_password_manager();
            return 1;
        }
        else if (strcmp(args[1], "add") == 0) {
            if (argc < 4) {
                printf("Usage: citrus add <service> <username>\n");
                return 1;
            }

            char* password = get_password("Enter password: ");
            store_password(args[2], args[3], password);
            return 1;
        }
        else if (strcmp(args[1], "get") == 0) {
            if (argc < 4) {
                printf("Usage: citrus get <service> <username>\n");
                return 1;
            }

            retrieve_password(args[2], args[3]);
            return 1;
        }
        else if (strcmp(args[1], "list") == 0) {
            list_passwords();
            return 1;
        }
        else {
            printf("Unknown citrus command: %s\n", args[1]);
            return 1;
        }
    }
    if (strcmp(args[0], "network") == 0) {
        if (argc < 2) {
            printf("Usage: network [ports|connections|suspicious|scan|interfaces|firewall]\n");
            return 1;
        }

        if (strcmp(args[1], "ports") == 0) {
            check_open_ports();
            return 1;
        }
        else if (strcmp(args[1], "connections") == 0) {
            check_active_connections();
            return 1;
        }
        else if (strcmp(args[1], "suspicious") == 0) {
            check_suspicious_activity();
            return 1;
        }
        else if (strcmp(args[1], "scan") == 0) {
            run_network_security_scan();
            return 1;
        }
        else if (strcmp(args[1], "interfaces") == 0) {
            show_network_interfaces();
            return 1;
        }
        else if (strcmp(args[1], "firewall") == 0) {
            check_firewall_status();
            return 1;
        }
        else {
            printf("Unknown network command: %s\n", args[1]);
            return 1;
        }
    }
    if (strcmp(args[0], "export") == 0) {
        if (argc < 2) {
            // With no arguments, print all environment variables
            print_environment();
        } else {
            // Rebuild the export string after "export"
            char export_str[1024] = "";
            for (int i = 1; i < argc; i++) {
                strcat(export_str, args[i]);
                if (i < argc - 1)
                    strcat(export_str, " ");
            }
            handle_export(export_str);
        }
        return 1;
    }
    if (strcmp(args[0], "env") == 0) {
        print_environment();
        return 1;
    }
    if (strcmp(args[0], "echo") == 0) {
        // First expand any potential wildcards in the arguments
        char *expanded_args[MAX_ARGS];
        int expanded_count = 0;
        int had_expansion = 0;

        for (int i = 1; i < argc; i++) {
            if (strchr(args[i], '*') || strchr(args[i], '?') || strchr(args[i], '[')) {
                glob_t globbuf;
                if (glob(args[i], GLOB_TILDE, NULL, &globbuf) == 0) {
                    if (globbuf.gl_pathc > 0) {
                        had_expansion = 1;
                        for (size_t j = 0; j < globbuf.gl_pathc && expanded_count < MAX_ARGS - 1; j++) {
                            expanded_args[expanded_count++] = strdup(globbuf.gl_pathv[j]);
                        }
                    } else {
                        expanded_args[expanded_count++] = args[i];
                    }
                    globfree(&globbuf);
                } else {
                    expanded_args[expanded_count++] = args[i];
                }
            } else if (args[i][0] == '$' && strlen(args[i]) > 1) {
                // Handle $VAR expansion
                char *env_value = getenv(args[i] + 1);
                if (env_value)
                    expanded_args[expanded_count++] = env_value;
            } else {
                expanded_args[expanded_count++] = args[i];
            }
        }
        expanded_args[expanded_count] = NULL;

        // Print expanded arguments
        for (int i = 0; i < expanded_count; i++) {
            printf("%s", expanded_args[i]);
            if (i < expanded_count - 1)
                printf(" ");
        }
        printf("\n");

        // Free any memory allocated during expansion
        if (had_expansion) {
            for (int i = 0; i < expanded_count; i++) {
                if (expanded_args[i] != args[i] && expanded_args[i] != getenv(args[i] + 1))
                    free(expanded_args[i]);
            }
        }

        return 1;
    }
    return 0;
}
