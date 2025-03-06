#include "aliases.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *name;
    char *value;
} alias_t;

static alias_t aliases[MAX_ALIASES];
static int alias_count = 0;

static char alias_file_path[PATH_MAX] = "";

// Writes the current aliases to the persistent alias file.
static void update_alias_file(void) {
    if (alias_file_path[0] == '\0') {
        char *home = getenv("HOME");
        if (home)
            snprintf(alias_file_path, sizeof(alias_file_path), "%s/.nosh_aliases", home);
        else
            return;
    }
    FILE *fp = fopen(alias_file_path, "w");
    if (!fp) {
        perror("fopen");
        return;
    }
    for (int i = 0; i < alias_count; i++) {
        // Write each alias as: name value
        fprintf(fp, "%s %s\n", aliases[i].name, aliases[i].value);
    }
    fclose(fp);
}

// Loads persistent aliases from the alias file.
void load_aliases(void) {
    char *home = getenv("HOME");
    if (!home) return;
    snprintf(alias_file_path, sizeof(alias_file_path), "%s/.nosh_aliases", home);
    FILE *fp = fopen(alias_file_path, "r");
    if (!fp) return;  // No persistent alias file exists yet.
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // Remove trailing newline.
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n')
            line[len-1] = '\0';
        // Tokenize the line. Expecting format: name value
        char *name = strtok(line, " ");
        char *value = strtok(NULL, "");
        if (name && value) {
            add_alias(name, value);
        }
    }
    fclose(fp);
}

// Adds an alias and updates the persistent file.
void add_alias(const char *name, const char *value) {
    // Check if alias already exists and update it.
    for (int i = 0; i < alias_count; i++) {
        if (strcmp(aliases[i].name, name) == 0) {
            free(aliases[i].value);
            aliases[i].value = strdup(value);
            update_alias_file();
            return;
        }
    }
    if (alias_count < MAX_ALIASES) {
        aliases[alias_count].name = strdup(name);
        aliases[alias_count].value = strdup(value);
        alias_count++;
        update_alias_file();
    } else {
        printf("Maximum number of aliases reached.\n");
    }
}

// Removes an alias and updates the persistent file.
void remove_alias(const char *name) {
    for (int i = 0; i < alias_count; i++) {
        if (strcmp(aliases[i].name, name) == 0) {
            free(aliases[i].name);
            free(aliases[i].value);
            for (int j = i; j < alias_count - 1; j++) {
                aliases[j] = aliases[j+1];
            }
            alias_count--;
            update_alias_file();
            return;
        }
    }
    printf("Alias not found: %s\n", name);
}

// Prints all currently defined aliases.
void print_aliases(void) {
    for (int i = 0; i < alias_count; i++) {
        printf("%s='%s'\n", aliases[i].name, aliases[i].value);
    }
}

// Checks the input for an alias and substitutes it if found.
void substitute_alias(char *input) {
    char temp[1024];
    strncpy(temp, input, sizeof(temp));
    temp[1023] = '\0';
    char *token = strtok(temp, " \t");
    if (!token)
        return;
    for (int i = 0; i < alias_count; i++) {
        if (strcmp(token, aliases[i].name) == 0) {
            char new_input[1024];
            // Replace the alias with its value and append the rest of the command.
            snprintf(new_input, sizeof(new_input), "%s%s", aliases[i].value, input + strlen(token));
            strncpy(input, new_input, 1024);
            input[1023] = '\0';
            return;
        }
    }
}
