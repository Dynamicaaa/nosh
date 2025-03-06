#ifndef ENVIRONMENT_H
#define ENVIRONMENT_H

#include <limits.h>

// Load .noshrc configuration file
void load_noshrc(void);

// Add or update an environment variable (VAR=VALUE format)
int handle_export(const char *export_str);

// Print all environment variables
void print_environment(void);

// Get current shell's PATH
char *get_path(void);

#endif // ENVIRONMENT_H
