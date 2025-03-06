#ifndef ALIASES_H
#define ALIASES_H

#include "nosh.h"

// Alias management functions.
void add_alias(const char *name, const char *value);
void remove_alias(const char *name);
void print_aliases(void);
void substitute_alias(char *input);
void load_aliases(void);    // Load persistent aliases from file

#endif // ALIASES_H
