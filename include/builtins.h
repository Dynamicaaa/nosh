#ifndef BUILTINS_H
#define BUILTINS_H

// Processes built-in commands (cd, pwd, clear, help, history, alias, etc.).
// Returns 1 if the command was handled as built-in.
int handle_builtin(char *input);
void enable_xnu_mode(void);
int is_xnu_mode_enabled(void);
void load_xnu_mode(void); // Add this to load XNU mode state

#endif // BUILTINS_H
