#ifndef HISTORY_H
#define HISTORY_H

// Rename to avoid conflict with GNU Readline's add_history.
void nosh_add_history(const char *command);
void print_history(void);
char *get_history(int index);
void clear_history(void);  // Add this line to declare the clear_history function

#endif // HISTORY_H
