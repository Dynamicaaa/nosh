#ifndef PASSWORD_H
#define PASSWORD_H

#include <limits.h>

// Get password from user without showing input
char* get_password(const char* prompt);

// Initialize the password manager
void initialize_password_manager(void);

// Unlock the password manager with the master password
int unlock_password_manager(void);

// Store a password
int store_password(const char* service, const char* username, const char* password);

// Retrieve a password
int retrieve_password(const char* service, const char* username);

// List all stored passwords
int list_passwords(void);

// Clear the master key from memory
void clear_master_key(void);

#endif // PASSWORD_H
