#ifndef COBALT_H
#define COBALT_H

#include <stddef.h>

// Key derivation function
int cobalt_derive_key(const char* password, const unsigned char* salt, unsigned char* key, size_t key_len);

// Encryption function
int cobalt_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* key, unsigned char* ciphertext, unsigned char* iv, unsigned char* tag);

// Decryption function
int cobalt_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* tag, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext);

#endif // COBALT_H