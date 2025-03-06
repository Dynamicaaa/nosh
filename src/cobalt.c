#include "cobalt.h"
#include <sodium.h>
#include <string.h>

#define SALT_SIZE 16
#define IV_SIZE 12
#define KEY_SIZE 32
#define TAG_SIZE 16

// Key derivation function using libsodium
int cobalt_derive_key(const char* password, const unsigned char* salt, unsigned char* key, size_t key_len) {
    if (crypto_pwhash(key, key_len, password, strlen(password), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        return 0; // Error
    }
    return 1; // Success
}

// Encryption function using libsodium
int cobalt_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* key, unsigned char* ciphertext, unsigned char* iv, unsigned char* tag) {
    randombytes_buf(iv, IV_SIZE); // Generate random IV

    unsigned long long ciphertext_len;
    if (crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_len,
                                      plaintext, plaintext_len,
                                      NULL, 0, // No additional data
                                      NULL, iv, key) != 0) {
        return 0; // Error
    }

    memcpy(tag, ciphertext + ciphertext_len - TAG_SIZE, TAG_SIZE); // Extract tag
    return 1; // Success
}

// Decryption function using libsodium
int cobalt_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* tag, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext) {
    unsigned long long plaintext_len;
    unsigned char full_ciphertext[ciphertext_len + TAG_SIZE];

    // Combine ciphertext and tag
    memcpy(full_ciphertext, ciphertext, ciphertext_len);
    memcpy(full_ciphertext + ciphertext_len, tag, TAG_SIZE);

    if (crypto_aead_aes256gcm_decrypt(plaintext, &plaintext_len,
                                      NULL, // No additional data
                                      full_ciphertext, ciphertext_len + TAG_SIZE,
                                      NULL, 0, // No additional data
                                      iv, key) != 0) {
        return 0; // Error
    }

    return 1; // Success
}