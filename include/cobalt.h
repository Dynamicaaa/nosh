#ifndef COBALT_H
#define COBALT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define COBALT_KEY_SIZE 32
#define COBALT_IV_SIZE 12
#define COBALT_TAG_SIZE 16
#define COBALT_SALT_SIZE 16
#define COBALT_PBKDF2_ITERATIONS 100000

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
    // Windows CryptoAPI constants
    #define COBALT_RSA_KEY_BITS CALG_RSA_KEYX
    #define COBALT_RSA_PADDING PKCS1_OAEP_PADDING
#else
    // Apple/Unix constants
    #define COBALT_RSA_KEY_BITS 2048
    #define COBALT_RSA_PADDING kSecPaddingOAEP
#endif

#define COBALT_SIG_MAX_SIZE 256

// Platform-agnostic interface
int cobalt_derive_key(const char* password, const unsigned char *salt, unsigned char* key);
int cobalt_encrypt(const unsigned char *plaintext, size_t plaintext_len, 
                  const unsigned char *key, unsigned char *ciphertext,
                  unsigned char *iv, unsigned char *tag);
int cobalt_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                  const unsigned char *tag, const unsigned char *key,
                  const unsigned char *iv, unsigned char *plaintext);
int cobalt_generate_key(unsigned char *key, size_t key_len);
int cobalt_create_hmac(const unsigned char *data, size_t data_len,
                      const unsigned char *key, size_t key_len,
                      unsigned char *hmac, size_t *hmac_len);
int cobalt_key_exchange(unsigned char *public_key, size_t *public_key_len,
                       unsigned char *private_key, size_t *private_key_len);
int cobalt_generate_rsa_keypair(unsigned char *public_key, size_t *public_key_len,
                               unsigned char *private_key, size_t *private_key_len);
int cobalt_rsa_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                      const unsigned char *public_key, size_t public_key_len,
                      unsigned char *ciphertext, size_t *ciphertext_len);
int cobalt_rsa_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                      const unsigned char *private_key, size_t private_key_len,
                      unsigned char *plaintext, size_t *plaintext_len);
int cobalt_sign_data(const unsigned char *data, size_t data_len,
                    const unsigned char *private_key, size_t private_key_len,
                    unsigned char *signature, size_t *signature_len);
int cobalt_verify_signature(const unsigned char *data, size_t data_len,
                          const unsigned char *public_key, size_t public_key_len,
                          const unsigned char *signature, size_t signature_len);

#ifdef __cplusplus
}
#endif

#endif // COBALT_H
