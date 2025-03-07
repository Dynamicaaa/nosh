#include "cobalt.h"
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
    #pragma comment(lib, "crypt32.lib")
#elif defined(__APPLE__)
    #include <Security/Security.h>
#else
    #include <sys/random.h>
#endif

#include <mbedtls/gcm.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <argon2.h>

int cobalt_derive_key(const char* password, const unsigned char *salt, unsigned char* key) {
    // Use Argon2 for key derivation
    if (argon2id_hash_raw(2, 1 << 16, 1, password, strlen(password), salt, COBALT_SALT_SIZE, key, COBALT_KEY_SIZE) != ARGON2_OK) {
        return 0;
    }
    return 1;
}

int cobalt_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                  const unsigned char *key, unsigned char *ciphertext,
                  unsigned char *iv, unsigned char *tag) {
    mbedtls_gcm_context gcm;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "aes_gcm";

    mbedtls_gcm_init(&gcm);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) != 0) {
        return 0;
    }

    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) { // Use 256-bit key
        return 0;
    }

    // Generate random IV
    if (mbedtls_ctr_drbg_random(&ctr_drbg, iv, COBALT_IV_SIZE) != 0) {
        return 0;
    }

    if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext_len, iv, COBALT_IV_SIZE, NULL, 0, plaintext, ciphertext, COBALT_TAG_SIZE, tag) != 0) {
        return 0;
    }

    mbedtls_gcm_free(&gcm);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return 1;
}

int cobalt_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                  const unsigned char *tag, const unsigned char *key,
                  const unsigned char *iv, unsigned char *plaintext) {
    mbedtls_gcm_context gcm;

    mbedtls_gcm_init(&gcm);

    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) { // Use 256-bit key
        return 0;
    }

    if (mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, iv, COBALT_IV_SIZE, NULL, 0, tag, COBALT_TAG_SIZE, ciphertext, plaintext) != 0) {
        return 0;
    }

    mbedtls_gcm_free(&gcm);

    return 1;
}