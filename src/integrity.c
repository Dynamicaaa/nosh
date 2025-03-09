#include "integrity.h"
#include "cobalt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <mbedtls/sha256.h>

#define HASH_SIZE 32  // SHA-256 hash size
#define BLOCK_SIZE 4096

// Calculate SHA-256 hash of file
static int calculate_file_hash(const char* filename, unsigned char* hash) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) return 0;

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 = SHA-256

    unsigned char buffer[BLOCK_SIZE];
    size_t bytes;
    while ((bytes = fread(buffer, 1, BLOCK_SIZE, fp)) > 0) {
        mbedtls_sha256_update(&ctx, buffer, bytes);
    }

    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
    fclose(fp);
    return 1;
}

int verify_file_integrity(const char* filename) {
    unsigned char stored_hash[HASH_SIZE];
    unsigned char current_hash[HASH_SIZE];
    
    // Read stored hash
    char hash_path[PATH_MAX];
    snprintf(hash_path, sizeof(hash_path), "%s/.nosh/integrity/%s.hash", getenv("HOME"), filename);
    
    FILE* fp = fopen(hash_path, "rb");
    if (!fp) {
        printf("No stored hash found for %s\n", filename);
        return 0;
    }
    
    if (fread(stored_hash, 1, HASH_SIZE, fp) != HASH_SIZE) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    // Calculate current hash
    if (!calculate_file_hash(filename, current_hash)) {
        printf("Failed to calculate hash for %s\n", filename);
        return 0;
    }

    // Compare hashes
    if (memcmp(stored_hash, current_hash, HASH_SIZE) != 0) {
        printf("WARNING: File %s has been modified!\n", filename);
        return 0;
    }

    printf("File %s integrity verified\n", filename);
    return 1;
}

int generate_file_hash(const char* filename) {
    unsigned char hash[HASH_SIZE];
    
    if (!calculate_file_hash(filename, hash)) {
        return 0;
    }

    return store_file_hash(filename, hash);
}

int store_file_hash(const char* filename, const unsigned char* hash) {
    char hash_dir[PATH_MAX];
    char hash_path[PATH_MAX];
    snprintf(hash_dir, sizeof(hash_dir), "%s/.nosh/integrity", getenv("HOME"));
    snprintf(hash_path, sizeof(hash_path), "%s/%s.hash", hash_dir, filename);
    
    // Create integrity directory if it doesn't exist
#ifdef _WIN32
    mkdir(hash_dir);  // Windows version doesn't use permissions
#else
    mkdir(hash_dir, 0700);  // Unix version with permissions
#endif

    FILE* fp = fopen(hash_path, "wb");
    if (!fp) return 0;
    
    size_t written = fwrite(hash, 1, HASH_SIZE, fp);
    fclose(fp);
    
    return written == HASH_SIZE;
}