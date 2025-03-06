#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "password.h"

#define SALT_SIZE 16
#define IV_SIZE 16
#define KEY_SIZE 32
#define BLOCK_SIZE 16
#define TAG_SIZE 16

static char password_file[PATH_MAX] = "";
static unsigned char master_key[KEY_SIZE] = {0};
static int master_key_initialized = 0;

// Get password without echo
char* get_password(const char* prompt) {
    static char password[256];
    struct termios old, new;

    // Turn off echo
    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

    printf("%s", prompt);
    fgets(password, sizeof(password), stdin);

    // Remove newline
    password[strcspn(password, "\n")] = 0;

    // Restore terminal
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    printf("\n");

    return password;
}

// Derives a key from a password and salt
static int derive_key(const char* password, const unsigned char* salt,
                     unsigned char* key, size_t key_len) {
    if (!password || !salt || !key)
        return 0;

    // Use PBKDF2 to derive a key
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                         salt, SALT_SIZE,
                         10000, // iterations
                         EVP_sha256(),
                         key_len, key)) {
        return 0;
    }

    return 1;
}

// Encrypts data using AES-256-GCM
static int aes_encrypt(const unsigned char* plaintext, size_t plaintext_len,
                      const unsigned char* key, const unsigned char* iv,
                      unsigned char* ciphertext, unsigned char* tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    // Initialize encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        return -1;

    // Encrypt plaintext
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    // Finalize encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    // Get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag))
        return -1;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Decrypts data using AES-256-GCM
static int decrypt(const unsigned char* ciphertext, size_t ciphertext_len,
                  const unsigned char* tag,
                  const unsigned char* key, const unsigned char* iv,
                  unsigned char* plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    // Initialize decryption operation
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        return -1;

    // Decrypt ciphertext
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    // Set expected tag value
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag))
        return -1;

    // Finalize decryption
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        // Successful decryption
        plaintext_len += len;
        return plaintext_len;
    } else {
        // Tag verification failed
        return -1;
    }
}

void initialize_password_manager(void) {
    char *home = getenv("HOME");
    if (!home) return;

    // Ensure .nosh directory exists
    char nosh_dir[PATH_MAX];
    snprintf(nosh_dir, sizeof(nosh_dir), "%s/.nosh", home);
    mkdir(nosh_dir, 0700);  // Create with restricted permissions

    snprintf(password_file, sizeof(password_file), "%s/.nosh/citrus.dat", home);

    // Check if password file exists
    struct stat st;
    if (stat(password_file, &st) != 0) {
        // First time setup
        printf("Password manager setup - create a master password\n");
        printf("This password will be used to encrypt your stored passwords.\n");
        printf("Warning: If you forget this password, your stored passwords will be unrecoverable.\n\n");

        char* master_password = get_password("New master password: ");

        // Confirm password
        char* confirm = get_password("Confirm master password: ");

        if (strcmp(master_password, confirm) != 0) {
            printf("Passwords don't match! Password manager not initialized.\n");
            return;
        }

        // Generate a random salt
        unsigned char salt[SALT_SIZE];
        if (RAND_bytes(salt, SALT_SIZE) != 1) {
            printf("Failed to generate random salt! Password manager not initialized.\n");
            return;
        }

        // Derive a key from the password
        if (!derive_key(master_password, salt, master_key, KEY_SIZE)) {
            printf("Key derivation failed! Password manager not initialized.\n");
            return;
        }

        // Create the password file with just the salt
        FILE* fp = fopen(password_file, "wb");
        if (fp) {
            // Write the salt at the beginning of the file
            fwrite(salt, 1, SALT_SIZE, fp);
            fclose(fp);
            printf("Password manager initialized successfully\n");
            master_key_initialized = 1;
        } else {
            printf("Failed to create password file!\n");
        }
    }
}

int unlock_password_manager(void) {
    // If already unlocked, do nothing
    if (master_key_initialized)
        return 1;

    // Open the password file
    FILE* fp = fopen(password_file, "rb");
    if (!fp) {
        printf("Password file not found. Run 'citrus init' first.\n");
        return 0;
    }

    // Read the salt
    unsigned char salt[SALT_SIZE];
    if (fread(salt, 1, SALT_SIZE, fp) != SALT_SIZE) {
        printf("Invalid password file format.\n");
        fclose(fp);
        return 0;
    }

    fclose(fp);

    // Get the master password
    char* master_password = get_password("Enter master password: ");

    // Derive the key
    if (!derive_key(master_password, salt, master_key, KEY_SIZE)) {
        printf("Key derivation failed!\n");
        return 0;
    }

    master_key_initialized = 1;
    return 1;
}

int store_password(const char* service, const char* username, const char* password) {
    if (!master_key_initialized) {
        if (!unlock_password_manager())
            return 0;
    }

    // Read existing passwords
    FILE* fp = fopen(password_file, "rb");
    if (!fp) {
        printf("Password file not found.\n");
        return 0;
    }

    // Skip the salt
    fseek(fp, SALT_SIZE, SEEK_SET);

    // Read all existing entries
    struct {
        char service[128];
        char username[128];
        unsigned char* data;
        size_t size;
    } entries[100];
    int entry_count = 0;

    while (!feof(fp) && entry_count < 100) {
        char service_buf[128], username_buf[128];
        size_t service_len, username_len, data_len;

        // Read service and username lengths
        if (fread(&service_len, sizeof(size_t), 1, fp) != 1) break;
        if (fread(&username_len, sizeof(size_t), 1, fp) != 1) break;

        // Read service and username
        if (fread(service_buf, 1, service_len, fp) != service_len) break;
        if (fread(username_buf, 1, username_len, fp) != username_len) break;
        service_buf[service_len] = '\0';
        username_buf[username_len] = '\0';

        // Read encrypted data size
        if (fread(&data_len, sizeof(size_t), 1, fp) != 1) break;

        // Allocate and read encrypted data + IV + TAG
        entries[entry_count].data = malloc(data_len + IV_SIZE + TAG_SIZE);
        if (!entries[entry_count].data) break;

        if (fread(entries[entry_count].data, 1, data_len + IV_SIZE + TAG_SIZE, fp) != data_len + IV_SIZE + TAG_SIZE) {
            free(entries[entry_count].data);
            break;
        }

        // Store entry data
        strncpy(entries[entry_count].service, service_buf, sizeof(entries[entry_count].service));
        strncpy(entries[entry_count].username, username_buf, sizeof(entries[entry_count].username));
        entries[entry_count].size = data_len;

        entry_count++;
    }

    fclose(fp);

    // Check if entry already exists
    int found = -1;
    for (int i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].service, service) == 0 &&
            strcmp(entries[i].username, username) == 0) {
            found = i;
            break;
        }
    }

    // Generate random IV
    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        printf("Failed to generate random IV!\n");
        return 0;
    }

    // Encrypt the password
    size_t password_len = strlen(password);
    unsigned char ciphertext[1024];
    unsigned char tag[TAG_SIZE];

    int ciphertext_len = aes_encrypt((unsigned char*)password, password_len,
                                   master_key, iv, ciphertext, tag);

    if (ciphertext_len < 0) {
        printf("Encryption failed!\n");
        return 0;
    }

    // Write all entries back to file
    fp = fopen(password_file, "wb");
    if (!fp) {
        printf("Failed to open password file for writing!\n");
        return 0;
    }

    // Read the salt from the file
    unsigned char salt[SALT_SIZE];
    FILE* rfp = fopen(password_file, "rb");
    if (rfp) {
        fread(salt, 1, SALT_SIZE, rfp);
        fclose(rfp);
    }

    // Write salt back
    fwrite(salt, 1, SALT_SIZE, fp);

    // Write all entries
    for (int i = 0; i < entry_count; i++) {
        // Skip the entry we're updating
        if (i == found) continue;

        size_t service_len = strlen(entries[i].service);
        size_t username_len = strlen(entries[i].username);

        // Write service and username lengths
        fwrite(&service_len, sizeof(size_t), 1, fp);
        fwrite(&username_len, sizeof(size_t), 1, fp);

        // Write service and username
        fwrite(entries[i].service, 1, service_len, fp);
        fwrite(entries[i].username, 1, username_len, fp);

        // Write data size
        fwrite(&entries[i].size, sizeof(size_t), 1, fp);

        // Write encrypted data, IV, and tag
        fwrite(entries[i].data, 1, entries[i].size + IV_SIZE + TAG_SIZE, fp);

        // Free memory
        free(entries[i].data);
    }

    // Write the new/updated entry
    size_t service_len = strlen(service);
    size_t username_len = strlen(username);

    // Write service and username lengths
    fwrite(&service_len, sizeof(size_t), 1, fp);
    fwrite(&username_len, sizeof(size_t), 1, fp);

    // Write service and username
    fwrite(service, 1, service_len, fp);
    fwrite(username, 1, username_len, fp);

    // Write data size
    fwrite(&ciphertext_len, sizeof(size_t), 1, fp);

    // Write encrypted data, IV, and tag
    fwrite(ciphertext, 1, ciphertext_len, fp);
    fwrite(iv, 1, IV_SIZE, fp);
    fwrite(tag, 1, TAG_SIZE, fp);

    fclose(fp);

    printf("Password for %s@%s stored successfully.\n", username, service);
    return 1;
}

int retrieve_password(const char* service, const char* username) {
    if (!master_key_initialized) {
        if (!unlock_password_manager())
            return 0;
    }

    // Open the password file
    FILE* fp = fopen(password_file, "rb");
    if (!fp) {
        printf("Password file not found.\n");
        return 0;
    }

    // Skip the salt
    fseek(fp, SALT_SIZE, SEEK_SET);

    // Search for the entry
    while (!feof(fp)) {
        char service_buf[128], username_buf[128];
        size_t service_len, username_len, data_len;

        // Read service and username lengths
        if (fread(&service_len, sizeof(size_t), 1, fp) != 1) break;
        if (fread(&username_len, sizeof(size_t), 1, fp) != 1) break;

        // Read service and username
        if (fread(service_buf, 1, service_len, fp) != service_len) break;
        if (fread(username_buf, 1, username_len, fp) != username_len) break;
        service_buf[service_len] = '\0';
        username_buf[username_len] = '\0';

        // Read encrypted data size
        if (fread(&data_len, sizeof(size_t), 1, fp) != 1) break;

        // Check if this is the entry we're looking for
        if (strcmp(service_buf, service) == 0 &&
            strcmp(username_buf, username) == 0) {

            // Allocate memory for encrypted data
            unsigned char* encrypted_data = malloc(data_len + IV_SIZE + TAG_SIZE);
            if (!encrypted_data) {
                fclose(fp);
                return 0;
            }

            // Read encrypted data, IV, and tag
            if (fread(encrypted_data, 1, data_len + IV_SIZE + TAG_SIZE, fp) != data_len + IV_SIZE + TAG_SIZE) {
                free(encrypted_data);
                fclose(fp);
                return 0;
            }

            // Extract ciphertext, IV, and tag
            unsigned char* ciphertext = encrypted_data;
            unsigned char* iv = encrypted_data + data_len;
            unsigned char* tag = encrypted_data + data_len + IV_SIZE;

            // Decrypt the password
            unsigned char plaintext[1024];
            int plaintext_len = decrypt(ciphertext, data_len, tag, master_key, iv, plaintext);

            free(encrypted_data);
            fclose(fp);

            if (plaintext_len < 0) {
                printf("Decryption failed! Invalid password or tampered data.\n");
                return 0;
            }

            // Null-terminate the plaintext
            plaintext[plaintext_len] = '\0';

            printf("Password for %s@%s: %s\n", username, service, plaintext);
            return 1;
        }

        // Skip to the next entry
        fseek(fp, data_len + IV_SIZE + TAG_SIZE, SEEK_CUR);
    }

    fclose(fp);
    printf("No password found for %s@%s.\n", username, service);
    return 0;
}

int list_passwords(void) {
    if (!master_key_initialized) {
        if (!unlock_password_manager())
            return 0;
    }

    // Open the password file
    FILE* fp = fopen(password_file, "rb");
    if (!fp) {
        printf("Password file not found.\n");
        return 0;
    }

    // Skip the salt
    fseek(fp, SALT_SIZE, SEEK_SET);

    // Read and print all entries
    int count = 0;
    printf("Stored passwords:\n");
    printf("----------------\n");

    while (!feof(fp)) {
        char service_buf[128], username_buf[128];
        size_t service_len, username_len, data_len;

        // Read service and username lengths
        if (fread(&service_len, sizeof(size_t), 1, fp) != 1) break;
        if (fread(&username_len, sizeof(size_t), 1, fp) != 1) break;

        // Read service and username
        if (fread(service_buf, 1, service_len, fp) != service_len) break;
        if (fread(username_buf, 1, username_len, fp) != username_len) break;
        service_buf[service_len] = '\0';
        username_buf[username_len] = '\0';

        // Read encrypted data size
        if (fread(&data_len, sizeof(size_t), 1, fp) != 1) break;

        printf("%d. %s: %s\n", ++count, service_buf, username_buf);

        // Skip to the next entry
        fseek(fp, data_len + IV_SIZE + TAG_SIZE, SEEK_CUR);
    }

    fclose(fp);

    if (count == 0) {
        printf("No passwords stored yet.\n");
    } else {
        printf("\nUse 'citrus get service username' to retrieve a password.\n");
    }

    return 1;
}

void clear_master_key(void) {
    memset(master_key, 0, KEY_SIZE);
    master_key_initialized = 0;
}
