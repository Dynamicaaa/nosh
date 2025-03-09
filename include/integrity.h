#ifndef INTEGRITY_H
#define INTEGRITY_H

// Check file integrity using SHA-256
int verify_file_integrity(const char* filename);

// Generate integrity hash for a file
int generate_file_hash(const char* filename);

// Store hash in integrity database
int store_file_hash(const char* filename, const unsigned char* hash);

// Verify all tracked files
int verify_all_files(void);

#endif // INTEGRITY_H