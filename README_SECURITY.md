# NOSH Security Documentation

## Overview

`nosh` is a security-focused shell that incorporates several advanced security features to protect sensitive data and operations. This document outlines the security features, their implementation details, and best practices for users.

## Security Features

### XNU Hardened Mode

XNU mode provides enhanced security for sensitive operations:

- **Command History Protection**: All commands executed in XNU mode are excluded from history
- **Command Sanitization**: Prevents shell metacharacter injection by replacing characters like `;`, `|`, `&`, `` ` ``, `$`, `>`, and `<` with spaces
- **Alias Isolation**: Disables alias substitution to prevent potential command hijacking
- **Terminal Clearing**: Automatically clears terminal on exit, including scrollback buffer
- **Persistence**: XNU mode settings are stored securely between sessions

Implementation details:
```c
// In builtins.c
if (is_xnu_mode_enabled()) {
    for (char* p = sanitized; *p; p++) {
        // Remove shell metacharacters that could be used for command chaining/injection
        if (*p == ';' || *p == '|' || *p == '&' ||
            *p == '`' || *p == '$' ||
            (*p == '>' && *(p-1) != '2') || *p == '<') {
                *p = ' ';
        }
    }
}
```

### Secure File Wiping

The `wipe` command securely erases sensitive files by:

1. Overwriting file contents with zeros using a secure multi-pass approach
2. Using appropriate block sizes for efficient operations
3. Finalizing with filesystem unlinking (deletion)

This prevents file recovery through standard means and is suitable for erasing sensitive information.

Implementation details:
```c
// In builtins.c - handle_secure_wipe function
const int BLOCK_SIZE = 4096;
char *zeros = calloc(1, BLOCK_SIZE);
// Overwrite file with zeros
for (off_t offset = 0; offset < size; offset += BLOCK_SIZE) {
    ssize_t to_write = (size - offset < BLOCK_SIZE) ? (size - offset) : BLOCK_SIZE;
    if (write(fd, zeros, to_write) != to_write) {
        perror("wipe: write");
        break;
    }
}
```

### Password Manager (Citrus)

The integrated `citrus` password manager uses industry standard security:

- **AES-256-GCM**: Authenticated encryption with associated data
- **PBKDF2 Key Derivation**: With 10,000 iterations for Master Password protection
- **Random Salt & IV**: Unique per-password security parameters
- **Secure Memory Handling**: Sensitive data is wiped from memory
- **Tamper Detection**: Authentication tags verify data integrity

Implementation:
```c
// Encryption uses AES-256-GCM
if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
    return -1;

// Key derivation with 10,000 iterations
if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                      salt, SALT_SIZE,
                      10000, // iterations
                      EVP_sha256(),
                      key_len, key)) {
    return 0;
}
```

### Network Security Tools

Network security tools allow monitoring system communication security:
- Open port detection
- Active connection monitoring
- Suspicious activity detection
- Security scanning
- Interface monitoring
- Firewall status checks

Implementation details:
```c
// Sample implementation from network.c
int check_suspicious_activity(void) {
    printf("Checking for suspicious network activity...\n");
    printf("-----------------------------------------\n");

    // Look for connections in unusual states
    system("netstat -tn | grep -v 'ESTABLISHED\\|LISTEN'");

    return 1;
}
```

## Security Design Principles

### Defense in Depth

`nosh` utilizes multiple layers of protection:
1. User interface safeguards (XNU mode)
2. System-level protections (secure file operations)
3. Cryptographic security (password manager)
4. Network monitoring (continuous security awareness)

### Least Privilege

The shell follows the principle that operations should have the minimum privileges necessary:
- Minimal exposure of sensitive operations
- Clear separation between normal and high-security modes
- Explicit permission requirements for sensitive actions
- Controlled access to credential data

### Secure by Default

Security features are enabled and correctly configured by default:
- Strong encryption parameters
- Secure wiping defaults
- Safe command substitution
- Memory protection for sensitive data

## Cryptographic Implementation

### Master Password Protection

Password manager master keys are never stored directly:
- Master password converted to key using PBKDF2
- Salt is stored but key remains in memory only
- Master key cleared from memory on exit
- Memory sanitization on process termination

### Password Storage Format

The password database format includes:
1. 16-byte salt at file start
2. Entry records containing:
   - Service name length + service name
   - Username length + username
   - Encrypted data length
   - Encrypted password data
   - 16-byte IV (unique per password)
   - 16-byte Authentication tag

### Encryption Implementation

Individual passwords are protected with:
- Unique IV for each password
- AES-256-GCM encryption
- Authentication tag to detect tampering
- Key isolation (one master key accessing many credentials)

```c
// Generate random IV
unsigned char iv[IV_SIZE];
if (RAND_bytes(iv, IV_SIZE) != 1) {
    printf("Failed to generate random IV!\n");
    return 0;
}

// Encrypt the password
int ciphertext_len = aes_encrypt((unsigned char*)password, password_len,
                               master_key, iv, ciphertext, tag);
```

## Memory Protection

### Secure Memory Handling

Sensitive data in memory is protected by:
1. Limiting exposure time of sensitive data
2. Explicit memory clearing when no longer needed
3. Using static buffers where possible to avoid heap allocation
4. Proper input sanitization to prevent buffer overflows

```c
// Example of memory clearing
void clear_master_key(void) {
    memset(master_key, 0, KEY_SIZE);
    master_key_initialized = 0;
}
```

### Password Input Security

Password input is protected by:
1. Disabling terminal echo during input
2. Using secure terminal control APIs
3. Direct memory handling (no intermediate storage)

```c
// Turn off echo
tcgetattr(STDIN_FILENO, &old);
new = old;
new.c_lflag &= ~ECHO;
tcsetattr(STDIN_FILENO, TCSANOW, &new);
```

## Environment Security

### Configuration Security

Configuration is secured through:
1. Protected storage locations
2. Proper permission management
3. Secure parsing and handling

All configuration files are stored in the user's home directory with appropriate permissions:
- `.nosh_aliases` - For shell aliases
- `.nosh_xnu_mode` - For XNU mode persistence
- `.noshrc` - For environment configuration
- `.nosh/citrus.dat` - For encrypted passwords

### Secure Directory Creation

The password manager creates its directory with secure permissions:
```c
mkdir(nosh_dir, 0700);  // Create with restricted permissions
```

### Command Execution Security

Command execution is secured through:
1. Proper argument handling and sanitization
2. Environment variable expansion security
3. Wildcard expansion security
4. Path traversal prevention

## Best Practices for Users

### General Security

1. Use XNU mode when handling sensitive information
2. Clear history after sensitive operations
3. Use `wipe` instead of `rm` for sensitive files
4. Set a strong master password for the password manager
5. Regularly scan for network security issues

### XNU Mode Usage

When to use XNU mode:
- When accessing sensitive systems
- When handling credentials or API keys
- When performing administrative tasks
- When entering or displaying confidential information

### Password Manager

- Use a strong, unique master password
- Store all sensitive credentials in the password manager
- Don't use the shell history for quick access to passwords
- Run `citrus init` when first installing the shell

### Secure File Operations

- Use `wipe` for any file containing sensitive information
- Remember that standard `rm` doesn't securely erase file contents
- Be aware that SSD drives require special handling for secure erasure
- Consider encryption for highly sensitive files

### Network Security Management

- Run regular network scans with `network scan`
- Check open ports with `network ports`
- Monitor suspicious connections with `network suspicious`
- Verify firewall settings with `network firewall`

## Technical Limitations

1. XNU mode cannot prevent physical access to the terminal
2. Secure wiping effectiveness depends on storage type (especially SSDs)
3. Network security tools depend on system-level utilities
4. Password manager security depends on master password strength
5. Terminal emulator limitations may affect some security features

### Storage-Specific Limitations

For maximum security, be aware of these storage-specific limitations:

- **SSDs and Flash Storage**: Wear-leveling and block remapping can make secure erasure difficult
- **NFS and Remote Filesystems**: May not properly sync or may cache content
- **Copy-on-Write Filesystems**: May retain previous versions of files
- **Journaling Filesystems**: May contain file data in journal

## Threat Model

`nosh` is designed to protect against:

1. **Casual snooping**: Preventing others from viewing command history or screen content
2. **Credential theft**: Securing passwords and sensitive information
3. **Command injection**: Preventing malicious command execution
4. **Network reconnaissance**: Detecting suspicious network activity
5. **Data leakage**: Preventing sensitive data from persisting on disk

`nosh` does not protect against:

1. Kernel-level attacks
2. Hardware keyloggers
3. Sophisticated memory analysis attacks
4. Physical access attacks
5. Zero-day vulnerabilities in dependent libraries

## Security Audit Trail

The shell maintains the following security-relevant trails:

1. Network security scans are logged to console
2. Password manager operations are verified through cryptographic authentication
3. Secure wipe operations report success/failure
4. XNU mode transitions are explicitly indicated

## Reporting Security Issues

Security issues should be reported to the maintainers immediately and should include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. If available, suggested mitigations

## Future Security Enhancements

Planned security improvements:
1. Hardware key support for password manager
2. MFA integration
3. Enhanced XNU mode with mandatory access controls
4. File integrity verification
5. Enhanced network security scanning
6. Secure remote operation capability
7. Audit logging for security operations
8. Secure update mechanism
9. Sandboxing for command execution
10. Integration with system security frameworks

## Security Compliance

Where applicable, the shell implements security controls aligned with:
- NIST SP 800-53
- OWASP Secure Coding Practices
- CIS Benchmarks for Unix/Linux
- GDPR data protection requirements
- Industry-standard cryptographic practices

## Security Response Policy

If a security vulnerability is identified:
1. The issue will be assessed within 48 hours
2. Critical vulnerabilities will be patched as soon as possible
3. Users will be notified through appropriate channels
4. A CVE will be requested if applicable
5. Detailed analysis will be provided after mitigation
