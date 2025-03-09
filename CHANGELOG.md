# Changelog

## [v0.1.1]

### Added
- Enhanced XNU Mode Security:
  - Path traversal protection using `contains_path_traversal()` checks
  - File permission enforcement limiting execution to root/user owned files
  - Command auditing configuration
  - Network access restrictions

- Security Configuration System:
  - New `nconfig` command for granular security control
  - Configurable features: xnu, audit, path_traversal, file_perms, network
  - Persistent settings in `~/.nosh/xnu.conf`
  - Command-line configuration through `nconfig <feature> <true/false>`
  - Removed standalone `xnu` command in favor of `nconfig xnu true/false`

- Audit Logging System:
  - New `nconfig audit true/false` command to toggle audit logging
  - Persistent audit configuration in `~/.nosh/audit.conf`
  - Audit log stored in `~/.nosh/audit.log`
  - Command history logging in `~/.nosh/command_history.log` for regular mode
  - No logging in XNU mode for enhanced privacy

- File Integrity Verification:
  - New `integrity` command with `verify` and `gen` subcommands
  - SHA-256 hash generation and verification
  - Secure hash storage in `~/.nosh/integrity/` directory
  - Automatic permission enforcement for hash storage
  - Integration with help system

### Changed
- XNU mode enhancements:
  - Added file ownership checks
  - Added path traversal prevention
  - Improved command sanitization
  - Separated audit logging from command history
  - Updated status messages to reflect new security features
  - Migrated XNU toggle to `nconfig` system
- Help system reorganized into topic-based structure
- Security documentation expanded with integrity verification details

### Fixed
- Path traversal vulnerability in command execution
- Command history privacy in XNU mode
- File permission checks for executed commands
- Configuration persistence issues

### Security
- Added multiple new security layers to XNU mode:
  - Command execution restrictions
  - File access controls
  - Path traversal prevention
  - Audit configuration options
- Centralized security configuration management
- Enhanced security documentation in [README_SECURITY.md](README_SECURITY.md)
- Improved separation between regular and XNU mode logging
- Added file integrity verification using cryptographic hashes
- Implemented secure hash storage with restricted permissions

### Documentation
- Added audit logging configuration instructions
- Updated XNU mode security documentation
- Added new security features to help command output
- Added configuration command reference
- Updated technical limitations section
- Added file integrity verification guide and examples
- Restructured help system into focused topics