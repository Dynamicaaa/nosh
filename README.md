# nosh - Network Oriented Security Shell

`nosh` is a modern, security-focused shell designed with both usability and security in mind. It provides enhanced command-line functionality, network security features, and secure credential management.

## Key Features

### Basic Shell Features
- Command history with persistent storage
- Command aliases with persistent configuration
- Environment variable management
- Wildcard expansion for filenames
- Background process execution
- Command substitution

### Security Features
- XNU Hardened Mode for sensitive operations
- Secure file wiping with zero-fill overwriting
- Encrypted password manager (Citrus)
- Network security monitoring and analysis
- Command sanitization to prevent injection attacks

### Environment Management
- Support for `.noshrc` configuration files
- Environment variable persistence
- Path management

## Getting Started

### Dependencies

- GCC or compatible C compiler
- GNU Readline library (required for command line editing and history)
- OpenSSL (for the password manager encryption)

On Debian/Ubuntu:
```bash
sudo apt-get install build-essential libreadline-dev libssl-dev
```

On macOS (using Homebrew):
```bash
brew install readline openssl
```

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/nosh.git

# Build from source
cd nosh
make

# Install (optional)
sudo make install
```

### Basic Usage

```bash
# Start nosh
./nosh

# Start nosh in XNU (hardened) mode
./nosh --xnu
```

## Command Reference

### Shell Navigation
- `cd [dir]` - Change directory
- `pwd` - Print working directory
- `clear` - Clear terminal screen

### File Operations
- `ls`, `cp`, `mv`, etc. - Standard file operations
- `wipe <file>` - Securely erase and delete sensitive files

### History Management
- `history` - View command history
- `clear-history` - Clear command history

### Alias Management
- `alias [name] [cmd]` - Create or list aliases
- `unalias [name]` - Remove an alias

### Environment Variables
- `export VAR=VALUE` - Set environment variable
- `export VAR` - Display variable value
- `env` - List all environment variables

### Security Features
- `xnu` - Toggle XNU hardened security mode
- `citrus init` - Initialize password manager
- `citrus add <service> <username>` - Add a password
- `citrus get <service> <username>` - Retrieve a password
- `citrus list` - List stored passwords

### Network Security
- `network ports` - List open ports
- `network connections` - Show active connections
- `network suspicious` - Check for suspicious activity
- `network interfaces` - Show network interface details
- `network firewall` - Check firewall status
- `network scan` - Run a basic security scan

## Wildcard Support
The shell supports standard glob patterns:
- `*` - Matches any sequence of characters
- `?` - Matches any single character
- `[...]` - Matches any character in brackets
- `~` - Expands to HOME directory

Examples:
```bash
ls *.txt
cat ~/README*
echo /etc/*.conf
```

## XNU Hardened Mode
XNU mode provides enhanced security for sensitive operations:
- Disables command history
- Disables aliases
- Sanitizes commands to prevent injection
- Clears terminal on exit

Enable with the `xnu` command or start with `./nosh --xnu`.

## Password Manager
The integrated Citrus password manager securely stores credentials using AES-256-GCM encryption:

```bash
# Initialize (first time only)
citrus init

# Add a password
citrus add github myusername

# Retrieve a password
citrus get github myusername

# List all stored services
citrus list
```

## Configuration

You can customize nosh by creating a `.noshrc` file in your home directory:

```bash
# Example .noshrc
export PATH=$PATH:/usr/local/bin
export EDITOR=vim
alias ll="ls -la"
alias gs="git status"
```

## Security Best Practices
1. Use XNU mode when handling sensitive information
2. Use the `wipe` command instead of `rm` for sensitive files
3. Regularly check your network security with `network scan`
4. Store important credentials in the password manager
5. Run `clear-history` after sensitive operations

## License
This software is licensed under the MIT License. See the LICENSE file for details.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
