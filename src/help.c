#include <stdio.h>
#include "help.h"
#include "nosh.h"

void show_help_basic(void) {
    printf("Basic Commands:\n");
    printf("  cd [dir]           : Change directory (default HOME)\n");
    printf("  pwd                : Print current working directory\n");
    printf("  clear              : Clear the terminal\n");
    printf("  history            : Show command history\n");
    printf("  clear-history      : Clear command history\n");
    printf("  alias [name] [cmd] : Define an alias or list all if no args\n");
    printf("  unalias [name]     : Remove an alias\n");
    printf("  version            : Show shell version\n");
    printf("  help [topic]       : Display help (topics: basic,env,security,network,xnu)\n");
    printf("  exit               : Exit the shell\n\n");
}

void show_help_env(void) {
    printf("Environment Commands:\n");
    printf("  export VAR=VALUE   : Set an environment variable\n");
    printf("  export VAR         : Display an environment variable\n");
    printf("  export             : List all environment variables\n");
    printf("  env                : Show all environment variables\n");
    printf("  echo [args...]     : Display arguments with expansion\n\n");
}

void show_help_security(void) {
    printf("Security Commands:\n");
    printf("  wipe <file>        : Securely erase and delete a file\n");
    printf("  integrity verify f : Verify integrity of a file\n");
    printf("  integrity gen f    : Generate integrity hash for a file\n");
    printf("  citrus init        : Initialize password manager\n");
    printf("  citrus add s u     : Add password for service/username\n");
    printf("  citrus get s u     : Retrieve password for service/username\n");
    printf("  citrus list        : List all stored services\n\n");
}

void show_help_network(void) {
    printf("Network Commands:\n");
    printf("  network ports      : List open ports on your system\n");
    printf("  network connections: Show active network connections\n");
    printf("  network suspicious : Check for suspicious network activity\n");
    printf("  network scan       : Run a basic network security scan\n");
    printf("  network interfaces : Show network interface information\n");
    printf("  network firewall   : Check firewall status\n\n");
}

void show_help_xnu(void) {
    printf("XNU Mode Features:\n");
    printf("  - Disables command history and aliases\n");
    printf("  - Sanitizes commands to prevent injection\n");
    printf("  - Blocks path traversal attempts\n");
    printf("  - Enforces file permission checks\n");
    printf("  - Never logs commands for privacy\n");
    printf("  - Clears terminal on exit\n\n");
}

void show_help_config(void) {
    printf("Configuration:\n");
    printf("  nconfig <feature> <true/false>\n");
    printf("    xnu            - Enable/disable XNU hardened mode\n");
    printf("    audit          - Enable/disable command logging\n");
    printf("    path_traversal - Control path traversal protection\n");
    printf("    file_perms     - Set file permission enforcement\n");
    printf("    network        - Configure network restrictions\n\n");
    printf("Configuration Files:\n");
    printf("  ~/.nosh/xnu.conf   : Security feature settings\n");
    printf("  ~/.nosh/audit.log  : Command audit log (if enabled)\n");
    printf("  ~/.nosh/integrity/ : File integrity hashes\n\n");
}

void show_help_best_practices(void) {
    printf("Security Best Practices:\n");
    printf("  1. Enable XNU mode for sensitive operations\n");
    printf("  2. Use 'wipe' instead of 'rm' for sensitive files\n");
    printf("  3. Check network security with 'network scan'\n");
    printf("  4. Use citrus password manager for credentials\n");
    printf("  5. Enable audit logging for tracking commands\n");
    printf("  6. Verify integrity of sensitive files regularly\n\n");
}

void show_help(void) {
    printf("nosh - a secure, customizable shell\n\n");
    printf("Usage: help [topic]\n");
    printf("Available topics:\n");
    printf("  basic     - Basic shell commands\n");
    printf("  env       - Environment management\n");
    printf("  security  - Security features\n");
    printf("  network   - Network security tools\n");
    printf("  xnu       - XNU hardened mode\n");
    printf("  config    - Configuration options\n");
    printf("  practices - Security best practices\n\n");
    
    show_help_basic();
    show_help_env();
    show_help_security();
    show_help_network();
    show_help_xnu();
    show_help_config();
    show_help_best_practices();
}