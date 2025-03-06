#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "network.h"

// Check open ports on the local system
int check_open_ports(void) {
    printf("Checking for open ports on your system...\n");
    printf("-----------------------------------------\n");

    // Use native commands to check open ports
    system("netstat -tuln | grep LISTEN");

    return 1;
}

// Check active network connections
int check_active_connections(void) {
    printf("Checking active network connections...\n");
    printf("-------------------------------------\n");

    // Use native commands to check active connections
    system("netstat -tn | grep ESTABLISHED");

    return 1;
}

// Check for suspicious network activity
int check_suspicious_activity(void) {
    printf("Checking for suspicious network activity...\n");
    printf("-----------------------------------------\n");

    // Look for connections in unusual states
    system("netstat -tn | grep -v 'ESTABLISHED\\|LISTEN'");

    return 1;
}

// Run a basic network security scan
int run_network_security_scan(void) {
    printf("Running basic network security scan...\n");
    printf("-------------------------------------\n");

    // Check DNS settings
    printf("\n[DNS Configuration]\n");
    system("cat /etc/resolv.conf");

    // Check for unusual listening ports
    printf("\n[Unusual Listening Ports]\n");
    system("netstat -tuln | grep -v '127.0.0.1\\|::1' | grep LISTEN");

    // Check current routing table
    printf("\n[Routing Table]\n");
    system("netstat -rn");

    return 1;
}

// Get basic information about network interfaces
int show_network_interfaces(void) {
    printf("Network Interface Information:\n");
    printf("-----------------------------\n");

    system("ifconfig -a || ip addr");

    return 1;
}

// Check if firewall is active
int check_firewall_status(void) {
    printf("Checking firewall status...\n");
    printf("-------------------------\n");

    // Try different firewall types
    printf("Checking iptables rules:\n");
    system("iptables -L -n 2>/dev/null || echo 'iptables not available or requires root'");

    printf("\nChecking firewall service:\n");
    system("systemctl status firewalld 2>/dev/null || "
           "systemctl status ufw 2>/dev/null || "
           "echo 'No standard firewall service detected'");

    return 1;
}
