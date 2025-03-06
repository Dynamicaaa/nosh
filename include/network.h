#ifndef NETWORK_H
#define NETWORK_H

// Check open ports on the local system
int check_open_ports(void);

// Check active network connections
int check_active_connections(void);

// Check for suspicious network activity
int check_suspicious_activity(void);

// Run a basic network security scan
int run_network_security_scan(void);

// Get basic information about network interfaces
int show_network_interfaces(void);

// Check if firewall is active
int check_firewall_status(void);

#endif // NETWORK_H
