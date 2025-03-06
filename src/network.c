#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "network.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#else
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#ifdef __linux__
#include <sys/types.h>
#include <linux/route.h> // For Linux routing table info
#include <sys/ioctl.h>   // For SIOCGRTABLE on Linux
#endif
#endif

#ifdef __APPLE__
#include <net/route.h> // For macOS routing table info
#include <sys/sysctl.h> // For sysctl function and CTL_NET definition
#endif

// Function declaration for run_routing_table_check
int run_routing_table_check(void);

// Check open ports on the local system
int check_open_ports(void) {
    printf("Checking for open ports on your system...\n");
    printf("-----------------------------------------\n");

    int sock;
    int count = 0;

    // Check common ports
    int common_ports[] = {21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080, 8443};
    int num_ports = sizeof(common_ports) / sizeof(common_ports[0]);

    for (int i = 0; i < num_ports; i++) {
        // Create a socket
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket");
            continue;
        }

#ifndef _WIN32
        // Set non-blocking mode for quick check (POSIX systems)
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#else
        // Non-blocking mode for Windows
        unsigned long nonBlocking = 1;
        ioctlsocket(sock, FIONBIO, &nonBlocking);
#endif

        // Set up address
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
        addr.sin_port = htons(common_ports[i]);

        // Try to connect
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0
#ifndef _WIN32
            || (errno == EINPROGRESS || errno == EWOULDBLOCK) // POSIX non-blocking connect errors
#else
            || (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS) // Windows non-blocking connect errors
#endif
            ) {

            // Wait a tiny bit for connection
            fd_set wset;
            struct timeval tv;
            FD_ZERO(&wset);
            FD_SET(sock, &wset);
            tv.tv_sec = 0;
            tv.tv_usec = 100000; // 100ms timeout

            if (select(sock + 1, NULL, &wset, NULL, &tv) > 0) {
                int error = 0;
#ifndef _WIN32
                socklen_t len = sizeof(error);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
#else
                int len = sizeof(error);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len) == 0 && error == 0) {
#endif
                    // Port is open
                    printf("Port %d: OPEN\n", common_ports[i]);
                    count++;
                }
            }
        }

#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }

    if (count == 0) {
        printf("No common ports found to be open on localhost.\n");
    }

    return 1;
}

// Check active network connections
int check_active_connections(void) {
    printf("Checking active network connections...\n");
    printf("-------------------------------------\n");

#ifdef __linux__
    // Linux: Read from /proc/net/tcp
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) {
        printf("Cannot access network connection information. Try using netstat on your system.\n");
        return 1;
    }

    char line[512];
    int count = 0;

    // Skip the header line
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return 1;
    }

    printf("Local Address         Remote Address        State\n");
    printf("------------------------------------------------------\n");

    // Read each line
    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned int local_addr[4], local_port;
        unsigned int remote_addr[4], remote_port;
        unsigned int state;

        // Parse the line (format varies by kernel version)
        if (sscanf(line, "%*d: %02x%02x%02x%02x:%04x %02x%02x%02x%02x:%04x %02x",
                 &local_addr[0], &local_addr[1], &local_addr[2], &local_addr[3], &local_port,
                 &remote_addr[0], &remote_addr[1], &remote_addr[2], &remote_addr[3], &remote_port,
                 &state) == 11) {

            // Only show ESTABLISHED connections (state 01)
            if (state == 1) {
                printf("%d.%d.%d.%d:%-10d %d.%d.%d.%d:%-10d ESTABLISHED\n",
                       local_addr[0], local_addr[1], local_addr[2], local_addr[3], local_port,
                       remote_addr[0], remote_addr[1], remote_addr[2], remote_addr[3], remote_port);
                count++;
            }
        }
    }

    fclose(fp);

    if (count == 0) {
        printf("No active TCP connections found.\n");
    }

#elif defined(_WIN32) || defined(__APPLE__)
    // macOS and Windows: Use netstat command
    FILE *fp = popen("netstat -an | grep TCP", "r"); // Basic cross-platform netstat command
    if (!fp) {
        perror("popen");
        printf("Could not run netstat command.\n");
        return 1;
    }

    char line[512];
    int count = 0;
    printf("Proto Local Address         Foreign Address       State\n");
    printf("------------------------------------------------------\n");

    while (fgets(line, sizeof(line), fp) != NULL) {
        char proto[10], local_addr_str[100], foreign_addr_str[100], state_str[20];
        if (sscanf(line, "%s %s %s %s", proto, local_addr_str, foreign_addr_str, state_str) >= 4) {
            if (strcmp(state_str, "ESTABLISHED") == 0
#ifdef _WIN32
                || strcmp(state_str, " установлена") == 0 // Windows in Russian
#endif
                ) {
                printf("%-5s %-25s %-25s %s\n", proto, local_addr_str, foreign_addr_str, state_str);
                count++;
            }
        } else if (sscanf(line, "%s %s %s", proto, local_addr_str, foreign_addr_str) >= 3) { // macOS might not always have state
            printf("%-5s %-25s %-25s\n", proto, local_addr_str, foreign_addr_str); // Print without state if not available
            count++;
        }
    }
    pclose(fp);

    if (count == 0) {
        printf("No active TCP connections found.\n");
    }
#else
    printf("Active connection check not implemented for this platform.\n");
#endif

    return 1;
}

// Check for suspicious network activity
int check_suspicious_activity(void) {
    printf("Checking for suspicious network activity...\n");
    printf("-----------------------------------------\n");

#ifdef __linux__
    // Linux: Read from /proc/net/tcp
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) {
        printf("Cannot access network connection information. Try using netstat on your system.\n");
        return 1;
    }

    char line[512];
    int count = 0;

    // Skip the header line
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return 1;
    }

    printf("Unusual Connection States:\n");
    printf("--------------------------\n");

    // Read each line
    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned int local_addr[4], local_port;
        unsigned int remote_addr[4], remote_port;
        unsigned int state;

        // Parse the line
        if (sscanf(line, "%*d: %02x%02x%02x%02x:%04x %02x%02x%02x%02x:%04x %02x",
                 &local_addr[0], &local_addr[1], &local_addr[2], &local_addr[3], &local_port,
                 &remote_addr[0], &remote_addr[1], &remote_addr[2], &remote_addr[3], &remote_port,
                 &state) == 11) {

            // Skip ESTABLISHED (01) or LISTEN (0A) connections
            if (state != 1 && state != 10) {
                char *state_name;
                switch (state) {
                    case 2: state_name = "SYN_SENT"; break;
                    case 3: state_name = "SYN_RECV"; break;
                    case 4: state_name = "FIN_WAIT1"; break;
                    case 5: state_name = "FIN_WAIT2"; break;
                    case 6: state_name = "TIME_WAIT"; break;
                    case 7: state_name = "CLOSE"; break;
                    case 8: state_name = "CLOSE_WAIT"; break;
                    case 9: state_name = "LAST_ACK"; break;
                    case 11: state_name = "CLOSING"; break;
                    default: state_name = "UNKNOWN"; break;
                }

                printf("%d.%d.%d.%d:%-10d %d.%d.%d.%d:%-10d %s\n",
                       local_addr[0], local_addr[1], local_addr[2], local_addr[3], local_port,
                       remote_addr[0], remote_addr[1], remote_addr[2], remote_addr[3], remote_port,
                       state_name);
                count++;
            }
        }
    }

    fclose(fp);

    if (count == 0) {
        printf("No unusual connection states found.\n");
    }

#elif defined(_WIN32) || defined(__APPLE__)
    // macOS and Windows: Use netstat command and filter for non-established/listen states
    FILE *fp = popen("netstat -an | grep TCP", "r");
    if (!fp) {
        perror("popen");
        printf("Could not run netstat command.\n");
        return 1;
    }

    char line[512];
    int count = 0;
    printf("Proto Local Address         Foreign Address       State\n");
    printf("------------------------------------------------------\n");

    while (fgets(line, sizeof(line), fp) != NULL) {
        char proto[10], local_addr_str[100], foreign_addr_str[100], state_str[20];
        if (sscanf(line, "%s %s %s %s", proto, local_addr_str, foreign_addr_str, state_str) >= 4) {
            if (strcmp(state_str, "ESTABLISHED") != 0 && strcmp(state_str, "LISTEN") != 0
#ifdef _WIN32
                && strcmp(state_str, " установлена") != 0 && strcmp(state_str, "Прослушивание") != 0 // Windows in Russian
#endif
                ) {
                printf("%-5s %-25s %-25s %s\n", proto, local_addr_str, foreign_addr_str, state_str);
                count++;
            }
        }
    }
    pclose(fp);

    if (count == 0) {
        printf("No unusual connection states found.\n");
    }

#else
    printf("Suspicious activity check not implemented for this platform.\n");
#endif

    return 1;
}

// Run a basic network security scan
int run_network_security_scan(void) {
    printf("Running basic network security scan...\n");
    printf("-------------------------------------\n");

#if defined(__linux__) || defined(__APPLE__)
    // Check DNS settings (Linux/macOS: /etc/resolv.conf)
    printf("\n[DNS Configuration]\n");
    FILE *resolv = fopen("/etc/resolv.conf", "r");
    if (resolv) {
        char line[256];
        while (fgets(line, sizeof(line), resolv) != NULL) {
            printf("%s", line);
        }
        fclose(resolv);
    } else {
        printf("Could not access DNS configuration.\n");
    }
#elif defined(_WIN32)
    printf("\n[DNS Configuration]\n");
    printf("DNS configuration on Windows is system-wide and typically managed through the Network and Sharing Center.\n");
    printf("You can view your DNS settings using 'ipconfig /all' in cmd or PowerShell.\n");
#else
    printf("\n[DNS Configuration]\n");
    printf("DNS configuration check is OS-specific.\n");
#endif

#if defined(__linux__) || defined(__APPLE__)
    // Check routing table
    run_routing_table_check();
#elif defined(_WIN32)
    run_routing_table_check();
#else
    printf("\n[Routing Table]\n");
    printf("Routing table check is OS-specific and not implemented for this platform.\n");
#endif

#if defined(__linux__) || defined(__APPLE__)
    // Check for unusual listening ports (not on localhost)
    printf("\n[Unusual Listening Ports]\n");

    // Use socket to check if ports are listening on non-localhost interfaces
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
    } else {
        // Iterate through network interfaces
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL)
                continue;

            // Only IPv4 addresses
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);

                // Skip localhost
                if (strcmp(ip, "127.0.0.1") == 0)
                    continue;

                printf("Interface: %s, IP: %s\n", ifa->ifa_name, ip);

                // Check common ports on this interface
                int common_ports[] = {21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080, 8443};
                int num_ports = sizeof(common_ports) / sizeof(common_ports[0]);

                for (int i = 0; i < num_ports; i++) {
                    int sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sock < 0) continue;

#ifndef _WIN32
                    int flags = fcntl(sock, F_GETFL, 0);
                    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#else
                    unsigned long nonBlocking = 1;
                    ioctlsocket(sock, FIONBIO, &nonBlocking);
#endif

                    struct sockaddr_in test_addr;
                    memset(&test_addr, 0, sizeof(test_addr));
                    test_addr.sin_family = AF_INET;
                    test_addr.sin_addr = addr->sin_addr;
                    test_addr.sin_port = htons(common_ports[i]);

                    if (connect(sock, (struct sockaddr*)&test_addr, sizeof(test_addr)) == 0
#ifndef _WIN32
                        || (errno == EINPROGRESS || errno == EWOULDBLOCK)
#else
                        || (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
#endif
                        ) {

                        fd_set wset;
                        struct timeval tv;
                        FD_ZERO(&wset);
                        FD_SET(sock, &wset);
                        tv.tv_sec = 0;
                        tv.tv_usec = 100000; // 100ms timeout

                        if (select(sock + 1, NULL, &wset, NULL, &tv) > 0) {
                            int error = 0;
#ifndef _WIN32
                            socklen_t len = sizeof(error);
                            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
#else
                            int len = sizeof(error);
                            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len) == 0 && error == 0) {
#endif
                                printf("  Port %d: OPEN on %s\n", common_ports[i], ip);
                            }
                        }
                    }
#ifdef _WIN32
                    closesocket(sock);
#else
                    close(sock);
#endif
                }
            }
        }
        freeifaddrs(ifaddr);
    }
#elif defined(_WIN32)
    printf("\n[Unusual Listening Ports]\n");
    printf("Unusual listening ports detection on Windows requires more advanced techniques.\n");
    printf("Consider using tools like Resource Monitor or TCPView to check listening ports.\n");
#else
    printf("\n[Unusual Listening Ports]\n");
    printf("Unusual listening ports detection is OS-specific.\n");
#endif

    return 1;
}


int run_routing_table_check(void) {
    printf("\n[Routing Table]\n");
#ifdef __linux__
    // Linux: Get routing table using netlink
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char buf[8192];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();
    req.rtm.rtm_family = AF_INET;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (sendto(sock, &req, req.nlh.nlmsg_len, 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }

    char buffer[8192];
    struct iovec iov = { buffer, sizeof(buffer) };
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

    int len;
    while ((len = recvmsg(sock, &msg, 0)) > 0) {
        struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
        for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                close(sock);
                return 1;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                perror("NLMSG_ERROR");
                close(sock);
                return 1;
            }

            struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
            struct rtattr *rta = (struct rtattr *)RTM_RTA(rtm);
            int rta_len = RTM_PAYLOAD(nlh);

            char dst[INET_ADDRSTRLEN] = "0.0.0.0";
            char gw[INET_ADDRSTRLEN] = "0.0.0.0";
            char mask[INET_ADDRSTRLEN] = "0.0.0.0";
            char ifname[IF_NAMESIZE] = "";

            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                switch (rta->rta_type) {
                    case RTA_DST:
                        inet_ntop(AF_INET, RTA_DATA(rta), dst, sizeof(dst));
                        break;
                    case RTA_GATEWAY:
                        inet_ntop(AF_INET, RTA_DATA(rta), gw, sizeof(gw));
                        break;
                    case RTA_PREFSRC:
                        inet_ntop(AF_INET, RTA_DATA(rta), mask, sizeof(mask));
                        break;
                    case RTA_OIF:
                        if_indextoname(*(int *)RTA_DATA(rta), ifname);
                        break;
                }
            }

            printf("%-16s %-16s %-16s %s\n", dst, gw, mask, ifname);
        }
    }

    close(sock);

#elif defined(_WIN32)
    // Windows: Get routing table using GetIpForwardTable
    MIB_IPFORWARDTABLE *pIpForwardTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRet = 0;

    dwRet = GetIpForwardTable(NULL, &dwSize, FALSE);
    if (dwRet == ERROR_INSUFFICIENT_BUFFER) {
        pIpForwardTable = (MIB_IPFORWARDTABLE *)malloc(dwSize);
        if (pIpForwardTable) {
            dwRet = GetIpForwardTable(pIpForwardTable, &dwSize, FALSE);
            if (dwRet == NO_ERROR) {
                printf("Destination\t\tNetmask\t\tGateway\t\tIface\tMetric\tProto\tType\n");
                printf("------------------------------------------------------------------------------------\n");
                for (int i = 0; i < (int)pIpForwardTable->dwNumEntries; i++) {
                    MIB_IPFORWARDROW *row = &pIpForwardTable->table[i];
                    struct in_addr dest_addr, mask_addr, gw_addr;
                    dest_addr.s_addr = row->dwForwardDest;
                    mask_addr.s_addr = row->dwForwardMask;
                    gw_addr.s_addr = row->dwForwardNextHop;

                    printf("%-16s\t", inet_ntoa(dest_addr));
                    printf("%-16s\t", inet_ntoa(mask_addr));
                    printf("%-16s\t", inet_ntoa(gw_addr));
                    printf("%-5d\t", row->dwForwardIfIndex);
                    printf("%-6d\t", row->dwForwardMetric1);

                    switch (row->dwForwardProto) {
                        case MIB_IPPROTO_NETMGMT: printf("NETMGMT\t"); break;
                        case MIB_IPPROTO_ICMP: printf("ICMP\t"); break;
                        case MIB_IPPROTO_TCP: printf("TCP\t"); break;
                        case MIB_IPPROTO_UDP: printf("UDP\t"); break;
                        default: printf("Other(%d)\t", row->dwForwardProto);
                    }

                    switch (row->dwForwardType) {
                        case MIB_IPROUTE_TYPE_OTHER: printf("Other\n"); break;
                        case MIB_IPROUTE_TYPE_INVALID: printf("Invalid\n"); break;
                        case MIB_IPROUTE_TYPE_DIRECT: printf("Direct\n"); break;
                        case MIB_IPROUTE_TYPE_INDIRECT: printf("Indirect\n"); break;
                        default: printf("Unknown(%d)\n", row->dwForwardType);
                    }
                }
            } else {
                printf("GetIpForwardTable failed with error %ld\n", dwRet);
            }
            free(pIpForwardTable);
        } else {
            printf("Memory allocation failed for routing table.\n");
        }
    } else {
        printf("GetIpForwardTable (size query) failed with error %ld\n", dwRet);
    }

#elif defined(__APPLE__)
    // macOS: Get routing table using sysctl
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
    size_t needed;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
        perror("sysctl");
        return 1;
    }

    char *buf = malloc(needed);
    if (buf == NULL) {
        perror("malloc");
        return 1;
    }

    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
        perror("sysctl");
        free(buf);
        return 1;
    }

    char *next = buf;
    char *end = buf + needed;
    printf("Destination\tGateway\t\tNetmask\t\tInterface\n");
    printf("---------------------------------------------------------\n");

    while (next < end) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)next;
        struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
        struct sockaddr_in *dst = NULL, *gateway = NULL, *netmask = NULL;
        char ifname[IF_NAMESIZE];

        for (int i = 0; i < RTAX_MAX; i++) {
            if (rtm->rtm_addrs & (1 << i)) {
                if (i == RTAX_DST) dst = (struct sockaddr_in *)sa;
                if (i == RTAX_GATEWAY) gateway = (struct sockaddr_in *)sa;
                if (i == RTAX_NETMASK) netmask = (struct sockaddr_in *)sa;
                sa = (struct sockaddr *)((char *)sa + sa->sa_len);
            }
        }

        if (dst && gateway && netmask) {
            printf("%-16s\t", inet_ntoa(dst->sin_addr));
            printf("%-16s\t", inet_ntoa(gateway->sin_addr));
            printf("%-16s\t", inet_ntoa(netmask->sin_addr));
            if_indextoname(rtm->rtm_index, ifname);
            printf("%s\n", ifname);
        }

        next += rtm->rtm_msglen;
    }

    free(buf);

#else
    printf("\n[Routing Table]\n");
    printf("Routing table check from scratch is OS-specific and not implemented for this platform.\n");
#endif
    return 1;
}


// Get basic information about network interfaces
int show_network_interfaces(void) {
    printf("Network Interface Information:\n");
    printf("-----------------------------\n");

#ifdef _WIN32
    // Windows implementation
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    ULONG ulOutBufLen = 0;
    DWORD dwRet = 0;

    // Allocate memory for Adapter Info
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        printf("Error allocating memory needed to call GetAdaptersInfo\n");
        return 1;
    }
    ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    // Make an initial call to GetAdaptersInfo to get the necessary size into ulOutBufLen
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            printf("Error allocating memory needed to call GetAdaptersInfo\n");
            return 1;
        }
    }

    if ((dwRet = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        printf("Interface    IP Address          Netmask          Flags\n");
        printf("-----------------------------------------------------------\n");
        while (pAdapter) {
            printf("%-12s ", pAdapter->AdapterName);

            // IP Addresses
            IP_ADDR_STRING *pIpAddrString = &(pAdapter->IpAddressList);
            if (pIpAddrString) {
                printf("%-18s ", pIpAddrString->IpAddress.String);
            } else {
                printf("%-18s ", "N/A");
            }

            // Netmask
            if (pIpAddrString) {
                printf("%-18s ", pIpAddrString->IpMask.String);
            } else {
                printf("%-18s ", "N/A");
            }

            // Flags - basic indication (more detailed flags would require parsing pAdapter->Type and other fields)
            if (pAdapter->OperStatus == MIB_IF_OPER_STATUS_UP) {
                printf("UP RUNNING ");
            } else {
                printf("DOWN ");
            }
            printf("\n");
            pAdapter = pAdapter->Next;
        }
    } else {
        printf("GetAdaptersInfo failed with error: %ld\n", dwRet);
    }
    if (pAdapterInfo) free(pAdapterInfo);


#else
    // Linux and macOS implementation using getifaddrs
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }

    printf("Interface    IP Address          Netmask          Flags\n");
    printf("-----------------------------------------------------------\n");

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        // For IPv4 addresses
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;

            char ip[INET_ADDRSTRLEN];
            char mask[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &netmask->sin_addr, mask, INET_ADDRSTRLEN);

            printf("%-12s %-18s %-18s ", ifa->ifa_name, ip, mask);

            // Show flags
            if (ifa->ifa_flags & IFF_UP) printf("UP ");
            if (ifa->ifa_flags & IFF_RUNNING) printf("RUNNING ");
            if (ifa->ifa_flags & IFF_LOOPBACK) printf("LOOPBACK ");
            if (ifa->ifa_flags & IFF_BROADCAST) printf("BROADCAST ");
            if (ifa->ifa_flags & IFF_MULTICAST) printf("MULTICAST ");
            if (ifa->ifa_flags & IFF_POINTOPOINT) printf("POINTOPOINT ");

            printf("\n");
        }
        // Optionally add IPv6 support here
    }

    freeifaddrs(ifaddr);
#endif
    return 1;
}

// Check if firewall is active
int check_firewall_status(void) {
    printf("Checking firewall status...\n");
    printf("-------------------------\n");

#ifdef __linux__
    // Linux: Check for iptables, ufw, firewalld
    int iptables_found = 0;
    FILE *fp = fopen("/sbin/iptables", "r");
    if (fp) {
        iptables_found = 1;
        fclose(fp);
    } else {
        fp = fopen("/usr/sbin/iptables", "r");
        if (fp) {
            iptables_found = 1;
            fclose(fp);
        }
    }

    int ufw_found = 0;
    fp = fopen("/etc/ufw/ufw.conf", "r");
    if (fp) {
        ufw_found = 1;
        fclose(fp);
    }

    int firewalld_found = 0;
    fp = fopen("/etc/firewalld/firewalld.conf", "r");
    if (fp) {
        firewalld_found = 1;
        fclose(fp);
    }

    if (iptables_found || ufw_found || firewalld_found) {
        printf("Firewall software detected (iptables, ufw, firewalld). Status details require root or service check.\n");
    } else {
        printf("No common firewall software detected in standard locations.\n");
    }


#elif defined(_WIN32)
    // Windows: Check Windows Firewall status using netsh command
    FILE *fp = popen("netsh advfirewall show currentprofile", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (strstr(line, "Firewall Policy") != NULL && strstr(line, "Enabled") != NULL) {
                printf("%s", line); // Print lines related to firewall status
            }
        }
        pclose(fp);
    } else {
        perror("popen");
        printf("Could not run netsh command to check firewall status.\n");
    }

#elif defined(__APPLE__)
    // macOS: Check macOS Firewall using command line (pfctl or systemsetup)
    FILE *fp = popen("systemsetup -getremotelogin", "r"); // Check Remote Login (SSH) as a basic firewall indicator
    if (fp) {
        char line[512];
        if (fgets(line, sizeof(line), fp) != NULL) {
            printf("macOS Firewall (Remote Login status): %s", line);
        }
        pclose(fp);
    } else {
        perror("popen");
        printf("Could not check macOS firewall status.\n");
    }
    // More comprehensive macOS firewall checks would involve using pfctl, which is more complex and might require root.
    printf("For more detailed macOS firewall status, use 'sudo pfctl -s all' in Terminal.\n");

#else
    printf("Firewall status check not implemented for this platform.\n");
#endif

    return 1;
}
