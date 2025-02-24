#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <thread>
#include <mutex>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>

class NetworkScanner {
private:
    std::string subnet;
    std::vector<std::string> activeHosts;
    std::mutex mtx;
    static const int PING_TIMEOUT = 1;
    
    struct PingResult {
        std::string ip;
        bool isActive;
        std::string hostname;
        std::string macAddress;
    };

    unsigned short calculateChecksum(unsigned short *addr, int len) {
        int nleft = len;
        int sum = 0;
        unsigned short *w = addr;
        unsigned short answer = 0;

        while (nleft > 1) {
            sum += *w++;
            nleft -= 2;
        }

        if (nleft == 1) {
            *(unsigned char *)(&answer) = *(unsigned char *)w;
            sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        answer = ~sum;
        return answer;
    }

    std::string getMacAddress(const std::string& ip) {
        std::string cmd = "arp -n " + ip + " | grep -v incomplete | tail -n 1 | awk '{print $3}'";
        char buffer[128];
        std::string result;
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            while (!feof(pipe)) {
                if (fgets(buffer, 128, pipe) != nullptr)
                    result += buffer;
            }
            pclose(pipe);
        }
        return result.substr(0, 17);
    }

    void scanHost(const std::string& ip) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) return;

        struct sockaddr_in addr;
        struct icmphdr icmp_hdr;
        char packet[sizeof(struct icmphdr)];
        
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(ip.c_str());

        memset(&icmp_hdr, 0, sizeof(icmp_hdr));
        icmp_hdr.type = ICMP_ECHO;
        icmp_hdr.code = 0;
        icmp_hdr.checksum = 0;
        icmp_hdr.un.echo.id = getpid();
        icmp_hdr.un.echo.sequence = 1;
        memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));
        
        icmp_hdr.checksum = calculateChecksum((unsigned short*)packet, sizeof(icmp_hdr));
        memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));

        if (sendto(sock, packet, sizeof(icmp_hdr), 0, (struct sockaddr*)&addr, sizeof(addr)) > 0) {
            fd_set fdset;
            struct timeval tv;
            FD_ZERO(&fdset);
            FD_SET(sock, &fdset);
            tv.tv_sec = PING_TIMEOUT;
            tv.tv_usec = 0;

            if (select(sock + 1, &fdset, nullptr, nullptr, &tv) > 0) {
                char recv_buf[1024];
                struct sockaddr_in from;
                socklen_t fromlen = sizeof(from);
                
                if (recvfrom(sock, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from, &fromlen) > 0) {
                    std::string hostname;
                    struct hostent *he = gethostbyaddr(&(addr.sin_addr), sizeof(struct in_addr), AF_INET);
                    if (he != nullptr) {
                        hostname = std::string(he->h_name);
                    }
                    
                    std::string macAddr = getMacAddress(ip);
                    
                    std::lock_guard<std::mutex> lock(mtx);
                    activeHosts.push_back(ip + "\t" + hostname + "\t" + macAddr);
                }
            }
        }
        close(sock);
    }

public:
    NetworkScanner() {
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            exit(EXIT_FAILURE);
        }

        for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && 
                (ifa->ifa_flags & IFF_UP) && strcmp(ifa->ifa_name, "lo") != 0) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                subnet = inet_ntoa(sa->sin_addr);
                subnet = subnet.substr(0, subnet.find_last_of(".") + 1);
                break;
            }
        }
        freeifaddrs(ifaddr);
    }

    void scan() {
        std::vector<std::thread> threads;
        for (int i = 1; i < 255; i++) {
            std::string ip = subnet + std::to_string(i);
            threads.emplace_back(&NetworkScanner::scanHost, this, ip);
        }

        for (auto& thread : threads) {
            thread.join();
        }

        std::cout << "\nActive Hosts:\n";
        std::cout << "IP Address\tHostname\tMAC Address\n";
        std::cout << std::string(60, '-') << "\n";
        
        for (const auto& host : activeHosts) {
            std::cout << host << "\n";
        }
    }
};

int main() {
    if (getuid() != 0) {
        std::cerr << "This program must be run as root\n";
        return 1;
    }

    NetworkScanner scanner;
    scanner.scan();
    return 0;
}
