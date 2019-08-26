#include "packet.h"

uint16_t my_ntohs(uint16_t n) {	// network byte order to host byte order (2byte)
    return n << 8 | n >> 8;
}

uint32_t my_ntohl(uint32_t n) { //
    return
        ((n & 0x000000FF) << 24) |
        ((n & 0x0000FF00) << 8) |
        ((n & 0x00FF0000) >> 8) |
        ((n & 0xFF000000) >> 24);
}

uint16_t parsing_ethernet_header(const u_char* data)
{
    printf("=========== Ethernet header ===========\n");
    const EthernetHeader* ether_header = reinterpret_cast<const EthernetHeader*>(data);

    printf("Dmac : ");
    print_mac(ether_header->ether_dst);
    printf("Smac : ");
    print_mac(ether_header->ether_src);

    return my_ntohs(ether_header->type);
}

uint16_t parsing_ip_header(const u_char* data)
{
    printf("============== Ip header ==============\n");
    const IpHeader* ip_header = reinterpret_cast<const IpHeader*>(data);

    return ip_header->protocol;
}

uint8_t parsing_tcp_header(const u_char* data)
{
    printf("============= TCP header ==============\n");
    const TCPHeader* tcp_header = reinterpret_cast<const TCPHeader*>(data);

    printf("Sport : ");
    print_port(tcp_header->port_src);
    printf("Dport : ");
    print_port(tcp_header->port_dst);

    uint8_t headerLen = (tcp_header->flags & 0xFF)>>2;
    return headerLen;
}

void parsing_string2ip(u_char* ip, char* data)
{
    char* ipnum = strtok(data,".");
    for(int i=0; i<4; i++){
        ip[i] = atoi(ipnum);
        ipnum = strtok(NULL,".");
    }
}

void print_mac(const u_char* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char* ip) {
    printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(uint16_t port) {
    printf("%u\n", (port&0xFF) << 8 | port >> 8);
}
