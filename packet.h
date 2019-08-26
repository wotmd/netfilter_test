#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct EthernetHeader {
    u_char ether_dst[6];
    u_char ether_src[6];
    uint16_t type;
};

struct IpHeader {
    uint8_t version_ihl;
    uint8_t service_type;
    uint16_t totalLen;
    uint16_t identification;
    uint16_t flag;
    uint8_t time2live;
    uint8_t protocol;

    uint16_t checksum;
    uint32_t ip_src;
    uint32_t ip_dst;
};

struct TCPHeader {
    uint16_t port_src;
    uint16_t port_dst;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint16_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent;
};

struct ARPHeader {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    u_char sender_mac[6];
    u_char sender_ip[4];
    u_char target_mac[6];
    u_char target_ip[4];
};

struct ARPpacket{
    EthernetHeader ether_header;
    ARPHeader arp_header;
};

void print_mac(const u_char* mac);
void print_ip(const u_char* ip);
void print_port(uint16_t port);
uint16_t my_ntohs(uint16_t n);
uint32_t my_ntohl(uint32_t n);
uint16_t parsing_ethernet_header(const u_char* data);
uint16_t parsing_ip_header(const u_char* data);
uint8_t parsing_tcp_header(const u_char* data);
void parsing_string2ip(u_char* ip, char* data);


#endif // PACKET_H
