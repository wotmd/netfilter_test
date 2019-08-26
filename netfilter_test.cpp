#include "netfilter_test.h"

/*
 * nfqnl_test.c 예제에서 nfq_get_payload 함수가 수행이 되면 패킷의
 * IP header 시작 위치가 data라는 포인터 변수에 넘어 온다. 이후 IP, TCP, Data(HTTP)를 파싱하여
 * Host의 값이 유해 사이트(프로그램의 argument)인 경우
 * 차단(nfq_set_verdict 함수 인자에 NF_DROP으로 설정)을 하고
 * 나머지 경우에는 허용(NF_ACCEPT)을 하도록 코딩을 작성하여 사이트가 차단이 되는지 확인해 본다.
 *
 * 1. HTTP를 tcp port 80으로 가정한다.
 * 2. HTTP Response는 고려하지 않고 HTTP Request만 본다.
 * 3. TCP Data는 HTTP method(GET, POST 등등)로 시작한다(https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods).
*/

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0){
            printf("\n");
        }
        printf("%02x ", buf[i]);
    }
}

/* returns packet id */
u_int32_t filter_host (struct nfq_data *tb, char* hostname, bool* isok)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph)
        id = ntohl(ph->packet_id);

    ret = nfq_get_payload(tb, &data);

    const IpHeader* ipHeader = reinterpret_cast<const IpHeader*>(data);

    if(ipHeader->protocol == 6){
        size_t ipSize = (ipHeader->version_ihl&0xF)<<2;
        data += ipSize;

        const TCPHeader* tcp_header = reinterpret_cast<const TCPHeader*>(data);

        if(tcp_header->port_dst == my_ntohs(80)){ // request
            size_t tcpSize = (my_ntohs(tcp_header->flags) >> 12) << 2;
            data += tcpSize;

            if(!memcmp(data, "GET", 3) || !memcmp(data, "POST", 4)){
                char* host = strtok((char*)data, "\r\n");

                if(host != NULL){
                    host = strtok(NULL,"\r\n");
                    host+=6;

                    if(!strcmp(host, hostname)){
                        printf("host \"%s\" is not allow!\n", host);
                        *isok = false;
                    }
                }
            }
        }
    }

    return id;
}
