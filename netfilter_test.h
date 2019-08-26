#ifndef NFQNL_H
#define NFQNL_H

#include "packet.h"
#include <pcap.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>

void dump(unsigned char* buf, int size);
u_int32_t filter_host (struct nfq_data *tb, char* hostname, bool* isok);

#endif // NFQNL_H
