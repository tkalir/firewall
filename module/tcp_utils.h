#ifndef __TCP_UTILS_H
#define __TCP_UTILS_H
#include <net/tcp.h>
#include <linux/tcp.h>

typedef struct tcphdr tcphdr;

int is_hdr_fin(tcphdr* hdr);
int is_hdr_synack(tcphdr* hdr);
int is_hdr_syn(tcphdr* hdr);
int is_hdr_ack(tcphdr* hdr);
int is_hdr_established(tcphdr* hdr);

#endif
