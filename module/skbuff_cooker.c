#include <linux/ip.h>
#include <uapi/linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include "skbuff_cooker.h"

#define ERROR -1
#define OK 0
 
typedef struct iphdr iphdr;
typedef struct tcphdr tcphdr;

void cooker_init(skbuff_cooker* cooker, struct sk_buff* skb)
{
	iphdr* ip_header = (iphdr*)skb_network_header(skb);
	tcphdr* tcp_header = (tcphdr*)skb_transport_header(skb);

	cooker->skb = skb;
	cooker->src_ip = ip_header->saddr;
	cooker->dst_ip = ip_header->daddr;
	cooker->src_port = tcp_header->source;
	cooker->dst_port = tcp_header->dest;
}

void change_src_ip(skbuff_cooker* cooker, __be32 ip)
{
	cooker->src_ip = ip;	
}

void change_dst_ip(skbuff_cooker* cooker, __be32 ip)
{
	cooker->dst_ip = ip;	
}

void change_dst_port(skbuff_cooker* cooker, __be16 port)
{
	cooker->dst_port = port;	
}

void change_src_port(skbuff_cooker* cooker, __be16 port)
{
	cooker->src_port = port;	
}

int cook(skbuff_cooker* cooker)
{
	sk_buff* skb = cooker->skb;
	iphdr* ip_header = (iphdr*)skb_network_header(skb);
	tcphdr* tcp_header = (tcphdr*)skb_transport_header(skb);
	__u16 tcplen;

	/* Change the routing */
	ip_header->daddr = cooker->dst_ip;
	ip_header->saddr = cooker->src_ip;
 	tcp_header->dest = cooker->dst_port;
 	tcp_header->source = cooker->src_port;
	
	/* Fix IP header checksum */
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

	skb->ip_summed = CHECKSUM_NONE;
	skb->csum_valid = 0;

	/* Linearize the skb */
	if (skb_linearize(skb) < 0) {
		printk(KERN_INFO "error");
		return ERROR;
	}

	/* Re-take headers. The linearize may change skb's pointers */
	ip_header = ip_hdr(skb);
	tcp_header = tcp_hdr(skb);

	/* Fix TCP header checksum */
	tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
	tcp_header->check = 0;
	tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));
	printk(KERN_INFO "new ip %d",ntohl(ip_header->daddr));
	printk(KERN_INFO "new port %d",ntohs(tcp_header->dest));
	return OK;
}
