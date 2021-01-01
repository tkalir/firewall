#ifndef __SKBUFF_COOKER_H
#define __SKBUFF_COOKER_H

#include <linux/skbuff.h>
#include <linux/types.h>

typedef struct sk_buff sk_buff;

typedef struct skbuff_cooker
{
	sk_buff* skb;
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
}skbuff_cooker;

void cooker_init(skbuff_cooker* cooker, struct sk_buff* skb);

void change_src_ip(skbuff_cooker* cooker, __be32 ip);

void change_dst_ip(skbuff_cooker* cooker, __be32 ip);

void change_dst_port(skbuff_cooker* cooker, __be16 port);

void change_src_port(skbuff_cooker* cooker, __be16 port);

int cook(skbuff_cooker* cooker);

#endif
