#include "rule_base.h"
#define LOOPBACK_MASK 0xFF //big endian
#define LOOPBACK_IP 0x7F //big endian

MODULE_LICENSE("GPL");

void rule_base_init(rule_base_t* rules, __u8 default_action)
{
	rules->nRules = 0;
	rules->default_action = default_action;
}

size_t calc_table_size(int nrules)
{
	return sizeof(int) + nrules * sizeof(rule_generic_t);
}

void load_rules(rule_base_t* base, rule_table_t* table)
{
	memcpy(base, table, calc_table_size(table->nrules));
}

int match_ip(__be32 prefix_mask, __be32 subnet, __be32 address)
{
	return (prefix_mask & address) == (prefix_mask & subnet);
}

int is_above_1023(__be16 port)
{
	return ntohs((unsigned short)port) > 1023 ;
}

int match_ack(ack_t ack, ack_t rule_ack, __u8 protocol)
{
	if(rule_ack != ACK_ANY && protocol != PROT_TCP)
	{
		return 0;
	}
	if(ack != (ack & rule_ack))
	{
		return 0;
	}
	return 1;

}

int match_port(__be16 rule_port, __be16 port)
{
	const unsigned short be1023 = 65283;
	if(rule_port == 0)
	{
		return 1;
	}
	if(((int)rule_port == (int)be1023) && (is_above_1023(port)))
	{
		return 1;
	}
	return rule_port == port;
}

int match(rule_t* rule, packet_info_t* info)
{
	if((info->protocol != rule->protocol) && (rule->protocol != PROT_ANY))
	{
		return 0;
	}
	if(match_ip (rule->src_prefix_mask, rule->src_ip, info->src_ip) == 0)
	{
		return 0;	
	}
	if(match_ip(rule->dst_prefix_mask, rule->dst_ip, info->dst_ip) == 0)
	{
		return 0;	
	}
	if((rule->direction & info->direction) == 0)
	{
		return 0;
	}
	if(match_port(rule->src_port, info->src_port) == 0)
	{
		return 0;
	}
	if(match_port(rule->dst_port, info->dst_port) == 0)
	{
		return 0;
	}
	if(match_ack(info->ack, rule->ack, info->protocol) == 0)
	{
		return 0;
	}
	return 1;
}

int is_loopback(packet_info_t* info)
{
	if(match_ip(LOOPBACK_MASK, LOOPBACK_IP, info->src_ip))
	{
		return 1;
	}
	if(match_ip(LOOPBACK_MASK, LOOPBACK_IP, info->dst_ip))
	{
		return 1;
	}
	return 0;
}

int rule_base_match(rule_base_t* base, packet_info_t* info, __u8* action)
{
	int i;
	for(i = 0; i < base->nRules; i++)
	{
		if(match(&base->rules[i], info))
		{
			*action = base->rules[i].action;
			return i;	
		}
	}
	return -1;
}
