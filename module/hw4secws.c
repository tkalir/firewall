#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/time.h>

#include <linux/skbuff.h>
#include "fw.h"
#include "rule_base.h"
#include "logger.h"
#include "sysfs_handler.h"
#include "connection_table.h"
#include "proxy_handler.h"

#define ERROR -1
#define OK 0
#define RESET_LOG_MSG '0'

void proxy_dev_destroy(void);
int create_proxy_device(struct class* class);

MODULE_LICENSE("GPL");

//forward declerations
static int register_hook(struct nf_hook_ops* hook);
static int register_hooks(void);
static void unregister_hooks(void);

//typedefs
typedef struct udphdr udphdr;
typedef struct tcphdr tcphdr;
typedef struct sk_buff sk_buff;
typedef struct iphdr iphdr;

//static variables
static struct nf_hook_ops forward_hook;
static struct nf_hook_ops local_in_hook;
static struct nf_hook_ops local_out_hook;
static rule_base_t rules;
static logger_t logger;
static connection_table_t connections;
static struct class* class;

int set_sysfs(void);
int fix_checksum(__be32 dst_ip, __be16 dst_port, struct sk_buff* skbuff);

int is_christmas_tree(tcphdr* header)
{
	return (header->ack & header->fin & header->urg);
}
//---------------------------------------------------------
parse_stat_t parse_transport_header
(sk_buff* skb, packet_info_t* info)
{
	udphdr* udp_header;
  tcphdr* tcp_header;
	switch(info->protocol)
	{
		case PROT_UDP:
			udp_header = (udphdr*)skb_transport_header(skb);
                	info->src_port = udp_header->source;
			info->dst_port = udp_header->dest;
			info->ack      = 0; //for log match
			break;
        	case PROT_TCP:
                	tcp_header = (tcphdr*)skb_transport_header(skb);
                	info->src_port = tcp_header->source;
                	info->dst_port = tcp_header->dest;
			info->ack = (tcp_header->ack) ? ACK_YES : ACK_NO;
			return is_christmas_tree(tcp_header);
		case PROT_ICMP:
                	info->src_port = 0; //for log match
                	info->dst_port = 0;
			info->ack      = 0;
			break;
		default: 
			return PARSE_STAT_NOT_SUPPORTED;
	}
	return PARSE_STAT_OK;
}
//---------------------------------------------------------
direction_t get_direction(const struct nf_hook_state* state)
{
	if(state->out->name != NULL) 
	{
		if(strncmp(state->out->name,IN_NET_DEVICE_NAME,NET_NAME_LEN) == 0)
		{
			return DIRECTION_IN;	
		}
		if(strncmp(state->out->name,OUT_NET_DEVICE_NAME,NET_NAME_LEN) == 0)
		{
			return DIRECTION_OUT;	
		}
	}
	if(state->in->name != NULL) 
	{
		if(strncmp(state->in->name,IN_NET_DEVICE_NAME,NET_NAME_LEN) == 0)
		{
			return DIRECTION_OUT;	
		}
		if(strncmp(state->in->name,OUT_NET_DEVICE_NAME,NET_NAME_LEN) == 0)
		{
			return DIRECTION_IN;	
		}
	}
	return DIRECTION_LOOPBACK;
}
//---------------------------------------------------------
unsigned long get_timestamp(struct sk_buff* skb)
{
	struct timeval val;
	skb_get_timestamp(skb, &val);
	return val.tv_sec;
}

parse_stat_t parse_packet(struct sk_buff* skb, packet_info_t* info, const struct nf_hook_state* state)
{
 	iphdr* ip_header = (iphdr*)skb_network_header(skb);
	parse_stat_t stat;

	if(ip_header->version != IP_VERSION)
	{
		return PARSE_STAT_NOT_SUPPORTED;
	}

	info->direction = get_direction(state);
	if(info->direction == DIRECTION_LOOPBACK)
		return PARSE_STAT_LOOPBACK;
	info->src_ip = ip_header->saddr;
	info->dst_ip = ip_header->daddr;
	info->protocol = ip_header->protocol;
	stat = parse_transport_header(skb, info);
	info->timestamp = get_timestamp(skb);
	return stat;
}
//---------------------------------------------------------
int get_reason(int index, parse_stat_t stat)
{
	if(index == -1)
	{
		return REASON_NO_MATCHING_RULE;
	}
	if(stat == PARSE_STAT_XMAS_PACKET)
	{
		return REASON_XMAS_PACKET;
	}
	return index; //assuming index >= 0
}

__u8 decide_static_table(packet_info_t* packet, parse_stat_t stat, reason_t* reason)
{
	__u8 action = NF_DROP;
	int index = rule_base_match(&rules, packet, &action);
	*reason = get_reason(index, stat);
	return action;
}
//---------------------------------------------------------
__u8 decide_tcp_packet(packet_info_t* packet, parse_stat_t stat, sk_buff* skb, reason_t* reason)
{
	__u8 action;
	if(packet->ack == ACK_NO && !is_ftp_data(packet))
	{
		action = decide_static_table(packet, stat, reason);
printk(KERN_INFO "static deciding src port %d", packet->src_port);
		if(action == NF_DROP)
		{
printk(KERN_INFO "static dropping src port %d", packet->src_port);
			return NF_DROP;
		}
		action = new_connection(&connections, packet, skb);
printk(KERN_INFO "new con src port %d, dst %d, dropped? %d", ntohs(packet->src_port),ntohs(packet->dst_port), action != NF_ACCEPT);
		*reason = action == NF_DROP ? REASON_TCP_ILLEGAL : REASON_TCP_CONNECTION;
		return action;
	}
	printk(KERN_INFO "dynamic deciding");
	action = update_connection_table(&connections, packet, skb);
	*reason = action == NF_DROP ? REASON_TCP_ILLEGAL : REASON_TCP_CONNECTION;
	printk(KERN_INFO "src port %d, dst %d, dropped? %d", ntohs(packet->src_port),ntohs(packet->dst_port), action != NF_ACCEPT);
	return action;
}
//---------------------------------------------------------
int is_tcp_packet(packet_info_t* packet)
{
	return packet->protocol == PROT_TCP;
}

//---------------------------------------------------------
unsigned int func_local_in(void *priv, struct sk_buff *skb,const struct nf_hook_state *state)
{
	tcphdr* tcp_header;
	unsigned short dst_port;
	iphdr* ip_header = (iphdr*)skb_network_header(skb);
	tcp_header = (tcphdr*)skb_transport_header(skb);
  dst_port = tcp_header->dest;
//	printk(KERN_INFO "sent in, src %d dst %d", src_port, dst_port);
	printk(KERN_INFO "ip dst %d port %d", ip_header->daddr, tcp_header->dest);
	return NF_ACCEPT;
}
//---------------------------------------------------------
unsigned int hook_func(void *priv, struct sk_buff *skb,
const struct nf_hook_state *state)
{
	packet_info_t packet;
	parse_stat_t stat;
	__u8 action = NF_DROP;
	reason_t reason;
	int res;
	//iphdr* ip_header;

	stat = parse_packet(skb, &packet, state);
	packet.direction = get_direction(state);
	if(stat == PARSE_STAT_NOT_SUPPORTED || 
		stat == PARSE_STAT_LOOPBACK)
	{
		return NF_ACCEPT;
	}

	if(is_tcp_packet(&packet))
	{
		 action = decide_tcp_packet(&packet, stat, skb, &reason);
		}else{
		 action = decide_static_table(&packet, stat, &reason);
	}
	res = log_packet(&logger, &packet, action, reason);
	printk(KERN_INFO "dropped? %d", action != NF_ACCEPT);
	return action;
}
//---------------------------------------------------------
unsigned int hook_nothing(void *priv, struct sk_buff *skb,
const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

//---------------------------------------------------------
unsigned int hook_local_out(void *priv, struct sk_buff *skb,
const struct nf_hook_state *state)
{
	int res;
	tcphdr* tcp_header = (tcphdr*)skb_transport_header(skb);

	if(tcp_header->source == BE_HTTP_PROXY_PORT || 
		tcp_header->source == BE_FTP_PROXY_PORT)
	{
		res = update_proxy_2_client(&connections, skb);
	}else{
		res = update_proxy_2_server(&connections, skb);
	}
	return NF_ACCEPT;
}

//---------------------------------------------------------
ssize_t read_reset_file(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	
{
	ssize_t nread;
	char msg;
	nread = sscanf(buf, "%c", &msg);
	if (nread == 1) 
	{
		if(msg == RESET_LOG_MSG)
		{
			reset_logs(&logger);
		}
		return sizeof(msg);	
	}
	return -EINVAL;
}
//---------------------------------------------------------
int set_sysfs()
{
	if(sysfs_handler_create() != OK)
	{
		return ERROR;
	}
	if(init_sysfs_logs("log", "reset", NULL, read_reset_file, 
		S_IWUSR) != OK)
	{
		sysfs_handler_destroy_class();
		return ERROR;
	}
 
	if(init_sysfs_rules("rules", "rules", show_rules, read_rules, 
		S_IWUSR | S_IRUGO) != OK)
	{
		sysfs_handler_destroy_logs();
		sysfs_handler_destroy_class();
		return ERROR;
	}
	if(init_sysfs_connections("conns", "conns", show_connections, NULL, S_IRUGO) != OK)
	{
		sysfs_handler_destroy_logs();
		sysfs_handler_destroy_rules();
		sysfs_handler_destroy_class(); 
		return ERROR;
	}
	return OK;
}
//---------------------------------------------------------
static int __init firewall_init(void)
{
	if(set_sysfs() != OK)
	{
		return ERROR;
	}
	class = get_class();
	if(create_proxy_device(class) == ERROR)
	{
		destroy_sysfs();
		return ERROR;
	}
	if (register_hooks() == ERROR)
	{
		proxy_dev_destroy();
		destroy_sysfs();
		return ERROR;
	}

	rule_base_init(&rules, NF_DROP);
	logger_init(&logger);
	connection_table_init(&connections);

	return OK;
}
//---------------------------------------------------------
static void __exit firewall_exit(void)
{
	proxy_dev_destroy();
	unregister_hooks();
	destroy_sysfs();
	reset_logs(&logger);
	destroy_logger();

}
//---------------------------------------------------------
static void set_hook(struct nf_hook_ops* hook)
{
	hook->pf          = PF_INET;
	hook->priority    = NF_IP_PRI_FIRST;
}
//---------------------------------------------------------

static void set_forward_hook(struct nf_hook_ops* hook)
{
	set_hook(hook);
//	hook->hook        = hook_nothing;
	hook->hook        = hook_func;
	hook->hooknum     = NF_INET_PRE_ROUTING;
}
//---------------------------------------------------------
static void set_local_in_hook(struct nf_hook_ops* hook)
{
	set_hook(hook);
	hook->hook        = func_local_in;
	hook->hooknum     = NF_INET_LOCAL_IN;
}

//---------------------------------------------------------
static void set_local_out_hook(struct nf_hook_ops* hook)
{
	set_hook(hook);
	hook->hook        = hook_local_out;
	hook->hooknum     = NF_INET_LOCAL_OUT;
}

//---------------------------------------------------------
static int register_hooks(void)
{
	set_forward_hook(&forward_hook);
	set_local_in_hook(&local_in_hook);
	set_local_out_hook(&local_out_hook);

	if(register_hook(&forward_hook) == ERROR)
	{
		return ERROR;
	}
	if(register_hook(&local_in_hook) == ERROR)
	{
		nf_unregister_net_hook(&init_net, &forward_hook);
		return ERROR;
	}
	if(register_hook(&local_out_hook) == ERROR)
	{
		nf_unregister_net_hook(&init_net, &local_in_hook);
		nf_unregister_net_hook(&init_net, &forward_hook);
		return ERROR;
	}
	return OK;
}
//---------------------------------------------------------
static int register_hook(struct nf_hook_ops* hook)
{
	if(nf_register_net_hook(&init_net, hook) < 0)
	{
		return ERROR;
	}
	return OK;
}
//---------------------------------------------------------
static void unregister_hooks(void)
{
	nf_unregister_net_hook(&init_net, &forward_hook);
	nf_unregister_net_hook(&init_net, &local_in_hook);
	nf_unregister_net_hook(&init_net, &local_out_hook);
}

//---------------------------------------------------------

ssize_t read_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	
{
	int nrules;
	if(count > sizeof(int))
	{
		nrules = *(int*)buf;
	}else{
		return count;
	}
	if(nrules > MAX_RULES || count != calc_table_size(nrules))
	{
		return count;
	}
	load_rules(&rules, (rule_table_t*)buf);
	return count;
}

//---------------------------------------------------------

ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf)	
{
	ssize_t table_size = calc_table_size(rules.nRules);
	memcpy(buf, &rules, table_size); 
	return table_size;
}


module_init(firewall_init);
module_exit(firewall_exit);
