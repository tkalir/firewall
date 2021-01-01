#ifndef _CONNECTION_TABLE_H_
#define _CONNECTION_TABLE_H_

#include <linux/tcp.h>
#include <linux/list.h>
#include "fw.h"
#include "port_list.h"

typedef struct sk_buff sk_buff;
typedef struct list_head list_head;

#define HTTP_PORT_BE 20480
#define FTP_PORT_BE 5376
#define BE_HTTP_PROXY_PORT 8195
#define BE_FTP_PROXY_PORT 53760

#define FW_IOC_MAGIC  'f'
#define IOR_GET_IP_HTTP 42
#define IOR_GET_IP_FTP 43
#define IOW_FTP_PORT 44

//_IOR(FW_IOC_MAGIC, 2, unsigned short)
typedef enum {
	STATE_LISTENING			= 0,
	STATE_SYN_SENT			= 1,
	STATE_SYNACK_SENT		= 2,
	STATE_SERVER_ESTABLISHED	= 3,
	STATE_CLIENT_ESTABLISHED	= 4,
	STATE_FIN_SENT			= 5,
	STATE_CLOSED			= 6,
}state_t;

typedef struct connection_table_t
{
	list_head connections;
	list_head http_clients;
	list_head http_servers;
	list_head ftp_clients;
	list_head ftp_servers;
	port_list_t port_list;
}connection_table_t;

typedef struct connection_log_t
{
	unsigned int	src_ip;
	unsigned int	dst_ip;
	unsigned short	src_port;
	unsigned short	dst_port;
	state_t state;
}connection_log_t;


typedef struct connection_id_t
{
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port;
	__be16	dst_port;
}connection_id_t;

typedef struct connection_entry_t
{
	list_head list;
	connection_id_t connection_id;
	state_t state;
	struct connection_entry_t* other;
}connection_entry_t;

typedef struct connection_t
{
	list_head list;
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port;
	__be16	dst_port;
	state_t state;
	struct connection_t* other;
}connection_t;

typedef struct proxied_connection_t
{
	list_head list;
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port;
	__be16	dst_port;
	state_t state;
	struct connection_t* other;
	__be16 proxy_port;
}proxied_connection_t;


typedef struct http_connection_t
{
	list_head list;
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port;
	__be16	dst_port;
	state_t state;
	struct connection_t* other;
	__be16 proxy_port;
}http_connection_t;

typedef struct ftp_connection_t
{
	list_head list;
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port;
	__be16	dst_port;
	state_t state;
	struct connection_t* other;
	__be16 proxy_port;
}ftp_connection_t;

typedef struct ip_port_t
{
	__be32	ip;
	__be16	port;
}ip_port_t;

void connection_table_init(connection_table_t* table);

__u8 update_connection_table(connection_table_t* table, packet_info_t* packet, sk_buff* skb);

void get_dest(ip_port_t* dest, connection_t connection);

int update_proxy_2_client(connection_table_t* table, sk_buff* skb);

int update_proxy_2_server(connection_table_t* table, sk_buff* skb);

__u8 new_connection(connection_table_t* table, packet_info_t* packet, sk_buff* skb);

int is_ftp_data(packet_info_t* packet);

ssize_t show_connections(struct device *dev, struct device_attribute *attr, char *buf);

#endif
