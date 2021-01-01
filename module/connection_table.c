#include <net/tcp.h>
#include <linux/cdev.h>
#include "connection_table.h"
#include "tcp_utils.h"
#include "skbuff_cooker.h"
#include "list_utils.h"

#define ERROR -1
#define OK 0

typedef struct connection_handler connection_handler;

typedef struct tcphdr tcphdr;
typedef struct iphdr iphdr;

typedef enum
{
	SIDE_CLIENT,
	SIDE_SERVER,
}side_t;

typedef enum
{
	HTTP = 80,
	FTP = 21,
}proxy_prot_t;

int redirect_to_proxy(struct sk_buff *skb, __be16 proxy_port, __be16 prot);

void set_handler(connection_table_t* table, connection_handler* handler, packet_info_t* packet);

connection_id_t* get_id(connection_t* conn);

list_head* get_list(connection_table_t* table, proxy_prot_t prot, side_t side);

void* find_http(struct connection_handler* handler, void* key);

__u8 update_http(connection_handler* handler, void* connec, struct sk_buff* skb);
int compare_by_proxy(list_head* list, void* item);
int compare_by_connection(list_head* list, void* item);
int redirect_srv_to_proxy(struct sk_buff *skb, __be32 ip);

struct connection_handler
{
	void* (*get_key)(connection_table_t*, packet_info_t*);
	void* (*find)(struct connection_handler*, void*);
	int (*should_add)(connection_table_t*, sk_buff*);
	int (*add)(struct connection_handler*, void*);
	__u8 (*update)(struct connection_handler*, void*, sk_buff*);

	list_head* list;
	connection_table_t* table;
	int to_proxy;
	proxy_prot_t prot;
	side_t side;
	connection_t* added;
};

static connection_table_t* static_table = NULL;
__be16 id_port = 0;

//---------------------------------------------------------

void connection_table_init(connection_table_t* table)
{
	static_table = table;
	INIT_LIST_HEAD(&table->connections);
	INIT_LIST_HEAD(&table->http_clients);
	INIT_LIST_HEAD(&table->http_servers);
	INIT_LIST_HEAD(&table->ftp_clients);
	INIT_LIST_HEAD(&table->ftp_servers);
	port_list_init(&table->port_list);
}

//---------------------------------------------------------

static void* allocate(size_t size)
{
	return kmalloc(size, GFP_KERNEL);
}

//---------------------------------------------------------

void* id_from_packet(packet_info_t* packet)
{
	return (connection_id_t*)&packet->src_ip;
}	


//---------------------------------------------------------

int should_add_regular(connection_table_t* table, sk_buff* skb)
{
	tcphdr* hdr = (tcphdr*)skb_transport_header(skb);
	return hdr->ack == 0 && hdr->syn == 1;
}


//---------------------------------------------------------

void flip(connection_t* connection)
{
	__be32	old_src_ip = connection->src_ip;
	__be16	old_src_port = connection->src_port;
	connection->src_ip = connection->dst_ip;
	connection->src_port = connection->dst_port;
	connection->dst_ip = old_src_ip;
	connection->dst_port = old_src_port;
}

//---------------------------------------------------------
connection_id_t* get_id(connection_t* conn)
{
	return (connection_id_t*)&conn->src_ip;
}

//---------------------------------------------------------

proxied_connection_t* create_connection_pair(void* connection_id, proxied_connection_t** other)
{
	proxied_connection_t* c2s = allocate(sizeof(proxied_connection_t));
	proxied_connection_t* s2c;
	if(c2s == NULL)
		return NULL;
	s2c = allocate(sizeof(proxied_connection_t));
	if(s2c == NULL)
	{
		kfree(c2s);
		return NULL;
	}
	memcpy(get_id((connection_t*)c2s), connection_id, sizeof(connection_id_t));
	memcpy(get_id((connection_t*)s2c), connection_id, sizeof(connection_id_t));
	flip((connection_t*)s2c);
	c2s->state = STATE_SYN_SENT;	
	s2c->state = STATE_CLOSED;
	c2s->other = (connection_t*)s2c;
	s2c->other = (connection_t*)c2s;
	*other = s2c;
	return c2s;
}

void destroy_connection_pair(proxied_connection_t* connection)
{
	kfree(connection->other);
	kfree(connection);
}

//---------------------------------------------------------


int add_regular(connection_handler* handler, void* connection_id)
{
	connection_entry_t* c2s = allocate(sizeof(connection_entry_t));
	connection_entry_t* s2c;
	
	if(c2s == NULL)
		return ERROR;
	s2c = allocate(sizeof(connection_entry_t));
	if(s2c == NULL)
	{
		kfree(c2s);
		return ERROR;
	}
	memcpy(&c2s->connection_id, connection_id, sizeof(connection_id_t));
	memcpy(&s2c->connection_id, connection_id, sizeof(connection_id_t));
	flip((connection_t*)s2c);
	c2s->state = STATE_SYN_SENT;	
	s2c->state = STATE_LISTENING;
	c2s->other = s2c;
	s2c->other = c2s;
	list_add(&c2s->list, handler->list);
	list_add(&s2c->list, handler->list);
	return 0;
}

//---------------------------------------------------------

void* find_regular(struct connection_handler* handler, void* key)
{
	connection_entry_t* pos;
	list_head* head = handler->list;
	list_for_each_entry(pos, head, list)
	{
		if(memcmp(&pos->connection_id, key, sizeof(connection_id_t)) == 0)
		{
			printk(KERN_INFO "match");
			return pos;
		}		
	}
	printk(KERN_INFO "no match");
	return NULL;
}

//---------------------------------------------------------
__u8 update_server_established(state_t* state, state_t other_state, tcphdr* hdr)
{
		if(is_hdr_fin(hdr))
		{
			*state = STATE_FIN_SENT;
			return NF_ACCEPT;
		}
		if(is_hdr_established(hdr))
		{
			return NF_ACCEPT;
		}	
		return NF_DROP;
}


//---------------------------------------------------------
__u8 update_client_established(state_t* state, state_t other_state, tcphdr* hdr)
{
		if(is_hdr_fin(hdr))
		{
			*state = STATE_FIN_SENT;
			return NF_ACCEPT;
		}
		if(is_hdr_established(hdr))
		{
			return NF_ACCEPT;
		}	
		return NF_DROP;
}

//---------------------------------------------------------
__u8 update_synsent(state_t* state, state_t other_state, tcphdr* hdr)
{
			if(is_hdr_syn(hdr) && other_state == STATE_LISTENING)
			{
						return NF_ACCEPT;	
			}
			if(is_hdr_ack(hdr) && other_state == STATE_SYNACK_SENT)
			{
				*state = STATE_CLIENT_ESTABLISHED;
				return NF_ACCEPT;	
			}
		return NF_DROP;
}

//---------------------------------------------------------

__u8 update_synacksent(state_t* state, state_t other_state, tcphdr* hdr)
{
	if(is_hdr_synack(hdr) && other_state == STATE_SYN_SENT)
	{
		return NF_ACCEPT;
	}
	if(is_hdr_ack(hdr) && other_state == STATE_CLIENT_ESTABLISHED)
	{
		*state = STATE_SERVER_ESTABLISHED;
		return NF_ACCEPT;
	}
		return NF_DROP;
}

//---------------------------------------------------------
__u8 update_listening(state_t* state, state_t other_state, tcphdr* hdr)
{
if(is_hdr_synack(hdr) && other_state == STATE_SYN_SENT)
		{
			printk(KERN_INFO "yay synack");
			*state = STATE_SYNACK_SENT;
			return NF_ACCEPT;
		}
		printk(KERN_INFO "nay synack syn %d ack %d ", hdr->syn, hdr->ack);
		return NF_DROP;
}

//---------------------------------------------------------
int is_established(state_t state)
{
	return state == STATE_SERVER_ESTABLISHED || state == STATE_CLIENT_ESTABLISHED;
}
//---------------------------------------------------------
__u8 update_fin_sent(state_t* state, state_t other_state, tcphdr* hdr)
{
	if(is_hdr_established(hdr) && other_state == STATE_FIN_SENT)
	{
		*state = STATE_CLOSED;
		return NF_ACCEPT;
	}

	if(is_hdr_established(hdr) && is_established(other_state))
	{
		return NF_ACCEPT;
	}
	if(is_hdr_fin(hdr))
	{
		return NF_ACCEPT;
	}

	return NF_DROP;
}

//---------------------------------------------------------

void remove_connection(connection_t* connection)
{
	list_del(&connection->list);
	kfree(connection);
}

//---------------------------------------------------------
__u8 update_reg_connection(void* connec, sk_buff* skb)
{
	__u8 action;
	connection_t* connection = connec;
	connection_t* other = connection->other;
	tcphdr* hdr = (tcphdr*)skb_transport_header(skb);
	printk(KERN_INFO "state %d other state %d syn %d ack %d rst %d", connection->state, other->state, hdr->syn, hdr->ack, hdr->rst);

	if(hdr->rst == 1)
	{
		return NF_DROP;
	}
	/*if(hdr->rst == 1)
	{
		remove_connection(connection);
		remove_connection(other);
		return NF_ACCEPT;
	}*/
	switch(connection->state)
	{
	case STATE_LISTENING:
		return update_listening(&connection->state, other->state, hdr);

	case STATE_SYNACK_SENT:
		return update_synacksent(&connection->state, other->state, hdr);

	case STATE_SYN_SENT:
			return update_synsent(&connection->state, other->state, hdr);

	case STATE_SERVER_ESTABLISHED:
		return update_server_established(&connection->state, other->state, hdr);

	case STATE_CLIENT_ESTABLISHED:
		return update_client_established(&connection->state, other->state, hdr);

	case STATE_FIN_SENT:
		action = update_fin_sent(&connection->state, other->state, hdr);
		if(connection->state == STATE_CLOSED)
		{
			remove_connection(connection);
			remove_connection(other);
		}
		return action;
		
	default: return NF_DROP;
	}
return NF_DROP;
}

__u8 update_regular(connection_handler* handler, void* connec, sk_buff* skb)
{
	return update_reg_connection(connec, skb);
}


//---------------------------------------------------------
void* connection_id_from_packet(packet_info_t* packet)
{
	return (connection_id_t*)&packet->src_ip;
}

//---------------------------------------------------------
http_connection_t* new_http_client(connection_table_t* table, packet_info_t* packet)
{
	proxied_connection_t* server;
	connection_id_t* id = connection_id_from_packet(packet);
	proxied_connection_t* client = create_connection_pair(id, &server);
	int is_error;

	if(client == NULL)
	{
		return NULL;
	}
	client->proxy_port = port_list_get(&table->port_list, &is_error);

	if(is_error)
	{
		destroy_connection_pair(client);
		return NULL;
	}

	server->proxy_port = client->proxy_port;
	printk(KERN_INFO "src port %d", client->src_port);
	printk(KERN_INFO "proxy port %d",client->proxy_port);

	list_add(&client->list, &(table->http_clients));
	list_add(&server->list, &(table->http_servers));
	return (http_connection_t*)client;
}

//---------------------------------------------------------
ftp_connection_t* new_ftp_client(connection_table_t* table, packet_info_t* packet)
{
	proxied_connection_t* server;
	connection_id_t* id = connection_id_from_packet(packet);
	proxied_connection_t* client = create_connection_pair(id, &server);
	int is_error;

	if(client == NULL)
	{
		return NULL;
	}
	client->proxy_port = port_list_get(&table->port_list, &is_error);

	if(is_error)
	{
		destroy_connection_pair(client);
		return NULL;
	}

	server->proxy_port = client->proxy_port;
	printk(KERN_INFO "src port %d", client->src_port);
	printk(KERN_INFO "proxy port %d",client->proxy_port);

	list_add(&client->list, &(table->ftp_clients));
	list_add(&server->list, &(table->ftp_servers));
	return (ftp_connection_t*)client;
}
//---------------------------------------------------------
void* get_regular_key(connection_table_t* table, packet_info_t* packet)
{
	return (connection_id_t*)&packet->src_ip;
}

//---------------------------------------------------------

int is_proxied(__u16 port)
{
	return port == HTTP_PORT_BE || port == FTP_PORT_BE;
}	

//---------------------------------------------------------
__u8 new_connection(connection_table_t* table, packet_info_t* packet, sk_buff* skb)
{
	proxied_connection_t* conn;
	list_head* find_res;
	list_head* search_in;
	proxy_prot_t prot;

	printk(KERN_INFO "in new connection");
	if(is_proxied(packet->dst_port))
	{
		prot = packet->dst_port == HTTP_PORT_BE ? HTTP : FTP;
		search_in = get_list(table, prot, SIDE_CLIENT);
		find_res = search_list(search_in, compare_by_connection, id_from_packet(packet));
		if(find_res != NULL) //drop if already exists
		{
			return NF_DROP;
		}
		if(packet->dst_port == HTTP_PORT_BE)
		{
			conn = (proxied_connection_t*)new_http_client(table, packet);
		}else{
			conn = (proxied_connection_t*)new_ftp_client(table, packet);
		}
		printk(KERN_INFO "created new client, is null %d", conn == NULL);
		if(conn != NULL)
		{
			redirect_to_proxy(skb, conn->proxy_port, packet->dst_port);
			return NF_ACCEPT;
		}else{
			return NF_DROP;
		}
	}
/*	if(packet->src_port == HTTP_PORT_BE)
	{
		return new_http_client();
	}*/
	return update_connection_table(table, packet, skb);
}

//---------------------------------------------------------
__u8 update_http_connection(connection_table_t* table,
			     packet_info_t* packet, 
			     sk_buff* skb)
{
	list_head* item;
	//list_head* search_in;
	proxied_connection_t* connection;
	//__u8 action = NF_DROP;
	connection_id_t* id = id_from_packet(packet);	
	
	if(packet->dst_port == HTTP_PORT_BE)
	{
		item = search_list(&table->http_clients, compare_by_connection, id);
		if(item == NULL)
		{
		printk(KERN_INFO "dropped http src");
			return NF_DROP;
		}
		connection = list_entry(item, proxied_connection_t, list);
		redirect_to_proxy(skb, connection->proxy_port, HTTP_PORT_BE);
	}

	if(packet->src_port == HTTP_PORT_BE)
	{
		item = search_list(&table->http_servers, compare_by_proxy, &id->dst_port);
		if(item == NULL)
		{
		printk(KERN_INFO "dropped http dst");
			return NF_DROP;
		}
		connection = list_entry(item, proxied_connection_t, list);
		redirect_srv_to_proxy(skb, connection->dst_ip);
		//return NF_DROP;
	}
	
	return NF_ACCEPT;
}
//---------------------------------------------------------
__u8 update_ftp_connection(connection_table_t* table,
			     packet_info_t* packet, 
			     sk_buff* skb)
{
	list_head* item;
	proxied_connection_t* connection;
	connection_id_t* id = id_from_packet(packet);	
	
	if(packet->dst_port == FTP_PORT_BE)
	{
		item = search_list(&table->ftp_clients, compare_by_connection, id);
		if(item == NULL)
		{
			return NF_DROP;
		}
		connection = list_entry(item, proxied_connection_t, list);
		redirect_to_proxy(skb, connection->proxy_port, FTP_PORT_BE);
	}

	if(packet->src_port == FTP_PORT_BE)
	{
		item = search_list(&table->ftp_servers, compare_by_proxy, &id->dst_port);
		if(item == NULL)
		{
			return NF_DROP;
		}
		connection = list_entry(item, proxied_connection_t, list);
		redirect_srv_to_proxy(skb, connection->dst_ip);
	}
	
	return NF_ACCEPT;
}
//---------------------------------------------------------
__u8 update_connection_table(connection_table_t* table,
			     packet_info_t* packet, 
			     sk_buff* skb)
{
	int stat;
	connection_handler handler;
	void* key;
	void* connection;

	if(packet->src_port == HTTP_PORT_BE || packet->dst_port == HTTP_PORT_BE)
	{
		return update_http_connection(table, packet, skb);
	}
	if(packet->src_port == FTP_PORT_BE || packet->dst_port == FTP_PORT_BE)
	{
		return update_ftp_connection(table, packet, skb);
	}
	set_handler(table, &handler, packet);
	key = handler.get_key(table, packet);
	connection = handler.find(&handler, key);

	if(connection == NULL)
	{
		if(handler.should_add(table, skb) && !is_ftp_data(packet))
		{
			stat = handler.add(&handler, key);
			if(stat != 0)
			{	
			printk(KERN_INFO "should add error");
				return NF_DROP;
			}
			printk(KERN_INFO "should add");
			return NF_ACCEPT;
		}else{
			printk(KERN_INFO "shouldnt add");
			return NF_DROP;
		}
	}else{
		return handler.update(&handler, connection, skb);
	}
}
//---------------------------------------------------------

//0 = we are at local_out, 1 = prerouting
void set_2_proxy(connection_handler* handler, int flag)
{
	handler->to_proxy = flag;
}
//---------------------------------------------------------
void set_handler(connection_table_t* table, connection_handler* handler, packet_info_t* packet)
{
	handler->list = &table->connections;
	handler->table = table;

	handler->get_key = get_regular_key;
	handler->find = find_regular;
	handler->should_add = should_add_regular;
	handler->add = add_regular;
	handler->update = update_regular;

	/*if(packet->dst_port == HTTP_PORT_BE || packet->src_port == HTTP_PORT_BE)
	{
		handler->prot = HTTP;
		handler->side = HTTP_PORT_BE ? SIDE_CLIENT : SIDE_SERVER;
		handler->update = update_http;
		handler->add = add_http;
		handler->find = find_http;
	}*/
}


//---------------------------------------------------------


int redirect_srv_to_proxy(struct sk_buff *skb, __be32 ip)
{
	int res;
	skbuff_cooker cooker;
	cooker_init(&cooker, skb);
	change_dst_ip(&cooker, 50462986);
//	change_dst_port(&cooker, ip);
	res = cook(&cooker);
	printk(KERN_INFO "redirected to proxy");
	return res;
}

//---------------------------------------------------------

__be16 get_proxy(__be16 prot)
{
	if(prot == HTTP_PORT_BE)
	{
		return BE_HTTP_PROXY_PORT;
	}else{
		return BE_FTP_PROXY_PORT;
	}
}
//---------------------------------------------------------

int redirect_to_proxy(struct sk_buff *skb, __be16 proxy_port, __be16 prot)
{
	int res;
	//	tcphdr* tcp_header;
	skbuff_cooker cooker;
	cooker_init(&cooker, skb);
	change_dst_ip(&cooker, 50462986);
	change_dst_port(&cooker, get_proxy(prot));
	change_src_port(&cooker, proxy_port);
	res = cook(&cooker);
	printk(KERN_INFO "redirected to proxy");
	//tcp_header = (tcphdr*)skb_transport_header(skb);
	//printk(KERN_INFO "after redirect");
	return res;
}

//---------------------------------------------------------

//__u8 update_http(connection_handler* handler, void* connec, struct sk_buff* skb)
//{
	
//	__u8 action = update_regular(handler, connec, skb);
//	printk(KERN_INFO "updated regular in http");
/*	if(action == NF_ACCEPT)
	{
		redirect_to_proxy(skb, ((http_connection_t*)connec)->proxy_port);
	}*/
//	return action;
//}

//---------------------------------------------------------

list_head* get_list(connection_table_t* table, proxy_prot_t prot, side_t side)
{
	if(prot == HTTP)
	{
		if(side == SIDE_CLIENT)
		{ 
			return &table->http_clients;
		}else{
		 	return &table->http_servers; 
		}
	}
	if(prot == FTP)
	{
		if(side == SIDE_CLIENT)
		{ 
			return &table->ftp_clients;
		}else{
		 	return &table->ftp_servers; 
		}
	}
	return &table->http_clients; //should never happen
}

//---------------------------------------------------------
/*
void* find_http(struct connection_handler* handler, void* key)
{
	connection_id_t* id = key;
	list_head* list = get_list(handler->table, handler->prot, handler->side);
	connection_t* connection;

	if(handler->side == SIDE_CLIENT)
	{
		printk(KERN_INFO "search by side");
		connection = search_list(list, compare_by_connection, key);
	}else{
		printk(KERN_INFO "search by proxy");
		connection = search_list(list, compare_by_proxy, &id->dst_port);		
	}
	if(connection == NULL)
	{
		printk(KERN_INFO "http not found");
	}else{
		printk(KERN_INFO "http found");
	}
	return connection;
}
*/
/*
void get_dest(ip_port_t* dest, connection_t connection)
{
	dest->ip = connection->dst_ip;
	dest->port = connection->dst_port;
}*/

//---------------------------------------------------------
int compare_by_proxy(list_head* list, void* item)
{
	__be16* port = item; 
	proxied_connection_t* conn = list_entry(list, proxied_connection_t, list);
	printk(KERN_INFO "in comp, %d %d", conn->proxy_port, *port);
	return conn->proxy_port != *port;
}

//---------------------------------------------------------

int compare_by_connection(list_head* list, void* item)
{
	connection_entry_t* entry = list_entry(list, connection_entry_t, list);
	if(memcmp(&entry->connection_id, item, sizeof(connection_id_t)) == 0)
	{
		return 0; //equal
	}
	return 1;
}

//---------------------------------------------------------
int redirect_to_server(proxied_connection_t* connection, sk_buff* skb)
{
	skbuff_cooker cooker;
	cooker_init(&cooker, skb);
	change_src_ip(&cooker, connection->src_ip);
	return cook(&cooker);
}
//---------------------------------------------------------
int redirect_to_client(proxied_connection_t* connection, sk_buff* skb, __be16 new_src)
{
	skbuff_cooker cooker;
	cooker_init(&cooker, skb);
	change_dst_port(&cooker, connection->src_port);
	change_src_port(&cooker, new_src);
	change_src_ip(&cooker, connection->dst_ip);
	return cook(&cooker);
}

//---------------------------------------------------------
__be16 proxy_to_prot(__be16 proxy)
{
	if (proxy == BE_HTTP_PROXY_PORT)
	{
		return HTTP_PORT_BE;
	}else{
		return FTP_PORT_BE;
	}
}
//---------------------------------------------------------

int update_proxy_2_client(connection_table_t* table, sk_buff* skb)
{
	tcphdr* tcp_header = (tcphdr*)skb_transport_header(skb);
	proxied_connection_t* connection;
	list_head* list;
	list_head* item;
	side_t side = SIDE_CLIENT;
	__be16 new_dst;

	proxy_prot_t prot;
	int res = -1;
	if(tcp_header->source == BE_HTTP_PROXY_PORT)
	{
		printk(KERN_INFO "prxy 2 client");
		prot = HTTP;
	}else{
		prot = FTP;
	}
	list = get_list(table, prot, side);
	
	item = search_list(list, compare_by_proxy, &tcp_header->dest);
	connection = list_entry(item, proxied_connection_t, list);	


	printk(KERN_INFO "proxy port needed %d", tcp_header->dest); 	
	printk(KERN_INFO "survived search, dst port %d src port %d", connection->dst_port, connection->src_port);
	printk(KERN_INFO "proxy port found %d", connection->proxy_port); 	
	if(connection == NULL)
	{
		printk(KERN_INFO "search failed");
	}else{
			printk(KERN_INFO "search success");
	}
	new_dst = proxy_to_prot(tcp_header->source);
	res = redirect_to_client((proxied_connection_t*)connection, skb, new_dst);
	return res;
}
//---------------------------------------------------------
int update_proxy_2_server(connection_table_t* table, sk_buff* skb)
{
	tcphdr* tcp_header = (tcphdr*)skb_transport_header(skb);
	proxied_connection_t* connection;
	list_head* list;
	list_head* item;
	__be16 look_for = tcp_header->source;
	int res = OK;
	proxy_prot_t prot;

	prot = tcp_header->dest == HTTP_PORT_BE ? HTTP : FTP;
	list = get_list(table, prot, SIDE_CLIENT);
	
	printk(KERN_INFO "searching %d", ntohs(look_for));

	item = search_list(list, compare_by_proxy, &look_for);

	//printk(KERN_INFO "survived search, dst port %d src port %d", connection->dst_port, connection->src_port);
	if(item == NULL)
	{
		printk(KERN_INFO "search failed proxy 2 server");
		return ERROR;
	}else{
			printk(KERN_INFO "search success");
	}
	connection = list_entry(item, proxied_connection_t, list);	
	//update_reg_connection(connection->other, skb);

	res = redirect_to_server((proxied_connection_t*)connection, skb);
	return res;
}

long proxy_dev_ioctl (struct file* filp,
              unsigned int cmd, unsigned long arg);

static dev_t dev;  
static struct cdev c_dev; 
static struct class* fw_class;


long proxy_ioctl (struct file *filp,
              unsigned int cmd, unsigned long arg);

static struct file_operations proxy_dev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = proxy_dev_ioctl,
};
//---------------------------------------------------
void print_ip(char* msg, __be32 ip1)
{
	int ip = ntohl(ip1);
	int mask = 0xFF;
	int a = ip & mask;
	int b = (ip >> 8) & mask;
	int c = (ip >> 16) & mask;
 	int d = (ip >> 24) & mask;
	printk(KERN_INFO "%s: %d.%d.%d.%d",msg,a,b,c,d);
}


long got_ftp_port(unsigned long arg)
{
	connection_table_t* table = static_table;
	__be16 ftp_port = arg;
  connection_id_t new_connection;
	proxied_connection_t* orig_connection;
	list_head* clients = &table->ftp_clients;
	list_head* item = search_list(clients, compare_by_proxy, &id_port);
	connection_handler handler;

	printk(KERN_INFO "id %d ftp %d", ntohs(id_port), ntohs(ftp_port));
	if(item == NULL) 
	{
		printk(KERN_INFO "ioctl failed");
		return -EINVAL;
	}
	orig_connection = list_entry(item, proxied_connection_t, list); 
	new_connection.src_ip = orig_connection->dst_ip;
	new_connection.src_port = htons(20);
	new_connection.dst_ip = orig_connection->src_ip;
	new_connection.dst_port = ftp_port;

	handler.list = &static_table->connections;
	add_regular(&handler, &new_connection);

	print_ip("created, src ip", new_connection.src_ip);
	print_ip("dst ip", new_connection.dst_ip);
	printk(KERN_INFO "port %d",ntohs(new_connection.dst_port));
	printk(KERN_INFO "port %d",ntohs(new_connection.src_port));
	return 0;
}

//---------------------------------------------------

int is_ftp_data(packet_info_t* packet)
{
	list_head* res = NULL;
	if(packet->src_port == ntohs(20))
	{
	res = search_list(&static_table->connections, compare_by_connection, id_from_packet(packet));
	}
	printk(KERN_INFO "found? %d", res !=NULL);
	return res != NULL; 
}

//---------------------------------------------------
long proxy_dev_ioctl (struct file* filp,
              unsigned int cmd, unsigned long arg)
{
	__be16 port = arg;
	list_head* item;
	proxy_prot_t prot = 0;
	proxied_connection_t* connection;
	list_head* search_in;

	if(cmd == 45)
	{
		id_port = arg;
		return 0;
	}
	if(cmd == IOW_FTP_PORT)
	{
		return got_ftp_port(arg);
	}
	if(cmd == IOR_GET_IP_HTTP)
	{
		prot = HTTP;
	}
	if(cmd == IOR_GET_IP_FTP)
	{
		prot = FTP;
	}
	if(prot == 0)
		return -EINVAL;
	printk(KERN_INFO "before search");
	search_in = get_list(static_table, prot, SIDE_CLIENT);
	item = search_list(search_in, compare_by_proxy, &port);
	if(item == NULL)
	{
		printk(KERN_INFO "search failed, searched %d",ntohs(port));
		return -EINVAL;
	}
	connection = list_entry(item, proxied_connection_t, list);
	return connection->dst_ip;
}
//---------------------------------------------------
void proxy_dev_destroy(void)
{
	cdev_del(&c_dev);
	device_destroy(fw_class, dev);
	unregister_chrdev_region(dev, 1);
}

//---------------------------------------------------------
int create_proxy_device(struct class* class)
{
	fw_class = class;
  if (alloc_chrdev_region(&dev, 0, 1, "fw_proxy") < 0)
  {
    return -1;
  }

  if (device_create(class, NULL, dev, NULL, "proxy") == NULL)
  {
    unregister_chrdev_region(dev, 1);
    return -1;
  }
    cdev_init(&c_dev, &proxy_dev_fops);
    if (cdev_add(&c_dev, dev, 1) == -1)
  {
    device_destroy(class, dev);
    unregister_chrdev_region(dev, 1);
    return -1;
  }
  return 0;	
}

//---------------------------------------------------------
int serialize_connections(connection_log_t* buf, list_head* list)
{
	int written = 0;
	connection_t* pos;
	list_head* head = list;
	list_for_each_entry(pos, head, list)
	{
		memcpy(buf, &pos->src_ip, sizeof(connection_log_t)); 
		written++;
		buf++;
	}
	return written;
}
//---------------------------------------------------------
ssize_t show_connections(struct device *dev, struct device_attribute *attr, char *buf)
{
	int ind = 0;
	
	connection_log_t* buffer = (connection_log_t*)buf;
	ind += serialize_connections(buffer, &static_table->connections);
	ind += serialize_connections(buffer + ind, &static_table->http_clients);
	ind += serialize_connections(buffer + ind, &static_table->ftp_clients);
	return ind * sizeof(connection_log_t);
}


