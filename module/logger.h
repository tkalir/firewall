#ifndef _LOGGER_H_
#define _LOGGER_H_

#include "fw.h"

struct log_node_t
{
	struct list_head klist;
	log_row_t log;
};

typedef struct log_node_t log_node_t;

struct logger_t
{
	log_node_t logs;
};

typedef struct logger_t logger_t;

struct log_key_t
{
	unsigned char  	protocol;
	unsigned char  	action;
	__be32   	src_ip;
	__be32		dst_ip;
	__be16 		src_port;
	__be16 		dst_port;
	reason_t     	reason;
};

typedef struct log_key_t log_key_t;

typedef struct log_entry_t
{
	unsigned long  	timestamp;
	log_key_t	log_key;
	unsigned int   	count;
}log_entry_t;

int logger_init(logger_t* logger);

int log(logger_t* logger, packet_info_t* packet);

int log_packet(logger_t* logger, packet_info_t* packet, u8 action, reason_t reason);

int serialize_logs(logger_t* logger, void** itr, int num, char* buf);

void destroy_logger(void);

void reset_logs(logger_t* logger);

#endif

