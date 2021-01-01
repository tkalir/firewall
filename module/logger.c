#include <linux/string.h>
#include "logger.h"
#include "log_dev.h"


MODULE_LICENSE("GPL");


static void* allocate(void)
{
	return kmalloc(sizeof(log_node_t), GFP_KERNEL);
}

struct list_head* get_klist(logger_t* logger);

log_node_t* get_tail(logger_t* logger)
{
	return list_last_entry(&logger->logs.klist, log_node_t, klist);
}

int logger_init(logger_t* logger)
{
	INIT_LIST_HEAD(&logger->logs.klist);
	return log_dev_init(logger);
}

void fill_log(log_row_t* log, packet_info_t* packet, u8 action, reason_t reason)
{
	log->timestamp = packet->timestamp;
	log->protocol = packet->protocol;
	log->action = action;
	log->src_ip = packet->src_ip;
	log->dst_ip = packet->dst_ip;
	log->src_port = packet->src_port;
	log->dst_port = packet->dst_port;	
	log->reason = reason;
	log->count = 1;
}

int match_logs(log_entry_t* log1, log_entry_t* log2)
{
	return !memcmp((char*)&log1->log_key, (char*)&log2->log_key, sizeof(log_key_t));
}

log_node_t* search_for_log(logger_t* logger, log_entry_t* log)
{
	struct log_node_t* itr;
	list_for_each_entry(itr, get_klist(logger), klist)
	{
		if(match_logs((log_entry_t*)&itr->log, log))
		{
			return itr;
		}
	}
	return NULL;
	
}

void update_log(log_entry_t* log, unsigned long timestamp)
{
	log->timestamp = timestamp;
	log->count++;
}

void init_log(log_entry_t* new, log_entry_t* info)
{
	new->timestamp = info->timestamp;
	new->log_key = info->log_key;
	new->count = 1;
}

struct list_head* get_klist(logger_t* logger)
{
	return &logger->logs.klist;	
}

void reset_logs(logger_t* logger)
{
	struct list_head* itr;
	struct list_head* reserve;
	struct list_head* lhead = get_klist(logger);
	log_node_t* entry;
	list_for_each_safe(itr, reserve, lhead)
	{
		entry = list_entry(itr, log_node_t, klist);
		list_del(itr);	
		kfree(entry);
	}
}


int add_log(logger_t* logger, log_entry_t* log)
{
	log_node_t* res;
	res = search_for_log(logger, log);
	if(res != NULL)
	{
		update_log((log_entry_t*)&res->log, log->timestamp);
		
		list_move_tail(&res->klist, get_klist(logger));
	}else{
		res = allocate();
		if(res == NULL)
		{
			return 1;
		}
		init_log((log_entry_t*)&res->log, log);
		list_add_tail(&res->klist, &logger->logs.klist);
	}
	return 0;
}

int serialize_logs(logger_t* logger, void** itr, int num, char* buf)
{
	int i;
	int wrote = 0;
	log_node_t* entry;
	struct list_head* pos = (*itr == NULL) ? get_klist(logger) : *itr;
	if(list_empty(get_klist(logger)))
	{
		*itr = NULL;
		return 0;
	}
	
	for(i = 0; i < num; i++)
	{
		pos = pos->next;
		entry = list_entry(pos, log_node_t, klist);
		memcpy(buf, (const void*)&entry->log, sizeof(log_row_t));
		buf += sizeof(log_row_t);
		wrote++;
		if(list_is_last(pos, get_klist(logger)))
		{	
			*itr = NULL;
			return wrote;
		}
	}
	*itr = pos;
	return wrote;
}

int log_packet(logger_t* logger, packet_info_t* packet, u8 action, reason_t reason)
{
	log_entry_t log;
	fill_log((log_row_t*)&log, packet, action, reason);
	return add_log(logger, &log);
}

void destroy_logger(void)
{
	log_dev_destroy();
}
