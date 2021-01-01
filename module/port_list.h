#ifndef __PORT_LIST_H_
#define __PORT_LIST_H_

#include <linux/list.h>
typedef struct list_head list_head;

typedef struct port_list_t
{
	list_head free_list;
	list_head used_list;
	unsigned int counter; 
}port_list_t;

void port_list_init(port_list_t* list);

__be16 port_list_get(port_list_t* list, int* is_error);

void free_port(port_list_t* list, __be16 port);

#endif
