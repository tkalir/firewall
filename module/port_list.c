#include <linux/slab.h>
#include "port_list.h"

typedef struct assigned_port_t
{
	list_head list;
	__be16 port;
}assigned_port_t;


void port_list_init(port_list_t* list)
{
	INIT_LIST_HEAD(&list->free_list);
	INIT_LIST_HEAD(&list->used_list);
	list->counter = 0;
}

//--------------------------------------

static assigned_port_t* create_port(port_list_t* list)
{
	assigned_port_t* res;
	res = kmalloc(sizeof(assigned_port_t), GFP_KERNEL);
	if(res == NULL)
	{
		return NULL;
	}
	list->counter = list->counter + 1;
	if(list->counter == 800 || list->counter == 210)
	{
		list->counter = list->counter + 1;
	}
	res->port = htons(list->counter);
	return res;
}

//--------------------------------------

__be16 port_list_get(port_list_t* list, int* is_error)
{
	assigned_port_t* res;
	if(list_empty(&list->free_list))
	{
		res = create_port(list);
		if(res == NULL)
		{
			*is_error = 1;
		}else{
			*is_error = 0;
			return res->port;
		}
		
	}
	res = list_first_entry((list_head*)list, assigned_port_t, list);
	list_del((list_head*)res);
	list_add((list_head*)res, &list->used_list);
	return res->port;
} 

//--------------------------------------
static assigned_port_t* find_port(list_head* list, __u16 port)
{
	assigned_port_t* pos;
	list_for_each_entry(pos, list, list)
	{
		if(pos->port == port)
		{
			return pos;
		}
	}
	return NULL; //error, not supposed to happen
}
//--------------------------------------
void free_assigned_port(port_list_t* list, __u16 port)
{
	assigned_port_t* found = find_port(&list->used_list, port);
	if(found == NULL)
	{
		return; //should never happen
	}
	list_add((list_head*)found, &list->free_list);
}
