#include "list_utils.h"

typedef int (*list_comprator)(list_head* list, void* item);

list_head* search_list(list_head* list, list_comprator comp, void* item)
{
	list_head* pos;
	list_for_each(pos, list)
	{
		if(comp(pos, item) == 0)
		{
			return pos;
		}
	}
	return NULL;
}
