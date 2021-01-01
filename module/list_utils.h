#include <linux/list.h>
typedef struct list_head list_head;

typedef int (*list_comprator)(list_head* list, void* item);

list_head* search_list(list_head* list, list_comprator comp, void* item);
