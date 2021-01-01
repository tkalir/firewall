#ifndef _SYSFS_HANDLER_H_
#define _SYSFS_HANDLER_H_

typedef ssize_t (*show_func)(struct device *dev, struct device_attribute *attr, char *buf);

typedef ssize_t (*store_func)(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

void destroy_sysfs(void);

int sysfs_handler_create(void);

int init_sysfs_logs(char* device_name, char* attr_name, show_func show, store_func store, umode_t mode);

int init_sysfs_rules(char* device_name, char* attr_name, show_func show, store_func store, umode_t mode);

int init_sysfs_connections(char* device_name, char* attr_name, show_func show, store_func store, umode_t mode);

void sysfs_handler_destroy_class(void);

void sysfs_handler_destroy_rules(void);

void sysfs_handler_destroy_logs(void);

void sysfs_handler_destroy_connections(void);

struct class* get_class(void);

#endif
