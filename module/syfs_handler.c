#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "sysfs_handler.h"
	
MODULE_LICENSE("GPL");

#define CLASS_NAME "fw"
#define ERROR 1
#define OK 0

typedef struct sysfs_dev_t
{
	dev_t devid;
	int major_number;
	struct device* sysfs_device;
	struct device_attribute atr;
	char* name;
}sysfs_dev_t;

static struct class* sysfs_class = NULL;
static sysfs_dev_t rules;
static sysfs_dev_t logs;
static sysfs_dev_t connections;

int set_sysfs_dev(sysfs_dev_t* dev);
	
static struct file_operations fops = {
	.owner = THIS_MODULE
};

void destroy_dev(sysfs_dev_t* dev);
//---------------------------------------------------------
int set_dev(sysfs_dev_t* dev, char* device_name, char* attr_name, show_func show, store_func store, umode_t mode)
{
	dev->name = device_name;
	dev->atr.show = show;
	dev->atr.store = store;
	dev->atr.attr.name = attr_name;
	dev->atr.attr.mode = mode;
	return set_sysfs_dev(dev);
}
//---------------------------------------------------------
int create_sysfs_device(sysfs_dev_t* mydev)
{
	mydev->devid = MKDEV(mydev->major_number, 0);
	mydev->sysfs_device = device_create(sysfs_class, NULL, mydev->devid, NULL, mydev->name);
	if (IS_ERR(mydev->sysfs_device))
	{
		return ERROR;
	}
	return OK;
}	

//---------------------------------------------------------
	
int create_class(void)
{
	sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(sysfs_class))
	{
		return ERROR;
	}
	return OK;
}

//---------------------------------------------------------


int create_char_device(sysfs_dev_t* dev)
{
	dev->major_number = register_chrdev(0, dev->name, &fops);
	return (dev->major_number < 0) ? ERROR : OK;
}

int create_attribute(sysfs_dev_t* dev)
{
	int res;
	res = device_create_file(dev->sysfs_device, 
	(const struct device_attribute *)&dev->atr.attr);
	return (res) ? ERROR : OK; 
}

//---------------------------------------------------------
int sysfs_handler_create(void)
{
	if(create_class() == ERROR)
	{
		return ERROR;	
	}
	return OK;	
}

//---------------------------------------------------------
int init_sysfs_logs(char* device_name, char* attr_name, show_func show, store_func store, umode_t mode)
{
	return set_dev(&logs, device_name, attr_name, show, store, mode);	
}
//---------------------------------------------------------
int init_sysfs_rules(char* device_name, char* attr_name, show_func show, store_func store, umode_t mode)
{
	return set_dev(&rules, device_name, attr_name, show, store, mode);	
}
//---------------------------------------------------------
int init_sysfs_connections(char* device_name, char* attr_name, show_func show, store_func store, umode_t mode)
{
	return set_dev(&connections, device_name, attr_name, show, store, mode);	
}
//---------------------------------------------------------
void sysfs_handler_destroy_connections(void)
{
	destroy_dev(&connections);
}
//---------------------------------------------------------
int set_sysfs_dev(sysfs_dev_t* dev)
{
	if(create_char_device(dev) == ERROR)
	{
		return ERROR;
	}

	if(create_sysfs_device(dev) == ERROR)
	{
		class_destroy(sysfs_class);
		unregister_chrdev(dev->major_number, dev->name);
		return ERROR;
	}
	if(create_attribute(dev) == ERROR)
	{
		device_destroy(sysfs_class, dev->devid);
		class_destroy(sysfs_class);
		unregister_chrdev(dev->major_number, dev->name);
		return ERROR;
	}
	return OK;
}
//---------------------------------------------------------
void destroy_dev(sysfs_dev_t* dev)
{
	device_remove_file(dev->sysfs_device, 
		(const struct device_attribute*)&dev->atr.attr);
	device_destroy(sysfs_class, dev->devid);
	unregister_chrdev(dev->major_number, dev->name);
				
}
//---------------------------------------------------------
void sysfs_handler_destroy_class(void)
{
	class_destroy(sysfs_class);	
}

//---------------------------------------------------------
void sysfs_handler_destroy_rules(void)
{
	destroy_dev(&rules);
}

void sysfs_handler_destroy_logs()
{
	destroy_dev(&logs);
}
//---------------------------------------------------------

void destroy_sysfs(void)
{
	destroy_dev(&rules);
	destroy_dev(&logs);
	destroy_dev(&connections);
	class_destroy(sysfs_class);	
}

//---------------------------------------------------------
struct class* get_class()
{
	return sysfs_class;
}
