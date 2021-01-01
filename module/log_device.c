#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include "logger.h"
#include "log_dev.h"

#define LOG_DEV_BUFFER_SIZE 32

static logger_t* logger;
static void* itr = NULL;

static log_row_t buffer[LOG_DEV_BUFFER_SIZE];

static ssize_t log_read(struct file *file,
			  char* usr_buf, size_t count, loff_t * ppos);
int log_open(struct inode* node, struct file* file);
int log_close(struct inode* node, struct file* file);
long log_ioctl (struct file *filp,
              unsigned int cmd, unsigned long arg);

static struct file_operations log_dev_fops = {
	.owner = THIS_MODULE,
	.read = log_read,
	.unlocked_ioctl = log_ioctl,
	.open = log_open,
	.release = log_close,
};

static int indicate_end = 0;
static dev_t first;  
static struct cdev c_dev; 
static struct class* logger_class;

//---------------------------------------------------
long log_ioctl (struct file* filp,
              unsigned int cmd, unsigned long arg)
{
	if(cmd == IO_IS_EOF)
	{
		printk(KERN_INFO "%d ioctld", indicate_end);
		return indicate_end;
	}
	return -EINVAL;
}

//---------------------------------------------------
int log_device_init(void) 
{
  if (alloc_chrdev_region(&first, 0, 1, "fw") < 0)
  {
    return -1;
  }
    if ((logger_class = class_create(THIS_MODULE, "fw_log")) == NULL)
  {
    unregister_chrdev_region(first, 1);
    return -1;
  }
    if (device_create(logger_class, NULL, first, NULL, "fw_log") == NULL)
  {
    class_destroy(logger_class);
    unregister_chrdev_region(first, 1);
    return -1;
  }
    cdev_init(&c_dev, &log_dev_fops);
    if (cdev_add(&c_dev, first, 1) == -1)
  {
    device_destroy(logger_class, first);
    class_destroy(logger_class);
    unregister_chrdev_region(first, 1);
    return -1;
  }
  return 0;
}

//---------------------------------------------------

size_t get_min(size_t a, size_t b)
{
	return a < b ? a : b;
}
//---------------------------------------------------
size_t items_size(int nitems)
{
	return nitems * sizeof(log_row_t); 
}
//---------------------------------------------------
static ssize_t log_read(struct file *file,
			  char* usr_buf, size_t count, loff_t* ppos)
{

	size_t user_buf_size = count / sizeof(log_row_t);
	int written = 0;
	int ended = 0;
	int returned;
	ssize_t write_size, req_size;

	if(indicate_end)
	{
		//indicate_end = 0;
		itr = NULL;
		return 0;
	}

	if(user_buf_size == 0)
	{
		return -EINVAL;
	}

	while((written < user_buf_size) && !ended)
	{
		req_size = get_min(user_buf_size - written, LOG_DEV_BUFFER_SIZE);
		returned = serialize_logs(logger, &itr, req_size, (char*)buffer); 
		if(itr == NULL)
		{
			ended = 1;
			indicate_end = 1;
		}
		if(returned > 0)
		{
			if (copy_to_user(usr_buf, buffer, items_size(returned)))
			{
					return -EINVAL;
			}
		}
		written += returned;
	}
	write_size = items_size(written);
	*ppos = *ppos + write_size;
	return write_size;
}
//---------------------------------------------------
int log_open(struct inode* node, struct file* file)
{
	indicate_end = 0;
	return 0;
}

//---------------------------------------------------
int log_close(struct inode* node, struct file* file)
{
	return 0;
}
//---------------------------------------------------
int log_dev_init(logger_t* loggerptr)
{
	logger = loggerptr;
	return log_device_init();
}
//---------------------------------------------------
void log_dev_destroy(void)
{
	cdev_del(&c_dev);
	device_destroy(logger_class, first);
	class_destroy(logger_class);
	unregister_chrdev_region(first, 1);
}
