obj-m += firewall.o
firewall-objs += hw4secws.o
firewall-objs += logger.o 
firewall-objs += rule_base.o 
firewall-objs += syfs_handler.o 
firewall-objs += log_device.o
firewall-objs += connection_table.o
firewall-objs += port_list.o
firewall-objs += skbuff_cooker.o
firewall-objs += tcp_utils.o
firewall-objs += list_utils.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
