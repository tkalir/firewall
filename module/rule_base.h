#ifndef _RULE_BASE_H_
#define _RULE_BASE_H_

#include "fw.h"

ssize_t read_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

ssize_t read_from_usr(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

typedef struct rule_generic_t{
	char rule_name[20];
	direction_t direction;
	uint32_t	src_ip;
	uint32_t	src_prefix_mask;
	uint8_t    src_prefix_size;
	uint32_t	dst_ip;
	uint32_t	dst_prefix_mask; 	
	uint8_t    dst_prefix_size; 		
	uint16_t	src_port;  
	uint16_t	dst_port;
	uint8_t	protocol;			
	ack_t	ack; 				
	uint8_t	action;   
} rule_generic_t;

typedef struct rule_table_t
{
	int nrules;
	rule_generic_t rules[MAX_RULES];
}rule_table_t;

typedef struct rule_base_t
{
	int nRules;
	rule_t rules[MAX_RULES];	
	__u8 default_action;
}rule_base_t;

ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf);

size_t calc_table_size(int nrules);

void rule_base_init(rule_base_t* rules, __u8 default_action);

void load_rules(rule_base_t* base, rule_table_t* table);

int rule_base_match(rule_base_t* base, packet_info_t* info, __u8* action);

int is_loopback(packet_info_t* info);

#endif

