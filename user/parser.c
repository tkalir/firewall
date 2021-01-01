#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <time.h>
#include "parser.h"

#define WRONG_FORMAT -1

int stringify_line(FILE* input, char** args);

uint8_t read_protocol(char* str, int* is_error)
{
	*is_error = 0;
	if(strcmp(str, "TCP") == 0)
	{
		return 6;
	}
	if(strcmp(str, "UDP") == 0)
	{
		return 17;
	}
	if(strcmp(str, "ICMP") == 0)
	{
		return 1;
	}
	if(strcmp(str, "any") == 0)
	{
		return 143;
	}
	*is_error = 1;
	return 0;	
}

direction_t read_direction(char* str, int* is_error)
{
	*is_error = 0;
	if(strcmp(str, "in") == 0)
	{
		return DIRECTION_IN;
	}
	if(strcmp(str, "out") == 0)
	{
		return DIRECTION_OUT;
	}
	if(strcmp(str, "any") == 0)
	{
		return DIRECTION_ANY;
	}
	*is_error = 1;
	return DIRECTION_IN;
}

uint32_t create_mask(uint8_t size)
{
	int32_t mask = 1 << 31;
	if(size == 0)
	{
		return 0;
	}else{
		return mask >> (size - 1);
	}
}

int read_ip(char* ip, uint8_t* mask, int* is_error)
{
	union
	{
		char chars[4];
		unsigned int inty;
	}parser;
	int loc_mask;
	int segments[4];
	int res;
	if(strcmp(ip, "any") == 0)
	{
		*is_error = 0;
		*mask = 0;
		return 0;
	}
	res = sscanf(ip, "%d.%d.%d.%d/%d", &segments[3],&segments[2],
	&segments[1],&segments[0], &loc_mask);
	if(res != 5)
	{
		return -1;
	}
	for(int i = 0; i < 4; i++)
	{
		if(segments[i] > 255)
		{
			*is_error = 1;
			return 0;	
		}
		parser.chars[i] = (char)segments[i];
	}
	if(loc_mask > 32)
	{
		return -1;
	}
	*mask = loc_mask;
	*is_error = 0;
	return parser.inty;
	
}

uint16_t read_port(char* str, int* is_error)
{
	int port, res;
	if(strcmp(str, "any") == 0)
	{
		*is_error = 0;
		return 0;
	}
	if(strcmp(str, ">1023") == 0)
	{
		*is_error = 0;
		return 1023;
	}

	res = sscanf(str, "%d", &port);
	if(res != 1 || port < 0)
	{
		*is_error = 1;
	}else{
		*is_error = 0;
		return port;
	}
}

ack_t read_ack(char* str, int* is_error)
{
	if(strcmp(str, "yes") == 0)
	{
		*is_error = 0;
		return ACK_YES;
	}
	if(strcmp(str, "no") == 0)
	{
		*is_error = 0;
		return ACK_NO;
	}
	if(strcmp(str, "any") == 0)
	{
		*is_error = 0;
		return ACK_ANY;
	}
	*is_error = 1;

	return ACK_ANY;
}


uint8_t read_action(char* str, int* is_error)
{
	if(strcmp(str, "accept") == 0)
	{
		*is_error = 0;
		return  NF_ACCEPT;
	} 
	if(strcmp(str, "drop") == 0)
	{
		*is_error = 0;
		return  NF_DROP;
	}
	*is_error = 1;
	return 1;
}

char* stringify_direction(direction_t direction)
{
	switch(direction)
	{
		case DIRECTION_IN:
			return "in"; break;
		case DIRECTION_OUT:
			return "out"; break;
		case DIRECTION_ANY:
			return "any"; break;
		default:
			return "error";
	}
 }

int ip_to_str(unsigned int ip, char* str)
{
	unsigned char* ipc = (unsigned char*)&ip;
	return sprintf(str, "%u.%u.%u.%u", 
	(uint32_t)ipc[3], (uint32_t)ipc[2], (uint32_t)ipc[1], (uint32_t)ipc[0]);
}

char* prot_to_str(unsigned char protocol)
{
	if(protocol == PROT_TCP)
	{
		return "TCP";
	}
	if(protocol == PROT_UDP)
	{
		return "UDP";
	}
	if(protocol == PROT_ICMP)
	{
		return "ICMP";
	}
	if(protocol == PROT_ANY)
	{
		return "any";
	}
	return "ERROR";
}

char* get_action(unsigned char action)
{
	return (action == NF_ACCEPT) ? "accept" : "drop";
}

void format_time(unsigned long timestamp, char* timebuf, char* datebuf)
{
	time_t stamp = timestamp;
	struct tm* time = localtime(&stamp);
	sprintf(datebuf, "%02d/%02d/%d", time->tm_mday, time->tm_mon+1, 1900+time->tm_year);
  sprintf(timebuf, "%02d:%02d:%02d" , time->tm_hour, time->tm_min, time->tm_sec);
}

void stringify_subnet(unsigned int ip, int mask_size, char* buffer)
{
	int offset;
	if(ip == 0 && mask_size == 0)
	{
		sprintf(buffer, "any");
		return;
	}
	offset = ip_to_str(ip, buffer);
	sprintf(buffer + offset, "/%d", (int)mask_size);	
}

void stringify_port_rule(unsigned short port, char* buffer)
{
	if(port == 0)
	{
		sprintf(buffer, "any");
		return;
	}
	if(port == 1023)
	{
		sprintf(buffer, ">1023");
		return;
	}
	sprintf(buffer, "%d", port);
	
}

char* stringify_ack(ack_t ack)
{
	if(ack == ACK_YES)
	{
		return "yes";
	}
	if(ack == ACK_NO)
	{
		return "no";
	}
	return "any";
}

void rule_net_to_host(rule_generic_t* rule)
{
	rule->src_ip = ntohl(rule->src_ip);
	rule->dst_ip = ntohl(rule->dst_ip);
	rule->src_port = ntohs(rule->src_port);
	rule->dst_port = ntohs(rule->dst_port);	
}

int print_rule(rule_generic_t* rule)
{
	char ip_buffer[20];
	char port_buffer[8];
 	printf("%-20s", rule->rule_name);
	printf("%-*s", 4, stringify_direction(rule->direction));
	stringify_subnet(rule->src_ip, rule->src_prefix_size, ip_buffer);
	printf("%-*s", 21, ip_buffer);
	stringify_subnet(rule->dst_ip, rule->dst_prefix_size, ip_buffer);
	printf("%-*s", 21, ip_buffer);
	stringify_port_rule(rule->src_port, port_buffer);
	printf("%-*s", 6, port_buffer);
	stringify_port_rule(rule->dst_port, port_buffer);
	printf("%-*s", 6, port_buffer);
	printf("%-*s", 5, prot_to_str(rule->protocol));
	printf("%-*s", 4, stringify_ack(rule->ack));
	printf("%-*s", 5, get_action(rule->action));
	printf("\n");	
}

char* get_reason(reason_t reason)
{
	if(reason == REASON_NO_MATCHING_RULE)
	{
		return "NO_RULE";
	}
	if(reason == REASON_XMAS_PACKET)
	{
		return "XMAS_PACKET";
	}
	if(reason == REASON_TCP_ILLEGAL)
	{
		return "ILLEGAL_STATE";
	}
	if(reason == REASON_TCP_CONNECTION)
	{
		return "TCP_CONNECTION";
	}

	return NULL;
}

void print_reason(reason_t reason)
{
	if(get_reason(reason))
	{
		printf("%-*s", 8,get_reason(reason));
	}else{
		printf("%-*d", 8, reason);
	}
}


int parse_args(char* arg, rule_generic_t* rule, int index)
{
  int is_error = 0;
  switch(index)
  {
    case 0:
        strncpy(rule->rule_name, arg, 20); break;
    case 1:
        rule->direction = read_direction(arg, &is_error);
        break;
    case 2:
        rule->src_ip = read_ip(arg, &rule->src_prefix_size, &is_error);
	rule->src_ip = htonl(rule->src_ip);
        if(is_error == 0)
          rule->src_prefix_mask = create_mask(rule->src_prefix_size);
	  rule->src_prefix_mask = htonl(rule->src_prefix_mask); 	
        break;
    case 3:
        rule->dst_ip = read_ip(arg, &rule->dst_prefix_size, &is_error);
	rule->dst_ip = htonl(rule->dst_ip);
        if(is_error == 0)
          rule->dst_prefix_mask = create_mask(rule->dst_prefix_size);
          rule->dst_prefix_mask = htonl(rule->dst_prefix_mask);
        break;
    case 4:
         rule->protocol = read_protocol(arg, &is_error);
         break;
    case 5:
         rule->src_port = htons(read_port(arg, &is_error));
         break;
    case 6:
         rule->dst_port = htons(read_port(arg, &is_error));
         break;
    case 7:
         rule->ack = read_ack(arg, &is_error);
         break;
    case 8:
         rule->action = read_action(arg, &is_error);
         break;
    default:
         break;
    }
    return is_error;
}


int read_file(FILE* input, rule_generic_t* rules)
{
	char* args[9];
	int nrules = 0;
	int is_err;
	while(stringify_line(input, args) >= 0)
	{
		for(int i = 0; i < 9; i++)
		{
			is_err = parse_args(args[i], &rules[nrules], i);
			if(is_err)
			{
				printf("error at rule %d arg %d", nrules, i);
				return -1;
			}
		}
		nrules++;
	}
	return nrules;
}

int stringify_line(FILE* input, char** args)
{
	char* line = NULL;
	size_t max = 0, res;
	res = getline(&line, &max, input);
	char* arg;
	int i;
	if(res <= 0)
	{
		return res;
	}
	line[res - 1] = '\0';
	args[0] = strtok(line, " ");
	for(i = 1; i < 9; i++)
	{
		args[i] = strtok(NULL, " ");
		if(args[i] == NULL)
		{
			return WRONG_FORMAT;
		}
	}
	return 0;
}
