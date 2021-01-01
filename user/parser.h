#ifndef _PARSER_H_
#define _PARSER_H_

#include <stdint.h>

typedef enum {
	STATE_LISTENING			= 0,
	STATE_SYN_SENT			= 1,
	STATE_SYNACK_SENT		= 2,
	STATE_SERVER_ESTABLISHED	= 3,
	STATE_CLIENT_ESTABLISHED	= 4,
	STATE_FIN_SENT			= 5,
	STATE_CLOSED			= 6,
}state_t;

typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;

typedef enum {
	REASON_FW_INACTIVE		= -1,
	REASON_NO_MATCHING_RULE		= -2,
	REASON_XMAS_PACKET		= -4,
	REASON_ILLEGAL_VALUE		= -6,
	REASON_TCP_ILLEGAL		= -7,
	REASON_TCP_CONNECTION		= -8,
} reason_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

typedef struct connection_log_t
{
	unsigned int	src_ip;
	unsigned int	dst_ip;
	unsigned short	src_port;
	unsigned short	dst_port;
	state_t state;
}connection_log_t;

typedef struct rule_generic_t{
	char rule_name[20];
	direction_t direction;
	uint32_t	src_ip;
	uint32_t	src_prefix_mask;
	uint8_t    src_prefix_size;
	uint32_t	dst_ip;
	uint32_t	dst_prefix_mask; 	// as above
	uint8_t    dst_prefix_size; 	// as above	
	uint16_t	src_port;  
	uint16_t	dst_port;
	uint8_t	protocol;			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	uint8_t	action;   // valid values: NF_ACCEPT, NF_DROP
} rule_generic_t;

typedef struct {
	unsigned long  	timestamp;     	
	unsigned char  	protocol;     	
	unsigned char  	action;     
	unsigned int   	src_ip;		  	
	unsigned int	dst_ip;		  	
	unsigned short 	src_port;
	unsigned short 	dst_port;
	reason_t     	reason;       	
	unsigned int   	count;        	
} log_t;


struct rule_write
{
	int nrules;
	rule_generic_t rules[50];
};

void print_reason(reason_t reason);

int read_file(FILE* input, rule_generic_t* rules);

int ip_to_str(unsigned int ip, char* str);

char* prot_to_str(unsigned char protocol);

char* get_action(unsigned char action);

void format_time(unsigned long timestamp, char* timebuf, char* datebuf);

void rule_net_to_host(rule_generic_t* rule);

int print_rule(rule_generic_t* rule);

#endif
