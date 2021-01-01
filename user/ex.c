#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <linux/netfilter.h>

#include "parser.h"
#include "log_dev.h"

#define USAGE_MSG "actions are show_log, load_rules <path>, clear_log"

#define LOGS_BUF_SIZE 32

#define RULE_PATH "/sys/class/fw/rules/rules"
#define RESET_LOGS_PATH "/sys/class/fw/log/reset"
#define CONNS_PATH "/sys/class/fw/conns/conns"
#define LOGS_PATH "/dev/fw_log"

void write_rules(struct rule_write* rules, FILE* rules_file);

int load_rules(const char* path)
{
	struct rule_write rules;
	FILE* fp = fopen(path, "r");
	if(!fp)
	{
		perror("error opening input file");
		exit(EXIT_FAILURE);
	}
	FILE* rules_file = fopen(RULE_PATH, "r+");
	if(!rules_file)
	{
		perror("error opening rules file");
		exit(EXIT_FAILURE);
	};
	rules.nrules = read_file(fp, rules.rules);
	if(rules.nrules == -1)
	{
		perror("error reading rules file");
		exit(EXIT_FAILURE);
	}
	write_rules(&rules, rules_file);
}


void write_rules(struct rule_write* rules, FILE* rules_file)
{
	size_t res = fwrite(rules, 1, sizeof(int) + rules->nrules * sizeof(rule_generic_t), rules_file);
	if(res == 0 || ferror(rules_file))
	{
		perror("writing rules");
		exit(EXIT_FAILURE);
	}
}
void log_to_host(log_t* log)
{
	log->src_ip = ntohl(log->src_ip);
	log->dst_ip = ntohl(log->dst_ip);
	log->src_port = ntohs(log->src_port);
	log->dst_port = ntohs(log->dst_port);
}

void print_log(log_t* log)
{
	char ip_buffer[20];
	char date_buf[11];
	char time_buf[11];	
	char* protocol;
	
	format_time(log->timestamp, time_buf, date_buf);
	printf("%s  %-*s", time_buf, 11, date_buf);
	ip_to_str(log->src_ip, ip_buffer);
	printf("%-*s", 10,  ip_buffer);
	ip_to_str(log->dst_ip, ip_buffer);
	printf("%-*s", 10, ip_buffer);
	printf("%-*s", 5, prot_to_str(log->protocol));
	printf("%-*u", 6, (unsigned int)log->src_port);
	printf("%-*u", 6, (unsigned int)log->dst_port);
	printf("%-*s", 9, get_action(log->action));
	print_reason(log->reason);
	printf("%-*u", 4, log->count);
	printf("\n");
}

void print_log_headers()
{
	printf("%-*s",21, "timestamp");
	printf("%-*s", 10, "src_ip");
	printf("%-*s",10,"dst_ip");
	printf("%-*s",5, "prot");
	printf("%-*s",6,"src");
	printf("%-*s",6,"dst");
	printf("%-*s",9,"action");
	printf("%-*s",8,"reason");
	printf("%-*s",4,"count");
	printf("\n");
}

void print_logs(log_t* logs, int nLogs)
{
	for(int i = 0; i < nLogs; i++)
	{
		log_to_host(&logs[i]);
		print_log(&logs[i]);
	}
}

int read_logs()
{
	size_t nread = 0;
	int fd;
	log_t logs[LOGS_BUF_SIZE];
	FILE* log_file = fopen(LOGS_PATH, "r");
	if(log_file < 0)
	{
		perror("open log files");
		fclose(log_file);
		exit(EXIT_FAILURE);
	}
	fd = fileno(log_file);

	nread = fread(&logs, sizeof(log_t), LOGS_BUF_SIZE, log_file);
	if(nread == 0)
	{
		printf("no logs found\n");
		fclose(log_file);
		return 0;
	}
	if(nread > 0)
	{
		print_log_headers();
		while((nread > 0) || (ioctl(fd, IO_IS_EOF) == 0))
		{
			print_logs(logs, nread);
			nread = fread(&logs, sizeof(log_t), LOGS_BUF_SIZE, log_file);
		}
	}
	fclose(log_file);
	return 0;
}

int reset_logs()
{
	FILE* fp = fopen(RESET_LOGS_PATH, "w");
	if(!fp)
	{
		perror("reset log file");
		exit(EXIT_FAILURE);
	}
	if(fprintf(fp, "%c", '0') < 0)
	{
		perror("reseting log");
		exit(EXIT_FAILURE);
	}	
}

char* stringify_state(state_t state)
{
	switch(state)
	{
		case STATE_LISTENING:
			return "STATE_LISTENING";
		case STATE_SYN_SENT:
			return "STATE_SYN_SENT";
		case STATE_SYNACK_SENT:
			return "STATE_SYNACK_SENT";
		case STATE_SERVER_ESTABLISHED:
			return "STATE_SERVER_ESTABLISHED";
		case STATE_CLIENT_ESTABLISHED:
			return "STATE_SERVER_ESTABLISHED";
		case STATE_FIN_SENT:
			return "STATE_FIN_SENT";
		case STATE_CLOSED:
			return "STATE_CLOSED";
		default:
			return "ERROR";
	}
}

void show_connections()
{
	char ip_buf[20];
	int i;
	FILE* fp = fopen(CONNS_PATH, "r");
	connection_log_t conns[1024];
	ssize_t nread = fread(conns, sizeof(connection_log_t), 1024, fp);
	if(nread == 0)
	{
		printf("no connections found\n");
		fclose(fp);
		return;
	}

	printf("%-*s", 10,  "src_ip");
	printf("%-*s", 10, "dst_ip");
	printf("%-*s", 10,  "src_port");
	printf("%-*s", 10,  "dst_port");
	printf("%-*s", 10,  "state");
	printf("\n");
	for(i = 0; i < nread; i++)
	{
		ip_to_str(ntohl(conns[i].src_ip), ip_buf);
		printf("%-*s", 10,  ip_buf);
		ip_to_str(ntohl(conns[i].dst_ip), ip_buf);
		printf("%-*s", 10,  ip_buf);
		printf("%-*u", 10, (unsigned int)ntohs(conns[i].src_port));
		printf("%-*u", 10, (unsigned int)ntohs(conns[i].dst_port));
		printf("%-*s", 10, stringify_state(conns[i].state));
		printf("\n");
	}
}

void show_rules()
{
	int i;
	struct rule_write rules;
	FILE* fp = fopen(RULE_PATH, "r");
	if(!fp)
	{
		perror("error opening rule file");
		exit(EXIT_FAILURE);
	}
	if(fread(&rules, sizeof(struct rule_write), 1, fp) < 0)
	{
		perror("showing rules");
		exit(EXIT_FAILURE);
	}
	
	for(i = 0; i < rules.nrules; i++)
	{
		rule_net_to_host(&rules.rules[i]);
		print_rule(&rules.rules[i]);
	}
		
}

void print_usage()
{
	printf("%s\n", USAGE_MSG);
}

int main(int argc, const char** argv)
{
	FILE* fp;
	if(strcmp(argv[1], "show_log") == 0)
	{
		read_logs();
		return 0;
	}
	if(strcmp(argv[1], "load_rules") == 0)
	{
		load_rules(argv[2]);
		return 0;
	}
	if(strcmp(argv[1], "clear_log") == 0)
	{
		reset_logs();
		return 0;
	}
	if(strcmp(argv[1], "show_rules") == 0)
	{
		show_rules();
		return 0;
	}
	if(strcmp(argv[1], "show_conns") == 0)
	{
		show_connections();
		return 0;
	}
	print_usage();
	return 1;
}
