#ifndef _LOG_DEV_H_
#define _LOG_DEV_H_

#define FW_IOC_MAGIC  'f'
#define IO_IS_EOF _IO(FW_IOC_MAGIC, 1)

typedef struct logger_t logger_t;

int log_dev_init(logger_t* logger);

void log_dev_destroy(void);

#endif
