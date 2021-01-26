#ifndef __LOG_H
#define __LOG_H

#include <stdbool.h>
#include <stdio.h>

int log_info(const char *fmt, ...);
int log_verb(const char *fmt, ...);
int log_err(const char *fmt, ...);

void setLoggerVerbose(bool);

#endif /* __LOG_H */
