#ifndef __LOG_H
#define __LOG_H

#include <stdbool.h>
#include <stdio.h>

int log_info(FILE *f, const char *fmt, ...);
int log_verb(FILE *f, const char *fmt, ...);

void setLoggerVerbose(bool);

#endif /* __LOG_H */
