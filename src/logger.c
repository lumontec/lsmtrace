#include "logger.h"
#include <stdarg.h>

bool verbose = false;

void setLoggerVerbose(bool setting) {
    verbose = setting;
}

/* logging */
int log_info(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	int ret = vfprintf(stdout, fmt, args);
	va_end(args);

	return ret;
}

int log_err(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	int ret = vfprintf(stderr, fmt, args);
	va_end(args);

	return ret;
}

int log_verb(const char* fmt, ...) {
	if (!verbose)
		return 0;
	va_list args;
	va_start(args, fmt);
	int ret = vfprintf(stdout, fmt, args);
	va_end(args);

	return ret;
}


