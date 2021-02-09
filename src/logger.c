//   Copyright 2020 (C) Luca Montechiesi <lucamontechiesi@gmail.com>
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.


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


