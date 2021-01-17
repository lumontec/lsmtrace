#include <stdio.h>


///int my_printf(const char *fmt, ...);

//int dump(void *myStruct, long size);

char dst[100] = "";


static int sdump (const char *fmt, void* arg1, void* arg2, void *arg3) {

	const char *fmtcp = fmt;
	long size = 0;
	char tmp[1] = "1";

	for (int i=0; i<1000; i++) {

		__builtin_memcpy(tmp, fmtcp, 1);

		if (tmp[0] == 0) {
			size++;
			break;
		}

		size++;
		fmtcp++;
	}

	__builtin_memcpy(dst, fmt, size);

	if (__builtin_memcmp(dst, "%d", 2) == 0) {
		printf("%d\n", (int)arg1);
		return 0;
	}

	printf("%s", dst);

	return 0;

}

static int (*sdump_helper)(const char *fmt, ...) = (void *) sdump;
