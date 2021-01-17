#include "statedump.h"
#include "vmlinux.h"

/* Dump file struct */
int dumpFileStruct(void* data, size_t len)
{
	if(len < sizeof(struct file)) {
		return -1;
	}

	const struct file *filecp = data;
//	printf("filecp: %llu", filecp->f_version);
	return 0;
}

/* Test print ciao */
int printTest() {
	printf("ciao");
	return 0;
}

