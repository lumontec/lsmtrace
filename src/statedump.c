#include "statedump.h"
#include "vmlinux.h"

/* Dump file struct */
int dumpFileStruct(void* data, size_t len)
{
	if(len < sizeof(struct test)) {
		printf("got a len problem");
		return -1;
	}

	const struct test *testcp = data;

	printf("testcp->argvalue: %d\n", testcp->argvalue);
	printf("testcp->setvalue: %d\n", testcp->setvalue);

	return 0;
}

/* Test print ciao */
int printTest() {
	printf("ciao\n");
	return 0;
}

