#include "statedump.h"
#include "events.h"


/* Dump file struct event */
int dumpFileStruct(struct file fl, size_t len);


/* Dump typed event */
int dumpEvent(void* data, size_t len) {
	
	const struct Event *evt = data;

	switch (evt->etype)
	{
		case STRUCT_FILE: 
			printf("Struct file event detected\n");
			const file_Event* fevt = (file_Event*) evt;
			__builtin_dump_struct(fevt, &printf);
			break;
		case STRUCT_DENTRY: 
			printf("Struct dentry event detected\n");
			break;
		case STRUCT_QSTR: 
			printf("Struct qstr event detected\n");
			const qstr_Event* qevt = (qstr_Event*) evt;
			__builtin_dump_struct(qevt, &printf);
			break;
		default: 
			printf("Event not found\n");
			break;
	}

	return 0;
}



///* Dump file struct */
//int dumpFileStruct(struct file file_s, size_t len)
//{
//	if(len < sizeof(struct file)) {
//		printf("Len problem\n");
//		return -1;
//	}
//
//	printf("\nDUMPING file struct ------------------------------------------------------------------------------------------\n\n");
//
//	const struct file filecp = file_s;
//	__builtin_dump_struct(&filecp, &printf);
//
////	printf("testcp->argvalue: %llu\n", filecp->f_version);
//
//	return 0;
//}

/* Test print ciao */
int printTest() {
	printf("ciao\n");
	return 0;
}

