#include "statedump.h"
#include "events.h"


/* Dump file struct event */
int dumpFileStruct(struct file fl, size_t len);


/* Dump typed event */
int dumpEvent(void* data, size_t len) {
	
	const struct Event *evt = data;

	printf("\n---> %s: ", evt->label);

	switch (evt->etype)
	{
		case FUNCTION_CALL: {
			const func_call_Event* tevt = (func_call_Event*) evt;
			printf("-> %s", tevt->name);
			printf("( %s", tevt->args);
			printf(" )\n");
			break;
		}
		case STRUCT_FILE: {
			const file_struct_Event* tevt = (file_struct_Event*) evt;
			printf(" ->Message: %s\n", tevt->msg);
			__builtin_dump_struct(tevt, &printf);
			break;
		}
		case STRUCT_DENTRY: {
			const dentry_struct_Event* tevt = (dentry_struct_Event*) evt;
			printf(" -> Message: %s\n", tevt->msg);
			__builtin_dump_struct(tevt, &printf);
			break;
		}
		case STRUCT_QSTR: {
			const qstr_struct_Event* tevt = (qstr_struct_Event*) evt;
			printf(" -> Message: %s\n", tevt->msg);
			__builtin_dump_struct(tevt, &printf);
			break;
		}
		default: {
			printf(" Error: Event not found !\n");
			break;
		}
	}

	return 0;
}



/* Test print ciao */
int printTest() {
	printf("ciao\n");
	return 0;
}

