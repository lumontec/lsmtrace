#include "statedump.h"
#include "events.h"
#include "logger.h"
#include <stdio.h>


/* Dump file struct event */
int dumpFileStruct(struct file fl, size_t len);


int printFunCallEvt(const struct Event *evt) {
	const func_call_Event* tevt = (func_call_Event*) evt;
	log_info("-> %s: ", evt->label);
	log_info("-> %s", tevt->name);
	log_info("( %s", tevt->args);
	log_info(" )\n");
	return 0;
}

int printUintMemberEvt(const struct Event *evt) {
	const uint_member_Event* tevt = (uint_member_Event*) evt;
	log_info("     %s = ", tevt->msg);
	log_info("%#010x\n", tevt->member);
	return 0;
}

int printLlintMemberEvt(const struct Event *evt) {
	const llint_member_Event* tevt = (llint_member_Event*) evt;
	log_info("     %s = ", tevt->msg);
	log_info("%#010x\n", tevt->member);
	return 0;
}

int printStrMemberEvt(const struct Event *evt) {
	const str_member_Event* tevt = (str_member_Event*) evt;
	log_info("     %s = ", tevt->msg);
	log_info("%s\n", tevt->member);
	return 0;
}



/* Dump typed event */
int dumpEvent(void* data, size_t len) {
	
	const struct Event *evt = data;


	switch (evt->etype)
	{
		case FUNCTION_CALL: {
			return printFunCallEvt(evt);
		}
		case MEMBER_UINT: {
			return printUintMemberEvt(evt);
		}
		case MEMBER_LLINT: {
			return printLlintMemberEvt(evt);
		}
		case MEMBER_STR: {
			return printStrMemberEvt(evt);
		}
		case STRUCT_FILE: {
			const file_struct_Event* tevt = (file_struct_Event*) evt;
			log_info(" ->Message: %s\n", tevt->msg);
			__builtin_dump_struct(tevt, &log_info);
			break;
		}
		case STRUCT_DENTRY: {
			const dentry_struct_Event* tevt = (dentry_struct_Event*) evt;
			log_info(" -> Message: %s\n", tevt->msg);
			__builtin_dump_struct(tevt, &log_info);
			break;
		}
		case STRUCT_QSTR: {
			const qstr_struct_Event* tevt = (qstr_struct_Event*) evt;
			log_info(" -> Message: %s\n", tevt->msg);
			__builtin_dump_struct(tevt, &log_info);
			break;
		}
		default: {
			log_err("Event not found !\n");
			break;
		}
	}

	return 0;
}




/* Test print test */
int printTest() {
	log_info("test\n");
	return 0;
}

