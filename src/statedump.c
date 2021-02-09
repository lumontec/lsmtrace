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

#include "statedump.h"
#include "events.h"
#include "logger.h"
#include <stdio.h>
#include "syscall_helpers.h"


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

int printSysCallEnterEvt(const struct Event *evt) {
	const sys_enter_Event* tevt = (sys_enter_Event*) evt;
	log_info("-> %s: ", evt->label);
	char buf[MAX_LABEL_SIZE];
	syscall_name(tevt->id, buf, sizeof(buf));
	log_info(" %s\n", buf);
	return 0;
}

int printSysCallExitEvt(const struct Event *evt) {
	const sys_exit_Event* tevt = (sys_exit_Event*) evt;
	log_info("-> %s:  ", evt->label);
	char buf[MAX_LABEL_SIZE];
	syscall_name(tevt->id, buf, sizeof(buf));
	log_info(" %s\n", buf);
	log_info("     ret: %ld\n", tevt->ret);
	return 0;
}

int printSuintMemberEvt(const struct Event *evt) {
	const suint_member_Event* tevt = (suint_member_Event*) evt;
	log_info("     %s = ", tevt->msg);
	log_info("%hu\n", tevt->member);
	return 0;
}

int printUintMemberEvt(const struct Event *evt) {
	const uint_member_Event* tevt = (uint_member_Event*) evt;
	log_info("     %s = ", tevt->msg);
	log_info("%hu\n", tevt->member);
	return 0;
}

int printLuintMemberEvt(const struct Event *evt) {
	const luint_member_Event* tevt = (luint_member_Event*) evt;
	log_info("     %s = ", tevt->msg);
	log_info("%ld\n", tevt->member);
	return 0;
}


int printLlintMemberEvt(const struct Event *evt) {
	const llint_member_Event* tevt = (llint_member_Event*) evt;
	log_info("     %s = ", tevt->msg);
	log_info("%lld\n", tevt->member);
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
		case SYS_CALL_ENTER: {
			return printSysCallEnterEvt(evt);
		}
		case SYS_CALL_EXIT: {
			return printSysCallExitEvt(evt);
		}
		case MEMBER_SUINT: {
			return printSuintMemberEvt(evt);
		}
		case MEMBER_UINT: {
			return printUintMemberEvt(evt);
		}
		case MEMBER_LUINT: {
			return printLuintMemberEvt(evt);
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

