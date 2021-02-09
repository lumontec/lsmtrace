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



#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "events.h"

#define FILTER_CATHEGORY_INT(CATH)		\
if (CATH != cathegory && cathegory != ALL_CATH)	\
	return 0;				

#define FILTER_CATHEGORY_VOID(CATH) 		\
if (CATH != cathegory && cathegory != ALL_CATH)	\
	return ;				


#define FILTER_OWN_PID_INT() 			\
int pid = bpf_get_current_pid_tgid() >> 32;	\
if (pid != my_pid)				\
	return 0;				

#define FILTER_OWN_PID_VOID() 			\
int pid = bpf_get_current_pid_tgid() >> 32;	\
if (pid != my_pid)				\
	return;					


/* Maps declaration */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");


/* Globals */

long ringbuffer_flags = 0;
int my_pid = 0;
const volatile enum {
	ALL_CATH = 0,
	PROG_EXEC_CATH = 1,
	MOUNT_FS_CATH = 2,
	FILE_CATH = 10,
	INODE_CATH = 20
} cathegory;


char struct_dump_label[MAX_MSG_SIZE] = "STRUCT_DUMP";


/* Dirty macro hacks to work around libbpf lack of string locals */

#define DUMP_FUNC(FNAME, ...) {									\
	const char func_call_name[] = #FNAME;							\
	const char func_call_args[] = #__VA_ARGS__;						\
	dump_func(func_call_name, func_call_args);						\
}	

#define DUMP_MEMBER_SUINT(...) {								\
	const char dump_member_name[] = #__VA_ARGS__;						\
	short unsigned int mptr = BPF_CORE_READ(__VA_ARGS__);					\
	dump_suint_member(dump_member_name, mptr);						\
}

#define DUMP_MEMBER_UINT(...) {									\
	const char dump_member_name[] = #__VA_ARGS__;						\
	unsigned int mptr = BPF_CORE_READ(__VA_ARGS__);						\
	dump_uint_member(dump_member_name, mptr);						\
}

#define DUMP_MEMBER_LUINT(...) {								\
	const char dump_member_name[] = #__VA_ARGS__;						\
	long unsigned int mptr = BPF_CORE_READ(__VA_ARGS__);					\
	dump_luint_member(dump_member_name, mptr);						\
}

#define DUMP_MEMBER_LINT(...) {									\
	const char dump_member_name[] = #__VA_ARGS__;						\
	long int mptr = BPF_CORE_READ(__VA_ARGS__);						\
	dump_lint_member(dump_member_name, mptr);						\
}

#define DUMP_MEMBER_LLINT(...) {								\
	const char dump_member_name[] = #__VA_ARGS__;						\
	long long int mptr = BPF_CORE_READ(__VA_ARGS__);					\
	dump_llint_member(dump_member_name, mptr);						\
}

#define DUMP_MEMBER_USTR(...) {		 							\
	const char dump_member_name[] = #__VA_ARGS__;						\
	const unsigned char *mptr = BPF_CORE_READ(__VA_ARGS__);					\
	dump_ustr_member(dump_member_name, mptr);						\
}

#define DUMP_MEMBER_STR(...) {		 							\
	const char dump_member_name[] = #__VA_ARGS__;						\
	const char *mptr = BPF_CORE_READ(__VA_ARGS__);						\
	dump_str_member(dump_member_name, mptr);						\
}



static int dump_func(const char *fname, const char *fargs) {

	struct func_call_Event *evt; 								
	char func_call_label[] = "HOOK_CALL";

	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);

	if (!evt)										
		return -1;									

	evt->super.etype = FUNCTION_CALL;

	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), func_call_label);	
	bpf_probe_read_str(evt->name, sizeof(evt->name), fname);				
	bpf_probe_read_str(evt->args, sizeof(evt->args), fargs);				

	bpf_ringbuf_submit(evt, ringbuffer_flags);						

	return 0;
}

static int dump_suint_member(const char *mname, short unsigned int mptr) {

	struct suint_member_Event *evt; 								
	char suint_member_label[] = "MEMBER_DUMP";

	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);

	if (!evt)										
		return -1;									

	evt->super.etype = MEMBER_SUINT;

	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), suint_member_label);	
	evt->member = mptr;	
	bpf_probe_read_str(evt->msg, sizeof(evt->msg), mname);				
	bpf_ringbuf_submit(evt, ringbuffer_flags);						

	return 0;
}

static int dump_uint_member(const char *mname, unsigned int mptr) {

	struct uint_member_Event *evt; 								
	char uint_member_label[] = "MEMBER_DUMP";

	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);

	if (!evt)										
		return -1;									

	evt->super.etype = MEMBER_UINT;

	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), uint_member_label);	
	evt->member = mptr;	
	bpf_probe_read_str(evt->msg, sizeof(evt->msg), mname);				
	bpf_ringbuf_submit(evt, ringbuffer_flags);						

	return 0;
}

static int dump_luint_member(const char *mname, long unsigned int mptr) {

	struct luint_member_Event *evt; 								
	char luint_member_label[] = "MEMBER_DUMP";

	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);

	if (!evt)										
		return -1;									

	evt->super.etype = MEMBER_LUINT;

	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), luint_member_label);	
	evt->member = mptr;	
	bpf_probe_read_str(evt->msg, sizeof(evt->msg), mname);				
	bpf_ringbuf_submit(evt, ringbuffer_flags);						

	return 0;
}

static long dump_lint_member(const char *mname, unsigned int mptr) {

	struct lint_member_Event *evt; 								
	char lint_member_label[] = "MEMBER_DUMP";

	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);

	if (!evt)										
		return -1;									

	evt->super.etype = MEMBER_LINT;

	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), lint_member_label);	
	evt->member = mptr;	
	bpf_probe_read_str(evt->msg, sizeof(evt->msg), mname);				
	bpf_ringbuf_submit(evt, ringbuffer_flags);						

	return 0;
}

static long dump_llint_member(const char *mname, unsigned int mptr) {

	struct llint_member_Event *evt; 								
	char llint_member_label[] = "MEMBER_DUMP";

	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);

	if (!evt)										
		return -1;									

	evt->super.etype = MEMBER_LLINT;

	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), llint_member_label);	
	evt->member = mptr;	
	bpf_probe_read_str(evt->msg, sizeof(evt->msg), mname);				
	bpf_ringbuf_submit(evt, ringbuffer_flags);						

	return 0;
}





static int dump_str_member(const char *mname, const char *mptr) {

	struct str_member_Event *evt; 								
	char uint_member_label[] = "MEMBER_DUMP";

	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);

	if (!evt)										
		return -1;									

	evt->super.etype = MEMBER_STR;

	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), uint_member_label);	
	bpf_probe_read_str(evt->member, sizeof(evt->member), mptr);				
	bpf_probe_read_str(evt->msg, sizeof(evt->msg), mname);				
	bpf_ringbuf_submit(evt, ringbuffer_flags);						

	return 0;
}


static int dump_ustr_member(const char *mname, const unsigned char *mptr) {

	struct str_member_Event *evt; 								
	char uint_member_label[] = "MEMBER_DUMP";

	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);

	if (!evt)										
		return -1;									

	evt->super.etype = MEMBER_STR;

	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), uint_member_label);	
	bpf_probe_read_str(evt->member, sizeof(evt->member), mptr);				
	bpf_probe_read_str(evt->msg, sizeof(evt->msg), mname);				
	bpf_ringbuf_submit(evt, ringbuffer_flags);						

	return 0;
}

#endif /* _BPF_HELPERS_H */
