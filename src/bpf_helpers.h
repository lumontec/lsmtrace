#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "events.h"

#define FILTER_OWN_PID_INT() 			\
int pid = bpf_get_current_pid_tgid() >> 32;	\
if (pid != my_pid)				\
	return 0;				

#define FILTER_OWN_PID_VOID() 			\
int pid = bpf_get_current_pid_tgid() >> 32;	\
if (pid != my_pid)				\
	return;					


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");

long ringbuffer_flags = 0;
int my_pid = 0;


char func_call_label[MAX_MSG_SIZE] = "FUNCTION_CALL";
char struct_dump_label[MAX_MSG_SIZE] = "STRUCT_DUMP";


#define DUMP_FUNC(FNAME, ...)									\
{												\
	struct func_call_Event *evt;  								\
	static char FNAME##name[MAX_MSG_SIZE] = #FNAME;						\
	static char FNAME##args[MAX_MSG_SIZE] = #__VA_ARGS__;					\
												\
	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);			\
												\
	if (!evt)										\
		return -1;									\
												\
	evt->super.etype = FUNCTION_CALL;							\
	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), func_call_label);	\
	bpf_probe_read_str(evt->name, sizeof(evt->name), FNAME##name);				\
	bpf_probe_read_str(evt->args, sizeof(evt->args), FNAME##args);				\
												\
	bpf_ringbuf_submit(evt, ringbuffer_flags);						\
}


#define DUMP_STRUCT(STYPE, ETYPE, SPTR) 							\
{												\
/*	struct STYPE *STYPE;									\
*/												\
	struct STYPE##_struct_Event *evt; 							\
												\
	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);			\
												\
	if (!evt)										\
		return -1;									\
												\
	evt->super.etype = ETYPE;								\
	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), struct_dump_label);	\
	bpf_probe_read_kernel(&evt->STYPE, sizeof(evt->STYPE), SPTR);				\
												\
	bpf_ringbuf_submit(evt, ringbuffer_flags);						\
}

#endif /* _BPF_HELPERS_H */
