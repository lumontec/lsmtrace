/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __EVENTS_H
#define __EVENTS_H

#include "vmlinux.h"


enum Event_type {
	STRUCT_FILE = 0,
	STRUCT_DENTRY = 1,
	STRUCT_QSTR = 2,
};

/* Generic event type */
typedef struct Event {
	enum Event_type etype;
} Event;


typedef struct file_Event {
	Event super;
	struct file file_s;		
} file_Event;


typedef struct dentry_Event {
	Event super;
	struct dentry dentry_s;		
} dentry_Event;


typedef struct qstr_Event {
	Event super;
	struct qstr qstr_s;		
} qstr_Event;










//struct process_info {
//	int ppid;
//	int pid;
//	int tgid;
////	char name[PATH_MAX];
//};


//struct event {
//	int pid;
//	int ppid;
//	unsigned exit_code;
//	unsigned long long duration_ns;
//	char comm[TASK_COMM_LEN];
//	char filename[MAX_FILENAME_LEN];
////	bool exit_event;
//};

#endif /* __EVENTS_H */
