/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __EVENTS_H
#define __EVENTS_H

#include "vmlinux.h"

#define MAX_LABEL_SIZE 50
#define MAX_MSG_SIZE 50

enum Event_type {
	FUNCTION_CALL = 0,
	STRUCT_FILE = 1,
	STRUCT_DENTRY = 2,
	STRUCT_QSTR = 3,
};

/* Generic event interface */

typedef struct Event {
	enum Event_type etype;
	char label[MAX_LABEL_SIZE];
} Event;


/* Function call events */

typedef struct func_call_Event {
	Event super;
	char name[MAX_MSG_SIZE];
	char args[MAX_MSG_SIZE];
} func_call_Event;


/* Struct dump events */

typedef struct file_struct_Event {
	Event super;
	struct file file;		
	char msg[MAX_MSG_SIZE];
} file_struct_Event;

typedef struct dentry_struct_Event {
	Event super;
	struct dentry dentry;		
	char msg[MAX_MSG_SIZE];
} dentry_struct_Event;

typedef struct qstr_struct_Event {
	Event super;
	struct qstr qstr;
	char msg[MAX_MSG_SIZE];
} qstr_struct_Event;










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
