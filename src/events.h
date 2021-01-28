/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __EVENTS_H
#define __EVENTS_H

#include "vmlinux.h"

#define MAX_LABEL_SIZE 100
#define MAX_MSG_SIZE 200
#define MAX_STR_SIZE 200 

enum Event_type {

	FUNCTION_CALL = 0,

	MEMBER_UINT = 10,
	MEMBER_LINT = 12,
	MEMBER_LLINT = 13,
	MEMBER_STR = 15,

	STRUCT_FILE = 100,
	STRUCT_DENTRY = 101,
	STRUCT_QSTR = 102,
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


/* Struct member dump events */

typedef struct uint_member_Event {
	Event super;
	unsigned int member;	
	char msg[MAX_MSG_SIZE];
} uint_member_Event;

typedef struct lint_member_Event {
	Event super;
	long int member;	
	char msg[MAX_MSG_SIZE];
} lint_member_Event;

typedef struct llint_member_Event {
	Event super;
	long long int member;	
	char msg[MAX_MSG_SIZE];
} llint_member_Event;

typedef struct str_member_Event {
	Event super;
	char member[MAX_STR_SIZE];
	char msg[MAX_MSG_SIZE];
} str_member_Event;


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


#endif /* __EVENTS_H */
