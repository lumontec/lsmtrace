/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __LMSTRACE_H
#define __LMSTRACE_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct process_info {
	int ppid;
	int pid;
	int tgid;
//	char name[PATH_MAX];
};

struct test {
	int argvalue;
	int setvalue;
};

struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
//	bool exit_event;
};

#endif /* __LMSTRACE_H */
