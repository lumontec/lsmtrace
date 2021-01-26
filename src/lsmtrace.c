// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//


#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
//#include "lsmtrace.h"
#include <linux/btf.h>
#include "lsmtrace.skel.h"
#include "statedump.h"


/* Argp info */
const char *argp_program_version = "lsmtrace version 0.1";
const char *argp_program_bug_address = "<https://github.com/lumontec/lsmtrace.git/issues>";
const char argp_program_doc[] = 
"\nLinux Security Modules tracer\n"
"\n"
"Trace lsm hook calls triggered by process\n"
"\n"
"Options:\n";
const char argp_program_args[] = "my_executable";

/* Argp options */
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "filter", 'f', "<cathegory>", 0, "Filter lsm hook cathegory, available {all|file|inode}" },
	{},
};

/* Argp arguments */
static struct env {
	bool verbose;
	long min_duration_ms;
	const char *cathegory;
} env;

const char    *my_argv[64] = {"/bin/ls" , "/home", NULL};

/* Argp parse */
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'f':
//		errno = 0;
//		env.min_duration_ms = strtol(arg, NULL, 10);
//		if (errno || env.min_duration_ms <= 0) {
//			fprintf(stderr, "Invalid duration: %s\n", arg);
//			argp_usage(state);
//		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
   	case ARGP_KEY_NO_ARGS:
      		argp_usage (state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* Argp config */
static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.args_doc = argp_program_args,
	.doc = argp_program_doc,
};



/* Libbpf callback handlers */

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int handle_event(void *ctx, void *data, size_t len)
{
	dumpEvent(data, len);
	return 0;
}



/* Signal handlers */

static volatile bool exiting = false;

static void sig_parentHandler(int sig)
{

	if (exiting) return;

	if (SIGINT == sig)
		fprintf(stdout, "Received signal SIGINT\n");

	if (SIGTERM == sig)
		fprintf(stdout, "Received signal SIGTERM\n");

	exiting = true;
}

static void sig_childHandler(int sig)
{
	if (SIGCONT == sig)
		fprintf(stdout, "Received signal SIGCONT\n");
}


/* forks waiting for SIGCONT and returns pid */
static int exec_prog_and_wait(const char **argv)
{
	int my_pid;

	my_pid = fork();
     	if (my_pid < 0)
	{
		fprintf(stderr, "Could not execute fork\n");
         	exit(1);
	}

	/* child process */
     	if (my_pid == 0)
        {
		fprintf(stdout, "Forked child process, paused waiting for SIGCONT\n");
		signal(SIGCONT, sig_childHandler);
		pause();
		fprintf(stdout, "Forked child process, executing\n");
		if (-1 == execve(argv[0], (char **)argv , NULL)) {
			perror("child process execve failed [%m]");
			exit(1);
		}
		exit(0);
	}

	return my_pid;
}


int main(int argc, char **argv)
{

	struct ring_buffer *ringbuffer = NULL;
	struct lsmtrace_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_parentHandler);
	signal(SIGTERM, sig_parentHandler);

	fprintf(stdout, "Launching process fork\n");

	int child_pid = exec_prog_and_wait(my_argv);

	fprintf(stdout, "Parent pid: %d\n", getpid());
	fprintf(stdout, "Child pid: %d\n", child_pid);

	/* Load and verify BPF application */
	skel = lsmtrace_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* pass child pid to bpf side */
	skel->bss->my_pid = child_pid;

	/* Load & verify BPF programs */
	err = lsmtrace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	fprintf(stdout, "Attaching hooks, don`t rush..\n");

	/* Attach tracepoints */
	err = lsmtrace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Send child cont signal */
	fprintf(stdout, "Attached, starting execution\n");
	kill(child_pid, SIGCONT);	


	/* Set up ring buffer polling */
	ringbuffer = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL, NULL);
	if (!ringbuffer) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {

		err = ring_buffer__poll(ringbuffer, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}


cleanup:
	/* Clean up */
	ring_buffer__free(ringbuffer);
	lsmtrace_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
