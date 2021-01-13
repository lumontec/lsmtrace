// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "lsmtrace.h"
#include "lsmtrace.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "lsmtrace 0.1";
const char *argp_program_bug_address = "<https://github.com/lumontec/lsmtrace.git/issues>";
const char argp_program_doc[] =
"BPF lsmtrace application.\n"
"\n"
"Trace lsm hook calls triggered by the process\n"
"\n"
"USAGE: ./lsmtrace [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "other..", 'o', "meaning", 0, "Full description" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'o':
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
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

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

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t len)
{
	if(len < sizeof(struct process_info)) {
		return -1;
	}

	const struct process_info *s = data;
	printf("%d\t%d\t%d\t%s\n", s->ppid, s->pid, s->tgid, s->name);
	return 0;

//	const struct event *e = data;
//	struct tm *tm;
//	char ts[32];
//	time_t t;
//
//	time(&t);
//	tm = localtime(&t);
//	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
//
//	if (e->exit_event) {
//		printf("%-8s %-5s %-16s %-7d %-7d [%u]",
//		       ts, "EXIT", e->comm, e->pid, e->ppid, e->exit_code);
//		if (e->duration_ns)
//			printf(" (%llums)", e->duration_ns / 1000000);
//		printf("\n");
//	} else {
//		printf("%-8s %-5s %-16s %-7d %-7d %s\n",
//		       ts, "EXEC", e->comm, e->pid, e->ppid, e->filename);
//	}
//
//	return 0;
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
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = lsmtrace_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
//	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = lsmtrace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = lsmtrace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	ringbuffer = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL, NULL);
	if (!ringbuffer) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
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