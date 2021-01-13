/*
 * Copyright 2020 Google LLC
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "lsmtrace.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");

long ringbuffer_flags = 0;

SEC("lsm/bprm_committed_creds")
void BPF_PROG(exec_audit, struct linux_binprm *bprm)
{
	long pid_tgid;
	struct process_info *process;
	struct task_struct *current_task;

	// Reserve space on the ringbuffer for the sample
	process = bpf_ringbuf_reserve(&ringbuf, sizeof(*process), ringbuffer_flags);
	if (!process)
		return;

	// Get information about the current process
	pid_tgid = bpf_get_current_pid_tgid();
	process->pid = pid_tgid;
	process->tgid = pid_tgid >> 32;

	// Get the parent pid
	current_task = (struct task_struct *)bpf_get_current_task();
	process->ppid = BPF_CORE_READ(current_task, real_parent, pid);

	// Get the executable name
	bpf_get_current_comm(&process->name, sizeof(process->name));

	bpf_ringbuf_submit(process, ringbuffer_flags);
}

char _license[] SEC("license") = "GPL";

