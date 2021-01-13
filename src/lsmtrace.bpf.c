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


//  Security hooks for program execution operations. 

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(bprm_creds_for_exec, struct linux_binprm *bprm)
{
	bpf_printk("lsm_hook: exec: bprm_creds_for_exec\n");
	return 0;
}

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(bprm_creds_from_file, struct linux_binprm *bprm, struct file *file)
{
	bpf_printk("lsm_hook: exec: bprm_creds_from_file\n");
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
	bpf_printk("lsm_hook: exec: bprm_check_security\n");
	return 0;
}


SEC("lsm/bprm_committing_creds")
void BPF_PROG(bprm_committing_creds, struct linux_binprm *bprm)
{
	bpf_printk("lsm_hook: exec: bprm_committing_creds\n");
}

SEC("lsm/bprm_committed_creds")
void BPF_PROG(bprm_committed_creds, struct linux_binprm *bprm)
{
	bpf_printk("lsm_hook: exec: bprm_committed_creds\n");
}


// Security hooks for mount using fs_context.

SEC("lsm/fs_context_dup")
int BPF_PROG(fs_context_dup,  struct fs_context *fc, struct fs_context *src_sc)
{
	bpf_printk("lsm_hook: fs_context: fs_context_dup\n");
	return 0;
}

SEC("lsm/fs_context_parse_param")
int BPF_PROG(fs_context_parse_param, struct fs_context *fc, struct fs_parameter *param)
{
	bpf_printk("lsm_hook: fs_context: fs_context_parse_param\n");
	return 0;
}


// Security hooks for filesystem operations.

SEC("lsm/sb_alloc_security")
int BPF_PROG(sb_alloc_security, struct super_block *sb)
{
	bpf_printk("lsm_hook: fs: sb_alloc_security\n");
	return 0;
}

SEC("lsm/sb_free_security")
void BPF_PROG(sb_free_security, struct super_block *sb)
{
	bpf_printk("lsm_hook: fs: sb_free_security\n");
}

SEC("lsm/sb_free_mnt_opts")
void BPF_PROG(sb_free_mnt_opts, void *mnt_opts)
{
	bpf_printk("lsm_hook: fs: sb_free_mnt_opts\n");
}

SEC("lsm/sb_eat_lsm_opts")
int BPF_PROG(sb_eat_lsm_opts, char *orig, void **mnt_opts)
{
	bpf_printk("lsm_hook: fs: sb_eat_lsm_opts\n");
	return 0;
}









char _license[] SEC("license") = "GPL";






//SEC("lsm/bprm_committed_creds")
//void BPF_PROG(bprm_committed_creds, struct linux_binprm *bprm)
//{
//	bpf_printk("lsm_hook: bprm_committed_creds\n");
//	long pid_tgid;
//	struct process_info *process;
//	struct task_struct *current_task;
//
//	// Reserve space on the ringbuffer for the sample
//	process = bpf_ringbuf_reserve(&ringbuf, sizeof(*process), ringbuffer_flags);
//	if (!process)
//		return;
//
//	// Get information about the current process
//	pid_tgid = bpf_get_current_pid_tgid();
//	process->pid = pid_tgid;
//	process->tgid = pid_tgid >> 32;
//
//	// Get the parent pid
//	current_task = (struct task_struct *)bpf_get_current_task();
//	process->ppid = BPF_CORE_READ(current_task, real_parent, pid);
//
//	// Get the executable name
//	bpf_get_current_comm(&process->name, sizeof(process->name));
//
//	bpf_ringbuf_submit(process, ringbuffer_flags);
//}



