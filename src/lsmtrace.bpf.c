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

SEC("lsm/sb_statfs")
int BPF_PROG(sb_statfs, struct dentry *dentry)
{
	bpf_printk("lsm_hook: fs: sb_statfs\n");
	return 0;
}

SEC("lsm/sb_mount")
int BPF_PROG(sb_mount, const char *dev_name, const struct path *path,
	const char *type, unsigned long flags, void *data)
{
	bpf_printk("lsm_hook: fs: sb_mount\n");
	return 0;
}

// @sb_copy_data

SEC("lsm/sb_remount")
int BPF_PROG(sb_remount, struct super_block *sb, void *mnt_opts)
{
	bpf_printk("lsm_hook: fs: sb_mount\n");
	return 0;
}

SEC("lsm/sb_kern_mount")
int BPF_PROG(sb_kern_mount, struct super_block *sb)
{
	bpf_printk("lsm_hook: fs: sb_kern_mount\n");
	return 0;
}

SEC("lsm/sb_show_options")
int BPF_PROG(sb_show_options, struct seq_file *m, struct super_block *sb)
{
	bpf_printk("lsm_hook: fs: sb_show_options\n");
	return 0;
}

SEC("lsm/sb_umount")
int BPF_PROG(sb_umount, struct vfsmount *mnt, int flags)
{
	bpf_printk("lsm_hook: fs: sb_umount\n");
	return 0;
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(sb_pivotroot, const struct path *old_path,
	 const struct path *new_path)
{
	bpf_printk("lsm_hook: fs: sb_pivotroot\n");
	return 0;
}

SEC("lsm/sb_set_mnt_opts")
int BPF_PROG(sb_set_mnt_opts, struct super_block *sb, void *mnt_opts,
	 unsigned long kern_flags, unsigned long *set_kern_flags)
{
	bpf_printk("lsm_hook: fs: sb_set_mnt_opts\n");
	return 0;
}

SEC("lsm/sb_clone_mnt_opts")
int BPF_PROG(sb_clone_mnt_opts, const struct super_block *oldsb,
	 struct super_block *newsb, unsigned long kern_flags,
	 unsigned long *set_kern_flags)
{
	bpf_printk("lsm_hook: fs: sb_clone_mnt_opts\n");
	return 0;
}

SEC("lsm/sb_add_mnt_opt")
int BPF_PROG(sb_add_mnt_opt, const char *option, const char *val,
	 int len, void **mnt_opts)
{
	bpf_printk("lsm_hook: fs: sb_add_mnt_opt\n");
	return 0;
}

// @sb_parse_opts_str


SEC("lsm/move_mount")
int BPF_PROG(move_mount, const struct path *from_path,
	 const struct path *to_path)
{
	bpf_printk("lsm_hook: fs: move_mount\n");
	return 0;
}

//SEC("lsm/dentry_init_security")
//int BPF_PROG(dentry_init_security, struct dentry *dentry,
//	 int mode, const struct qstr *name, void **ctx, u32 *ctxlen)
//{
//	bpf_printk("lsm_hook: fs: dentry_init_security\n");
//	return 0;
//}

SEC("lsm/dentry_create_files_as")
int BPF_PROG(dentry_create_files_as, struct dentry *dentry, int mode,
	 struct qstr *name, const struct cred *old, struct cred *new)
{
	bpf_printk("lsm_hook: fs: dentry_create_files_as\n");
	return 0;
}


// Security hooks for inode operations.







char _license[] SEC("license") = "GPL";


// Not implemented:
// sb_copy_data
// sb_parse_opts_str






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



