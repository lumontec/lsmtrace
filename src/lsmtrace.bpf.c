/*
 * Copyright .. 
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
//#include <linux/limits.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_dump_helpers.h"
#include "bpf_dump_structs.h"
#include "events.h"

// Syscall helpers to trace syscall happening

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *args)
{
	FILTER_OWN_PID_INT()

	struct sys_enter_Event *evt; 								
	char sys_enter_label[] = "SYS_CALL_ENTER";

	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);

	if (!evt)										
		return -1;									

	evt->super.etype = SYS_CALL_ENTER;

	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), sys_enter_label);	
	evt->id = BPF_CORE_READ(args, id);

	bpf_ringbuf_submit(evt, ringbuffer_flags);						

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *args)
{
	FILTER_OWN_PID_INT()

	struct sys_exit_Event *evt; 								
	char sys_exit_label[] = "SYS_CALL_EXIT";

	evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), ringbuffer_flags);

	if (!evt)										
		return -1;									

	evt->super.etype = SYS_CALL_EXIT;

	bpf_probe_read_str(evt->super.label, sizeof(evt->super.label), sys_exit_label);	
	evt->id = BPF_CORE_READ(args, id);
	evt->ret = BPF_CORE_READ(args, ret);

	bpf_ringbuf_submit(evt, ringbuffer_flags);						

	return 0;
}


//  Security hooks for program execution operations. 

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(bprm_creds_for_exec, struct linux_binprm *bprm)
{
	FILTER_CATHEGORY_INT(PROG_EXEC_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(bprm_creds_for_exec, struct linux_binprm *bprm)
	
	DUMP_LINUX_BINPRM_STRUCT(bprm)

	bpf_printk("lsm_hook: exec: bprm_creds_for_exec\n");
	return 0;
}

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(bprm_creds_from_file, struct linux_binprm *bprm, struct file *file)
{
	FILTER_CATHEGORY_INT(PROG_EXEC_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(bprm_creds_from_file, struct linux_binprm *bprm, struct file *file)

	DUMP_LINUX_BINPRM_STRUCT(bprm)
	DUMP_FILE_STRUCT(file)

	bpf_printk("lsm_hook: exec: bprm_creds_from_file\n");
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
	FILTER_CATHEGORY_INT(PROG_EXEC_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(bprm_check_security, struct linux_binprm *bprm)

	DUMP_LINUX_BINPRM_STRUCT(bprm)

	bpf_printk("lsm_hook: exec: bprm_check_security\n");
	return 0;
}


SEC("lsm/bprm_committing_creds")
void BPF_PROG(bprm_committing_creds, struct linux_binprm *bprm)
{
	FILTER_CATHEGORY_VOID(PROG_EXEC_CATH)
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(bprm_committing_creds, struct linux_binprm *bprm)

	DUMP_LINUX_BINPRM_STRUCT(bprm)

	bpf_printk("lsm_hook: exec: bprm_committing_creds\n");
}

SEC("lsm/bprm_committed_creds")
void BPF_PROG(bprm_committed_creds, struct linux_binprm *bprm)
{
	FILTER_CATHEGORY_VOID(PROG_EXEC_CATH)
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(bprm_committed_creds, struct linux_binprm *bprm)

	DUMP_LINUX_BINPRM_STRUCT(bprm)

	bpf_printk("lsm_hook: exec: bprm_committed_creds\n");
}


// Security hooks for mount using fs_context.

SEC("lsm/fs_context_dup")
int BPF_PROG(fs_context_dup,  struct fs_context *fc, struct fs_context *src_sc)
{
	FILTER_CATHEGORY_INT(MOUNT_FS_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(fs_context_dup,  struct fs_context *fc, struct fs_context *src_sc)

	bpf_printk("lsm_hook: fs_context: fs_context_dup\n");
	return 0;
}

SEC("lsm/fs_context_parse_param")
int BPF_PROG(fs_context_parse_param, struct fs_context *fc, struct fs_parameter *param)
{
	FILTER_CATHEGORY_INT(MOUNT_FS_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(fs_context_parse_param, struct fs_context *fc, struct fs_parameter *param)

	bpf_printk("lsm_hook: fs_context: fs_context_parse_param\n");
	return 0;
}


// Security hooks for filesystem operations.

SEC("lsm/sb_alloc_security")
int BPF_PROG(sb_alloc_security, struct super_block *sb)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_alloc_security, struct super_block *sb)

	bpf_printk("lsm_hook: fs: sb_alloc_security\n");
	return 0;
}

SEC("lsm/sb_free_security")
void BPF_PROG(sb_free_security, struct super_block *sb)
{
	FILTER_CATHEGORY_VOID(FILE_CATH)
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(sb_alloc_security, struct super_block *sb)

	bpf_printk("lsm_hook: fs: sb_free_security\n");
}

SEC("lsm/sb_free_mnt_opts")
void BPF_PROG(sb_free_mnt_opts, void *mnt_opts)
{
	FILTER_CATHEGORY_VOID(FILE_CATH)
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(sb_free_mnt_opts, void *mnt_opts)

	bpf_printk("lsm_hook: fs: sb_free_mnt_opts\n");
}

SEC("lsm/sb_eat_lsm_opts")
int BPF_PROG(sb_eat_lsm_opts, char *orig, void **mnt_opts)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_eat_lsm_opts, char *orig, void **mnt_opts)

	bpf_printk("lsm_hook: fs: sb_eat_lsm_opts\n");
	return 0;
}

SEC("lsm/sb_statfs")
int BPF_PROG(sb_statfs, struct dentry *dentry)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_statfs, struct dentry *dentry)

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: fs: sb_statfs\n");
	return 0;
}

SEC("lsm/sb_mount")
int BPF_PROG(sb_mount, const char *dev_name, const struct path *path,
	const char *type, unsigned long flags, void *data)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_mount, const char *dev_name, const struct path *path,
	const char *type, unsigned long flags, void *data)

	bpf_printk("lsm_hook: fs: sb_mount\n");
	return 0;
}

// @sb_copy_data

SEC("lsm/sb_remount")
int BPF_PROG(sb_remount, struct super_block *sb, void *mnt_opts)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_remount, struct super_block *sb, void *mnt_opts)

	bpf_printk("lsm_hook: fs: sb_mount\n");
	return 0;
}

SEC("lsm/sb_kern_mount")
int BPF_PROG(sb_kern_mount, struct super_block *sb)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_kern_mount, struct super_block *sb)

//	bpf_printk("lsm_hook: fs: sb_kern_mount\n");
	return 0;
}

SEC("lsm/sb_show_options")
int BPF_PROG(sb_show_options, struct seq_file *m, struct super_block *sb)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_show_options, struct seq_file *m, struct super_block *sb)

	bpf_printk("lsm_hook: fs: sb_show_options\n");
	return 0;
}

SEC("lsm/sb_umount")
int BPF_PROG(sb_umount, struct vfsmount *mnt, int flags)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_umount, struct vfsmount *mnt, int flags)

	bpf_printk("lsm_hook: fs: sb_umount\n");
	return 0;
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(sb_pivotroot, const struct path *old_path,
	 const struct path *new_path)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_pivotroot, const struct path *old_path,
	 const struct path *new_path)

	bpf_printk("lsm_hook: fs: sb_pivotroot\n");
	return 0;
}

SEC("lsm/sb_set_mnt_opts")
int BPF_PROG(sb_set_mnt_opts, struct super_block *sb, void *mnt_opts,
	 unsigned long kern_flags, unsigned long *set_kern_flags)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_set_mnt_opts, struct super_block *sb, void *mnt_opts,
	 unsigned long kern_flags, unsigned long *set_kern_flags)

	bpf_printk("lsm_hook: fs: sb_set_mnt_opts\n");
	return 0;
}

SEC("lsm/sb_clone_mnt_opts")
int BPF_PROG(sb_clone_mnt_opts, const struct super_block *oldsb,
	 struct super_block *newsb, unsigned long kern_flags,
	 unsigned long *set_kern_flags)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_clone_mnt_opts, const struct super_block *oldsb,
	 struct super_block *newsb, unsigned long kern_flags,
	 unsigned long *set_kern_flags)

	bpf_printk("lsm_hook: fs: sb_clone_mnt_opts\n");
	return 0;
}

SEC("lsm/sb_add_mnt_opt")
int BPF_PROG(sb_add_mnt_opt, const char *option, const char *val,
	 int len, void **mnt_opts)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sb_add_mnt_opt, const char *option, const char *val,
	 int len, void **mnt_opts)

	bpf_printk("lsm_hook: fs: sb_add_mnt_opt\n");
	return 0;
}

// @sb_parse_opts_str


SEC("lsm/move_mount")
int BPF_PROG(move_mount, const struct path *from_path,
	 const struct path *to_path)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(move_mount, const struct path *from_path,
	 const struct path *to_path)

	bpf_printk("lsm_hook: fs: move_mount\n");
	return 0;
}

SEC("lsm/dentry_init_security")
int BPF_PROG(dentry_init_security, struct dentry *dentry,
	 int mode, const struct qstr *name, void **lsm_ctx, u32 *ctxlen)
{	
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(dentry_init_security, struct dentry *dentry,
	 int mode, const struct qstr *name, void **lsm_ctx, u32 *ctxlen)

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: fs: dentry_init_security\n");
	return 0;
}

SEC("lsm/dentry_create_files_as")
int BPF_PROG(dentry_create_files_as, struct dentry *dentry, int mode,
	 struct qstr *name, const struct cred *old, struct cred *new)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(dentry_create_files_as, struct dentry *dentry, int mode,
	 struct qstr *name, const struct cred *old, struct cred *new)

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: fs: dentry_create_files_as\n");
	return 0;
}


// Security hooks for inode operations.

SEC("lsm/inode_alloc_security")
int BPF_PROG(inode_alloc_security, struct inode *inode)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_alloc_security, struct inode *inode)

	DUMP_INODE_STRUCT(inode)

	bpf_printk("lsm_hook: inode: inode_alloc_security\n");
	return 0;
}

SEC("lsm/inode_free_security")
void BPF_PROG(inode_free_security, struct inode *inode)
{
	FILTER_CATHEGORY_VOID(INODE_CATH)
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(inode_free_security, struct inode *inode)

	DUMP_INODE_STRUCT(inode)

	bpf_printk("lsm_hook: inode: inode_free_security\n");
}

SEC("lsm/inode_init_security")
int BPF_PROG(inode_init_security, struct inode *inode,
	 struct inode *dir, const struct qstr *qstr, const char **name,
	 void **value, size_t *len)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_init_security, struct inode *inode,
	 struct inode *dir, const struct qstr *qstr, const char **name,
	 void **value, size_t *len)

	DUMP_INODE_STRUCT(inode)

	bpf_printk("lsm_hook: inode: inode_init_security\n");
	return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(inode_create, struct inode *inode_dir, struct dentry *dentry,
	 umode_t mode)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_create, struct inode *dir, struct dentry *dentry,
	 umode_t mode)

	DUMP_INODE_STRUCT(inode_dir)

	bpf_printk("lsm_hook: inode: inode_create\n");
	return 0;
}

SEC("lsm/inode_link")
int BPF_PROG(inode_link, struct dentry *old_dentry, struct inode *inode_dir,
	 struct dentry *new_dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_link, struct dentry *old_dentry, struct inode *dir,
	 struct dentry *new_dentry)

	DUMP_DENTRY_STRUCT(old_dentry)
	DUMP_INODE_STRUCT(inode_dir)
	DUMP_DENTRY_STRUCT(new_dentry)

	bpf_printk("lsm_hook: inode: inode_link\n");
	return 0;
}

SEC("lsm/path_link")
int BPF_PROG(path_link, struct dentry *old_dentry,
	 const struct path *new_dir, struct dentry *new_dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(path_link, struct dentry *old_dentry,
	 const struct path *new_dir, struct dentry *new_dentry)

	DUMP_DENTRY_STRUCT(old_dentry)
	DUMP_DENTRY_STRUCT(new_dentry)

	bpf_printk("lsm_hook: inode: path_link\n");
	return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(inode_unlink, struct inode *inode_dir, struct dentry *dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_unlink, struct inode *dir, struct dentry *dentry)

	DUMP_INODE_STRUCT(inode_dir)
	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_unlink\n");
	return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, const struct path *dir, struct dentry *dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(path_unlink, const struct path *dir, struct dentry *dentry)

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: path_unlink\n");
	return 0;
}

SEC("lsm/inode_symlink")
int BPF_PROG(inode_symlink, struct inode *inode_dir, struct dentry *dentry,
	 const char *old_name)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_symlink, struct inode *dir, struct dentry *dentry,
	 const char *old_name)

	DUMP_INODE_STRUCT(inode_dir)
	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_symlink\n");
	return 0;
}

SEC("lsm/path_symlink")
int BPF_PROG(path_symlink, const struct path *dir, struct dentry *dentry,
	 const char *old_name)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(path_symlink, const struct path *dir, struct dentry *dentry,
	 const char *old_name)

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: path_symlink\n");
	return 0;
}

SEC("lsm/inode_mkdir")
int BPF_PROG(inode_mkdir, struct inode *inode_dir, struct dentry *dentry,
	 umode_t mode)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_mkdir, struct inode *dir, struct dentry *dentry,
	 umode_t mode)

	DUMP_INODE_STRUCT(inode_dir)
	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_mkdir\n");
	return 0;
}

SEC("lsm/path_mkdir")
int BPF_PROG(path_mkdir, const struct path *dir, struct dentry *dentry,
	 umode_t mode)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(path_mkdir, const struct path *dir, struct dentry *dentry,
	 umode_t mode)

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: path_mkdir\n");
	return 0;
}

SEC("lsm/inode_rmdir")
int BPF_PROG(inode_rmdir, struct inode *inode_dir, struct dentry *dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_rmdir, struct inode *dir, struct dentry *dentry)

	DUMP_INODE_STRUCT(inode_dir)
	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_rmdir\n");
	return 0;
}

SEC("lsm/path_rmdir")
int BPF_PROG(path_rmdir, const struct path *dir, struct dentry *dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(path_rmdir, const struct path *dir, struct dentry *dentry)

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: path_rmdir\n");
	return 0;
}

SEC("lsm/inode_mknod")
int BPF_PROG(inode_mknod, struct inode *inode_dir, struct dentry *dentry,
	 umode_t mode, dev_t dev)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_mknod, struct inode *dir, struct dentry *dentry,
	 umode_t mode, dev_t dev)

	DUMP_INODE_STRUCT(inode_dir)
	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_mknod\n");
	return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(inode_rename, struct inode *old_inode_dir, struct dentry *old_dentry,
	 struct inode *new_inode_dir, struct dentry *new_dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	 struct inode *new_dir, struct dentry *new_dentry)

	DUMP_INODE_STRUCT(old_inode_dir)
	DUMP_DENTRY_STRUCT(old_dentry)
	DUMP_INODE_STRUCT(new_inode_dir)
	DUMP_DENTRY_STRUCT(new_dentry)

	bpf_printk("lsm_hook: inode: inode_rename\n");
	return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(path_rename, const struct path *old_dir,
	 struct dentry *old_dentry, const struct path *new_dir,
	 struct dentry *new_dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(path_rename, const struct path *old_dir,
	 struct dentry *old_dentry, const struct path *new_dir,
	 struct dentry *new_dentry)

	DUMP_DENTRY_STRUCT(old_dentry)
	DUMP_DENTRY_STRUCT(new_dentry)

	bpf_printk("lsm_hook: inode: path_rename\n");
	return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path, umode_t mode)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(path_chmod, const struct path *path, umode_t mode)

	bpf_printk("lsm_hook: inode: path_chmod\n");
	return 0;
}

//SEC("lsm/path_chown")
//int BPF_PROG(path_chown, const struct path *path, kuid_t uid, kgid_t gid)
//{
//	bpf_printk("lsm_hook: inode: path_chown\n");
//	return 0;
//}
//
SEC("lsm/path_chroot")
int BPF_PROG(path_chroot, const struct path *path)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(path_chroot, const struct path *path)

	bpf_printk("lsm_hook: inode: path_chroot\n");
	return 0;
}

SEC("lsm/path_notify")
int BPF_PROG(path_notify, const struct path *path, u64 mask,
	 unsigned int obj_type)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(path_notify, const struct path *path, u64 mask,
	 unsigned int obj_type)

	bpf_printk("lsm_hook: inode: path_notify\n");
	return 0;
}

SEC("lsm/inode_readlink")
int BPF_PROG(inode_readlink, struct dentry *dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_readlink, struct dentry *dentry)

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_readlink\n");
	return 0;
}

SEC("lsm/inode_follow_link")
int BPF_PROG(inode_follow_link, struct dentry *dentry, struct inode *inode,
	 bool rcu)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_follow_link, struct dentry *dentry, struct inode *inode,
	 bool rcu)

	DUMP_DENTRY_STRUCT(dentry)
	DUMP_INODE_STRUCT(inode)

	bpf_printk("lsm_hook: inode: inode_follow_link\n");
	return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(inode_permission, struct inode *inode, int mask)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_permission, struct inode *inode, int mask)

	DUMP_INODE_STRUCT(inode)

	bpf_printk("lsm_hook: inode: inode_permission\n");
	return 0;
}

SEC("lsm/inode_setattr")
int BPF_PROG(inode_setattr, struct dentry *dentry, struct iattr *attr)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_setattr\n");
	return 0;
}

SEC("lsm/path_truncate")
int BPF_PROG(path_truncate, const struct path *path)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	bpf_printk("lsm_hook: inode: path_truncate\n");
	return 0;
}

SEC("lsm/inode_getattr")
int BPF_PROG(inode_getattr, const struct path *path)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	bpf_printk("lsm_hook: inode: inode_getattr\n");
	return 0;
}

SEC("lsm/inode_setxattr")
int BPF_PROG(inode_setxattr, struct dentry *dentry, const char *name,
	 const void *value, size_t size, int flags)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_setxattr\n");
	return 0;
}

SEC("lsm/inode_post_setxattr")
int BPF_PROG(inode_post_setxattr, struct dentry *dentry,
	 const char *name, const void *value, size_t size, int flags)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_post_setxattr\n");
	return 0;
}

SEC("lsm/inode_getxattr")
int BPF_PROG(inode_getxattr, struct dentry *dentry, const char *name)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_getxattr\n");
	return 0;
}

SEC("lsm/inode_listxattr")
int BPF_PROG(inode_listxattr, struct dentry *dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_listxattr\n");
	return 0;
}

SEC("lsm/inode_removexattr")
int BPF_PROG(inode_removexattr, struct dentry *dentry, const char *name)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_removexattr\n");
	return 0;
}

SEC("lsm/inode_getsecurity")
int BPF_PROG(inode_getsecurity, struct inode *inode,
	 const char *name, void **buffer, bool alloc)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_INODE_STRUCT(inode)

	bpf_printk("lsm_hook: inode: inode_getsecurity\n");
	return 0;
}

SEC("lsm/inode_setsecurity")
int BPF_PROG(inode_setsecurity, struct inode *inode,
	 const char *name, const void *value, size_t size, int flags)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_INODE_STRUCT(inode)

	bpf_printk("lsm_hook: inode: inode_setsecurity\n");
	return 0;
}


SEC("lsm/inode_listsecurity")
int BPF_PROG(inode_listsecurity, struct inode *inode, char *buffer,
	 size_t buffer_size)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_INODE_STRUCT(inode)

	bpf_printk("lsm_hook: inode: inode_listsecurity\n");
	return 0;
}

SEC("lsm/inode_need_killpriv")
int BPF_PROG(inode_need_killpriv, struct dentry *dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_need_killpriv\n");
	return 0;
}

SEC("lsm/inode_killpriv")
int BPF_PROG(inode_killpriv, struct dentry *dentry)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: inode_killpriv\n");
	return 0;
}

SEC("lsm/inode_getsecid")
void BPF_PROG(inode_getsecid, struct inode *inode, u32 *secid)
{
	FILTER_CATHEGORY_VOID(INODE_CATH)
	FILTER_OWN_PID_VOID()

	DUMP_INODE_STRUCT(inode)

	bpf_printk("lsm_hook: inode: inode_getsecid\n");
}

SEC("lsm/inode_copy_up")
int BPF_PROG(inode_copy_up, struct dentry *dentry_src, struct cred **new)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_DENTRY_STRUCT(dentry_src)

	bpf_printk("lsm_hook: inode: inode_copy_up\n");
	return 0;
}

SEC("lsm/inode_copy_up_xattr")
int BPF_PROG(inode_copy_up_xattr, const char *name)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	bpf_printk("lsm_hook: inode: inode_copy_up_xattr\n");
	return 0;
}

SEC("lsm/d_instantiate")
int BPF_PROG(d_instantiate, struct dentry *dentry,
	 struct inode *inode)
{
	FILTER_CATHEGORY_INT(INODE_CATH)
	FILTER_OWN_PID_INT()

	DUMP_DENTRY_STRUCT(dentry)

	bpf_printk("lsm_hook: inode: d_instantiate\n");
	return 0;
}

SEC("lsm/getprocattr")
int BPF_PROG(getprocattr, struct task_struct *p, char *name,
	 char **value)
{
	FILTER_OWN_PID_INT()

	bpf_printk("lsm_hook: inode: getprocattr\n");
	return 0;
}

SEC("lsm/setprocattr")
int BPF_PROG(setprocattr, const char *name, void *value, size_t size)
{
	FILTER_OWN_PID_INT()

	bpf_printk("lsm_hook: inode: setprocattr\n");
	return 0;
}


// Security hooks for kernfs node operations

SEC("lsm/kernfs_init_security")
int BPF_PROG(kernfs_init_security, struct kernfs_node *kn_dir,
	 struct kernfs_node *kn)
{
	FILTER_OWN_PID_INT()

	bpf_printk("lsm_hook: kernfs_node: kernfs_init_security\n");
	return 0;
}


// Security hooks for file operations

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(file_permission, struct file *file, int mask)

	DUMP_FILE_STRUCT(file)
	bpf_printk("lsm_hook: file: file_permission\n");
	return 0;
}

SEC("lsm/file_alloc_security")
int BPF_PROG(file_alloc_security, struct file *file)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(file_alloc_security, struct file *file)

	DUMP_FILE_STRUCT(file)
	bpf_printk("lsm_hook: file: file_alloc_security\n");
	return 0;
}

SEC("lsm/file_free_security")
void BPF_PROG(file_free_security, struct file *file)
{
	FILTER_CATHEGORY_VOID(FILE_CATH)
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(file_free_security, struct file *file)

	DUMP_FILE_STRUCT(file)
	bpf_printk("lsm_hook: file: file_free_security\n");
}

SEC("lsm/file_ioctl")
int BPF_PROG(file_ioctl, struct file *file, unsigned int cmd,
	 unsigned long arg)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(file_ioctl, struct file *file, unsigned int cmd,
	 unsigned long arg)

	DUMP_FILE_STRUCT(file)
	bpf_printk("lsm_hook: file: file_ioctl\n");
	return 0;
}

SEC("lsm/mmap_addr")
int BPF_PROG(mmap_addr, unsigned long addr)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(mmap_addr, unsigned long addr)

	bpf_printk("lsm_hook: file: mmap_addr\n");
	return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot,
	 unsigned long prot, unsigned long flags)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(mmap_file, struct file *file, unsigned long reqprot,
	 unsigned long prot, unsigned long flags)

	DUMP_FILE_STRUCT(file)
	bpf_printk("lsm_hook: file: mmap_file\n");
	return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(file_mprotect, struct vm_area_struct *vma,
	 unsigned long reqprot, unsigned long prot)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(file_mprotect, struct vm_area_struct *vma,
	 unsigned long reqprot, unsigned long prot)

	bpf_printk("lsm_hook: file: file_mprotect\n");
	return 0;
}

SEC("lsm/file_lock")
int BPF_PROG(file_lock, struct file *file, unsigned int cmd)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(file_lock, struct file *file, unsigned int cmd)

	DUMP_FILE_STRUCT(file)
	bpf_printk("lsm_hook: file: file_mprotect\n");
	return 0;
}

SEC("lsm/file_fcntl")
int BPF_PROG(file_fcntl, struct file *file, unsigned int cmd,
	 unsigned long arg)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(file_fcntl, struct file *file, unsigned int cmd,
	 unsigned long arg)

	DUMP_FILE_STRUCT(file)
	bpf_printk("lsm_hook: file: file_fcntl\n");
	return 0;
}

SEC("lsm/file_set_fowner")
int BPF_PROG(file_set_fowner, struct file *file)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(file_set_fowner, struct file *file)

	DUMP_FILE_STRUCT(file)
	bpf_printk("lsm_hook: file: file_set_fowner\n");
	return 0;
}

SEC("lsm/file_send_sigiotask")
int BPF_PROG(file_send_sigiotask, struct task_struct *tsk,
	 struct fown_struct *fown, int sig)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(file_send_sigiotask, struct task_struct *tsk,
	 struct fown_struct *fown, int sig)

	bpf_printk("lsm_hook: file: file_send_sigiotask\n");
	return 0;
}

SEC("lsm/file_receive")
int BPF_PROG(file_receive, struct file *file)
{
	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(file_receive, struct file *file)

	DUMP_FILE_STRUCT(file)

	bpf_printk("lsm_hook: file: file_receive\n");
	return 0;
}


SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{

	FILTER_CATHEGORY_INT(FILE_CATH)
	FILTER_OWN_PID_INT()
	DUMP_FUNC(file_open, struct file *file)
	
	DUMP_FILE_STRUCT(file)

	bpf_printk("lsm_hook: file: file_open\n");
	return 0;
}



// Security hooks for task operations.

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task,
	 unsigned long clone_flags)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_alloc, struct task_struct *task,
	 unsigned long clone_flags)

	bpf_printk("lsm_hook: task: task_alloc\n");
	return 0;
}

SEC("lsm/task_free")
void BPF_PROG(task_free, struct task_struct *task)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(task_free, struct task_struct *task)

	bpf_printk("lsm_hook: task: task_free\n");
}

SEC("lsm/cred_alloc_blank")
int BPF_PROG(cred_alloc_blank, struct cred *cred, gfp_t gfp)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(cred_alloc_blank, struct cred *cred, gfp_t gfp)

	bpf_printk("lsm_hook: task: cred_alloc_blank\n");
	return 0;
}

SEC("lsm/cred_free")
void BPF_PROG(cred_free, struct cred *cred)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(cred_free, struct cred *cred)

	bpf_printk("lsm_hook: task: cred_free\n");
}

SEC("lsm/cred_prepare")
int BPF_PROG(cred_prepare, struct cred *new, const struct cred *old,
	 gfp_t gfp)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(cred_prepare, struct cred *new, const struct cred *old,
	 gfp_t gfp)


	bpf_printk("lsm_hook: task: cred_prepare\n");
	return 0;
}

SEC("lsm/cred_transfer")
void BPF_PROG(cred_transfer, struct cred *new,
	 const struct cred *old)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(cred_transfer, struct cred *new,
	 const struct cred *old)

	bpf_printk("lsm_hook: task: cred_transfer\n");
}

SEC("lsm/cred_getsecid")
void BPF_PROG(cred_getsecid, const struct cred *c, u32 *secid)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(cred_getsecid, const struct cred *c, u32 *secid)


	bpf_printk("lsm_hook: task: cred_getsecid\n");
}

SEC("lsm/kernel_act_as")
int BPF_PROG(kernel_act_as, struct cred *new, u32 secid)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(kernel_act_as, struct cred *new, u32 secid)

	bpf_printk("lsm_hook: task: kernel_act_as\n");
	return 0;
}

SEC("lsm/kernel_create_files_as")
int BPF_PROG(kernel_create_files_as, struct cred *new, struct inode *inode)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(kernel_create_files_as, struct cred *new, struct inode *inode)

	bpf_printk("lsm_hook: task: kernel_create_files_as\n");
	return 0;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(kernel_module_request, char *kmod_name)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(kernel_module_request, char *kmod_name)

	bpf_printk("lsm_hook: task: kernel_module_request\n");
	return 0;
}

SEC("lsm/kernel_load_data")
int BPF_PROG(kernel_load_data, enum kernel_load_data_id id, bool contents)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(kernel_load_data, enum kernel_load_data_id id, bool contents)

	bpf_printk("lsm_hook: task: kernel_load_data\n");
	return 0;
}

SEC("lsm/kernel_post_load_data")
int BPF_PROG(kernel_post_load_data, char *buf, loff_t size,
	 enum kernel_load_data_id id, char *description)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(kernel_post_load_data, char *buf, loff_t size,
	 enum kernel_load_data_id id, char *description)

	bpf_printk("lsm_hook: task: kernel_post_load_data\n");
	return 0;
}

SEC("lsm/kernel_read_file")
int BPF_PROG(kernel_read_file, struct file *file,
	 enum kernel_read_file_id id, bool contents)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(kernel_read_file, struct file *file,
	 enum kernel_read_file_id id, bool contents)

	bpf_printk("lsm_hook: task: kernel_read_file\n");
	return 0;
}

SEC("lsm/kernel_post_read_file")
int BPF_PROG(kernel_post_read_file, struct file *file, char *buf,
	 loff_t size, enum kernel_read_file_id id)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(kernel_post_read_file, struct file *file, char *buf,
	 loff_t size, enum kernel_read_file_id id)

	bpf_printk("lsm_hook: task: kernel_post_read_file\n");
	return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(task_fix_setuid, struct cred *new, const struct cred *old,
	 int flags)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_fix_setuid, struct cred *new, const struct cred *old,
	 int flags)

	bpf_printk("lsm_hook: task: task_fix_setuid\n");
	return 0;
}

SEC("lsm/task_fix_setgid")
int BPF_PROG(task_fix_setgid, struct cred *new, const struct cred * old,
	 int flags)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_fix_setgid, struct cred *new, const struct cred * old,
	 int flags)

	bpf_printk("lsm_hook: task: task_fix_setgid\n");
	return 0;
}

SEC("lsm/task_setpgid")
int BPF_PROG(task_setpgid, struct task_struct *p, pid_t pgid)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_setpgid, struct task_struct *p, pid_t pgid)

	bpf_printk("lsm_hook: task: task_setpgid\n");
	return 0;
}

SEC("lsm/task_getpgid")
int BPF_PROG(task_getpgid, struct task_struct *p)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_getpgid, struct task_struct *p)

	bpf_printk("lsm_hook: task: task_getpgid\n");
	return 0;
}

SEC("lsm/task_getsid")
int BPF_PROG(task_getsid, struct task_struct *p)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_getsid, struct task_struct *p)

	bpf_printk("lsm_hook: task: task_getsid\n");
	return 0;
}

SEC("lsm/task_getsecid")
void BPF_PROG(task_getsecid, struct task_struct *p, u32 *secid)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(task_getsecid, struct task_struct *p, u32 *secid)

	bpf_printk("lsm_hook: task: task_getsecid\n");
	return;
}

SEC("lsm/task_setnice")
int BPF_PROG(task_setnice, struct task_struct *p, int nice)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_setnice, struct task_struct *p, int nice)

	bpf_printk("lsm_hook: task: task_setnice\n");
	return 0;
}

SEC("lsm/task_setioprio")
int BPF_PROG(task_setioprio, struct task_struct *p, int ioprio)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_setioprio, struct task_struct *p, int ioprio)

	bpf_printk("lsm_hook: task: task_setioprio\n");
	return 0;
}

SEC("lsm/task_getioprio")
int BPF_PROG(task_getioprio, struct task_struct *p)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_getioprio, struct task_struct *p)

	bpf_printk("lsm_hook: task: task_getioprio\n");
	return 0;
}

SEC("lsm/task_prlimit")
int BPF_PROG(task_prlimit, const struct cred *cred,
	 const struct cred *tcred, unsigned int flags)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_prlimit, const struct cred *cred,
	 const struct cred *tcred, unsigned int flags)

	bpf_printk("lsm_hook: task: task_prlimit\n");
	return 0;
}

SEC("lsm/task_setrlimit")
int BPF_PROG(task_setrlimit, struct task_struct *p, unsigned int resource,
	 struct rlimit *new_rlim)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_setrlimit, struct task_struct *p, unsigned int resource,
	 struct rlimit *new_rlim)

	bpf_printk("lsm_hook: task: task_setrlimit\n");
	return 0;
}

SEC("lsm/task_setscheduler")
int BPF_PROG(task_setscheduler, struct task_struct *p)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_setscheduler, struct task_struct *p)

	bpf_printk("lsm_hook: task: task_setscheduler\n");
	return 0;
}

SEC("lsm/task_getscheduler")
int BPF_PROG(task_getscheduler, struct task_struct *p)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_getscheduler, struct task_struct *p)

	bpf_printk("lsm_hook: task: task_getscheduler\n");
	return 0;
}

SEC("lsm/task_movememory")
int BPF_PROG(task_movememory, struct task_struct *p)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_movememory, struct task_struct *p)

	bpf_printk("lsm_hook: task: task_movememory\n");
	return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(task_kill, struct task_struct *p, struct kernel_siginfo *info,
	 int sig, const struct cred *cred)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_kill, struct task_struct *p, struct kernel_siginfo *info,
	 int sig, const struct cred *cred)

	bpf_printk("lsm_hook: task: task_kill\n");
	return 0;
}

SEC("lsm/task_prctl")
int BPF_PROG(task_prctl, int option, unsigned long arg2,
	 unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(task_prctl, int option, unsigned long arg2,
	 unsigned long arg3, unsigned long arg4, unsigned long arg5)

	bpf_printk("lsm_hook: task: task_prctl\n");
	return 0;
}

SEC("lsm/task_to_inode")
void BPF_PROG(task_to_inode, struct task_struct *p,
	 struct inode *inode)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(task_to_inode, struct task_struct *p,
	 struct inode *inode)

	bpf_printk("lsm_hook: task: task_to_inode\n");
	return;
}


/* Security hooks for Netlink messaging. */

SEC("lsm/netlink_send")
int BPF_PROG(netlink_send, struct sock *sk, struct sk_buff *skb)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(netlink_send, struct sock *sk, struct sk_buff *skb)

	bpf_printk("lsm_hook: netlink: netlink_send\n");
	return 0;
}


/* Security hooks for Unix domain networking. */

SEC("lsm/unix_stream_connect")
int BPF_PROG(unix_stream_connect, struct sock *sock, struct sock *other,
	 struct sock *newsk)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(unix_stream_connect, struct sock *sock, struct sock *other,
	 struct sock *newsk)

	bpf_printk("lsm_hook: unix_domain: unix_stream_connect\n");
	return 0;
}

SEC("lsm/unix_may_send")
int BPF_PROG(unix_may_send, struct socket *sock, struct socket *other)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(unix_may_send, struct socket *sock, struct socket *other)

	bpf_printk("lsm_hook: unix_domain: unix_may_send\n");
	return 0;
}


/* Security hooks for socket operations. */

SEC("lsm/socket_create")
int BPF_PROG(socket_create, int family, int type, int protocol, int kern)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_create, int family, int type, int protocol, int kern)

	bpf_printk("lsm_hook: socket: socket_create\n");
	return 0;
}

SEC("lsm/socket_post_create")
int BPF_PROG(socket_post_create, struct socket *sock, int family, int type,
	 int protocol, int kern)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_post_create, struct socket *sock, int family, int type,
	 int protocol, int kern)

	bpf_printk("lsm_hook: socket: socket_post_create\n");
	return 0;
}

SEC("lsm/socket_socketpair")
int BPF_PROG(socket_socketpair, struct socket *socka, struct socket *sockb)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_socketpair, struct socket *socka, struct socket *sockb)

	bpf_printk("lsm_hook: socket: socket_socketpair\n");
	return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address,
	 int addrlen)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_bind, struct socket *sock, struct sockaddr *address,
	 int addrlen)

	bpf_printk("lsm_hook: socket: socket_bind\n");
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address,
	 int addrlen)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_connect, struct socket *sock, struct sockaddr *address,
	 int addrlen)

	bpf_printk("lsm_hook: socket: socket_connect\n");
	return 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(socket_listen, struct socket *sock, int backlog)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_listen, struct socket *sock, int backlog)

	bpf_printk("lsm_hook: socket: socket_listen\n");
	return 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(socket_accept, struct socket *sock, struct socket *newsock)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_accept, struct socket *sock, struct socket *newsock)

	bpf_printk("lsm_hook: socket: socket_accept\n");
	return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(socket_sendmsg, struct socket *sock, struct msghdr *msg,
	 int size)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_sendmsg, struct socket *sock, struct msghdr *msg,
	 int size)

	bpf_printk("lsm_hook: socket: socket_sendmsg\n");
	return 0;
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(socket_recvmsg, struct socket *sock, struct msghdr *msg,
	 int size, int flags)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_recvmsg, struct socket *sock, struct msghdr *msg,
	 int size, int flags)

	bpf_printk("lsm_hook: socket: socket_recvmsg\n");
	return 0;
}

SEC("lsm/socket_getsockname")
int BPF_PROG(socket_getsockname, struct socket *sock)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_getsockname, struct socket *sock)

	bpf_printk("lsm_hook: socket: socket_getsockname\n");
	return 0;
}

SEC("lsm/socket_getpeername")
int BPF_PROG(socket_getpeername, struct socket *sock)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_getpeername, struct socket *sock)

	bpf_printk("lsm_hook: socket: socket_getpeername\n");
	return 0;
}

SEC("lsm/socket_getsockopt")
int BPF_PROG(socket_getsockopt, struct socket *sock, int level, int optname)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_getsockopt, struct socket *sock, int level, int optname)

	bpf_printk("lsm_hook: socket: socket_getsockopt\n");
	return 0;
}

SEC("lsm/socket_setsockopt")
int BPF_PROG(socket_setsockopt, struct socket *sock, int level, int optname)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_setsockopt, struct socket *sock, int level, int optname)

	bpf_printk("lsm_hook: socket: socket_setsockopt\n");
	return 0;
}

SEC("lsm/socket_shutdown")
int BPF_PROG(socket_shutdown, struct socket *sock, int how)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_shutdown, struct socket *sock, int how)

	bpf_printk("lsm_hook: socket: socket_shutdown\n");
	return 0;
}

SEC("lsm/socket_sock_rcv_skb")
int BPF_PROG(socket_sock_rcv_skb, struct sock *sk, struct sk_buff *skb)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_sock_rcv_skb, struct sock *sk, struct sk_buff *skb)

	bpf_printk("lsm_hook: socket: socket_sock_rcv_skb\n");
	return 0;
}

//SEC("lsm/socket_getpeersec_stream")
//int BPF_PROG(socket_getpeersec_stream, struct socket *sock,
//	 char __user *optval, int __user *optlen, unsigned len)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(socket_getpeersec_stream, struct socket *sock,
//	 char __user *optval, int __user *optlen, unsigned len)
//
//	bpf_printk("lsm_hook: socket: socket_getpeersec_stream\n");
//	return 0;
//}

SEC("lsm/socket_getpeersec_dgram")
int BPF_PROG(socket_getpeersec_dgram, struct socket *sock,
	 struct sk_buff *skb, u32 *secid)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(socket_getpeersec_dgram, struct socket *sock,
	 struct sk_buff *skb, u32 *secid)

	bpf_printk("lsm_hook: socket: socket_getpeersec_dgram\n");
	return 0;
}

SEC("lsm/sk_alloc_security")
int BPF_PROG(sk_alloc_security, struct sock *sk, int family, gfp_t priority)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sk_alloc_security, struct sock *sk, int family, gfp_t priority)

	bpf_printk("lsm_hook: socket: sk_alloc_security\n");
	return 0;
}

SEC("lsm/sk_free_security")
void BPF_PROG(sk_free_security, struct sock *sk)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(sk_free_security, struct sock *sk)

	bpf_printk("lsm_hook: socket: sk_free_security\n");
	return;
}

SEC("lsm/sk_clone_security")
void BPF_PROG(sk_clone_security, const struct sock *sk,
	 struct sock *newsk)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(sk_clone_security, const struct sock *sk,
	 struct sock *newsk)

	bpf_printk("lsm_hook: socket: sk_clone_security\n");
	return;
}

SEC("lsm/sk_getsecid")
void BPF_PROG(sk_getsecid, struct sock *sk, u32 *secid)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(sk_getsecid, struct sock *sk, u32 *secid)

	bpf_printk("lsm_hook: socket: sk_getsecid\n");
	return;
}

SEC("lsm/sock_graft")
void BPF_PROG(sock_graft, struct sock *sk, struct socket *parent)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(sock_graft, struct sock *sk, struct socket *parent)

	bpf_printk("lsm_hook: socket: sock_graft\n");
	return;
}

SEC("lsm/inet_conn_request")
int BPF_PROG(inet_conn_request, struct sock *sk, struct sk_buff *skb,
	 struct request_sock *req)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inet_conn_request, struct sock *sk, struct sk_buff *skb,
	 struct request_sock *req)

	bpf_printk("lsm_hook: socket: inet_conn_request\n");
	return 0;
}

SEC("lsm/inet_csk_clone")
void BPF_PROG(inet_csk_clone, struct sock *newsk,
	 const struct request_sock *req)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(inet_csk_clone, struct sock *newsk,
	 const struct request_sock *req)

	bpf_printk("lsm_hook: socket: inet_csk_clone\n");
	return;
}

SEC("lsm/inet_conn_established")
void BPF_PROG(inet_conn_established, struct sock *sk,
	 struct sk_buff *skb)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(inet_conn_established, struct sock *sk,
	 struct sk_buff *skb)

	bpf_printk("lsm_hook: socket: inet_conn_established\n");
	return;
}

SEC("lsm/secmark_relabel_packet")
int BPF_PROG(secmark_relabel_packet, u32 secid)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(secmark_relabel_packet, u32 secid)

	bpf_printk("lsm_hook: socket: secmark_relabel_packet\n");
	return 0;
}

SEC("lsm/secmark_refcount_inc")
void BPF_PROG(secmark_refcount_inc)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(secmark_refcount_inc)

	bpf_printk("lsm_hook: socket: secmark_relabel_packet\n");
	return;
}

SEC("lsm/secmark_refcount_dec")
void BPF_PROG(secmark_refcount_dec)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(secmark_refcount_dec)

	bpf_printk("lsm_hook: socket: secmark_refcount_dec\n");
	return;
}

SEC("lsm/req_classify_flow")
void BPF_PROG(req_classify_flow, const struct request_sock *req,
	 struct flowi *fl)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(req_classify_flow)

	bpf_printk("lsm_hook: socket: req_classify_flow\n");
	return;
}

SEC("lsm/tun_dev_alloc_security")
int BPF_PROG(tun_dev_alloc_security, void **security)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(tun_dev_alloc_security, void **security)

	bpf_printk("lsm_hook: socket: tun_dev_alloc_security\n");
	return 0;
}

SEC("lsm/tun_dev_free_security")
void BPF_PROG(tun_dev_free_security, void *security)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(tun_dev_free_security, void *security)

	bpf_printk("lsm_hook: socket: tun_dev_free_security\n");
	return;
}

SEC("lsm/tun_dev_create")
int BPF_PROG(tun_dev_create)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(tun_dev_create)

	bpf_printk("lsm_hook: socket: tun_dev_create\n");
	return 0;
}

SEC("lsm/tun_dev_attach_queue")
int BPF_PROG(tun_dev_attach_queue, void *security)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(tun_dev_attach_queue, void *security)

	bpf_printk("lsm_hook: socket: tun_dev_attach_queue\n");
	return 0;
}

SEC("lsm/tun_dev_attach")
int BPF_PROG(tun_dev_attach, struct sock *sk, void *security)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(tun_dev_attach, struct sock *sk, void *security)

	bpf_printk("lsm_hook: socket: tun_dev_attach\n");
	return 0;
}

SEC("lsm/tun_dev_open")
int BPF_PROG(tun_dev_open, void *security)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(tun_dev_open, void *security)

	bpf_printk("lsm_hook: socket: tun_dev_open\n");
	return 0;
}


/* Security hooks for SCTP */

SEC("lsm/tun_dev_open")
int BPF_PROG(sctp_assoc_request, struct sctp_endpoint *ep,
	 struct sk_buff *skb)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sctp_assoc_request, struct sctp_endpoint *ep,
	 struct sk_buff *skb)

	bpf_printk("lsm_hook: sctp: sctp_assoc_request\n");
	return 0;
}

SEC("lsm/sctp_bind_connect")
int BPF_PROG(sctp_bind_connect, struct sock *sk, int optname,
	 struct sockaddr *address, int addrlen)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sctp_bind_connect, struct sock *sk, int optname,
	 struct sockaddr *address, int addrlen)

	bpf_printk("lsm_hook: sctp: sctp_bind_connect\n");
	return 0;
}

SEC("lsm/sctp_sk_clone")
void BPF_PROG(sctp_sk_clone, struct sctp_endpoint *ep,
	 struct sock *sk, struct sock *newsk)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(sctp_sk_clone, struct sctp_endpoint *ep,
	 struct sock *sk, struct sock *newsk)

	bpf_printk("lsm_hook: sctp: sctp_sk_clone\n");
	return;
}



/* Security hooks for Infiniband */


SEC("lsm/sctp_sk_clone")
int BPF_PROG(ib_pkey_access, void *sec, u64 subnet_prefix, u16 pkey)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(ib_pkey_access, void *sec, u64 subnet_prefix, u16 pkey)

	bpf_printk("lsm_hook: infiniband: ib_pkey_access\n");
	return 0;
}

SEC("lsm/ib_endport_manage_subnet")
int BPF_PROG(ib_endport_manage_subnet, void *sec, const char *dev_name,
	 u8 port_num)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(ib_endport_manage_subnet, void *sec, const char *dev_name,
	 u8 port_num)

	bpf_printk("lsm_hook: infiniband: ib_endport_manage_subnet\n");
	return 0;
}

SEC("lsm/ib_alloc_security")
int BPF_PROG(ib_alloc_security, void **sec)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(ib_alloc_security, void **sec)

	bpf_printk("lsm_hook: infiniband: ib_alloc_security\n");
	return 0;
}

SEC("lsm/ib_free_security")
void BPF_PROG(ib_free_security, void *sec)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(ib_free_security, void *sec)

	bpf_printk("lsm_hook: infiniband: ib_free_security\n");
	return;
}



/* Security hooks for XFRM operations. */

SEC("lsm/xfrm_policy_alloc_security")
int BPF_PROG(xfrm_policy_alloc_security, struct xfrm_sec_ctx **ctxp,
	 struct xfrm_user_sec_ctx *sec_ctx, gfp_t gfp)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(xfrm_policy_alloc_security, struct xfrm_sec_ctx **ctxp,
	 struct xfrm_user_sec_ctx *sec_ctx, gfp_t gfp)

	bpf_printk("lsm_hook: xfrm: xfrm_policy_alloc_security\n");
	return 0;
}

SEC("lsm/xfrm_policy_clone_security")
int BPF_PROG(xfrm_policy_clone_security, struct xfrm_sec_ctx *old_ctx,
	 struct xfrm_sec_ctx **new_ctx)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(xfrm_policy_clone_security, struct xfrm_sec_ctx *old_ctx,
	 struct xfrm_sec_ctx **new_ctx)

	bpf_printk("lsm_hook: xfrm: xfrm_policy_clone_security\n");
	return 0;
}

SEC("lsm/xfrm_policy_free_security")
void BPF_PROG(xfrm_policy_free_security, struct xfrm_sec_ctx *xfrm_ctx)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(xfrm_policy_free_security, struct xfrm_sec_ctx *xfrm_ctx)

	bpf_printk("lsm_hook: xfrm: xfrm_policy_clone_security\n");
	return;
}

SEC("lsm/xfrm_policy_delete_security")
int BPF_PROG(xfrm_policy_delete_security, struct xfrm_sec_ctx *xfrm_ctx)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(xfrm_policy_delete_security, struct xfrm_sec_ctx *xfrm_ctx)

	bpf_printk("lsm_hook: xfrm: xfrm_policy_delete_security\n");
	return 0;
}

SEC("lsm/xfrm_state_alloc")
int BPF_PROG(xfrm_state_alloc, struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(xfrm_state_alloc, struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx)

	bpf_printk("lsm_hook: xfrm: xfrm_state_alloc\n");
	return 0;
}

SEC("lsm/xfrm_state_alloc_acquire")
int BPF_PROG(xfrm_state_alloc_acquire, struct xfrm_state *x,
	 struct xfrm_sec_ctx *polsec, u32 secid)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(xfrm_state_alloc_acquire, struct xfrm_state *x,
	 struct xfrm_sec_ctx *polsec, u32 secid)

	bpf_printk("lsm_hook: xfrm: xfrm_state_alloc_acquire\n");
	return 0;
}

SEC("lsm/xfrm_state_free_security")
void BPF_PROG(xfrm_state_free_security, struct xfrm_state *x)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(xfrm_state_free_security, struct xfrm_state *x)

	bpf_printk("lsm_hook: xfrm: xfrm_state_alloc_acquire\n");
	return;
}

SEC("lsm/xfrm_state_delete_security")
int BPF_PROG(xfrm_state_delete_security, struct xfrm_state *x)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(xfrm_state_delete_security, struct xfrm_state *x)

	bpf_printk("lsm_hook: xfrm: xfrm_state_delete_security\n");
	return 0;
}

SEC("lsm/xfrm_policy_lookup")
int BPF_PROG(xfrm_policy_lookup, struct xfrm_sec_ctx *xfrm_ctx, u32 fl_secid,
	 u8 dir)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(xfrm_policy_lookup, struct xfrm_sec_ctx *xfrm_ctx, u32 fl_secid,
	 u8 dir)

	bpf_printk("lsm_hook: xfrm: xfrm_policy_lookup\n");
	return 0;
}

SEC("lsm/xfrm_state_pol_flow_match")
int BPF_PROG(xfrm_state_pol_flow_match, struct xfrm_state *x,
	 struct xfrm_policy *xp, const struct flowi *fl)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(xfrm_state_pol_flow_match, struct xfrm_state *x,
	 struct xfrm_policy *xp, const struct flowi *fl)

	bpf_printk("lsm_hook: xfrm: xfrm_state_pol_flow_match\n");
	return 0;
}

SEC("lsm/xfrm_state_pol_flow_match")
int BPF_PROG(xfrm_decode_session, struct sk_buff *skb, u32 *secid,
	 int ckall)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(xfrm_decode_session, struct sk_buff *skb, u32 *secid,
	 int ckall)

	bpf_printk("lsm_hook: xfrm: xfrm_decode_session\n");
	return 0;
}


/* Security hooks affecting all Key Management operations */


SEC("lsm/key_alloc")
int BPF_PROG(key_alloc, struct key *key, const struct cred *cred,
	 unsigned long flags)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(key_alloc, struct key *key, const struct cred *cred,
	 unsigned long flags)

	bpf_printk("lsm_hook: key_management: key_alloc\n");
	return 0;
}

SEC("lsm/key_free")
void BPF_PROG(key_free, struct key *key)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(key_free, struct key *key)

	bpf_printk("lsm_hook: key_management: key_free\n");
	return;
}

SEC("lsm/key_permission")
int BPF_PROG(key_permission, key_ref_t key_ref, const struct cred *cred,
	 enum key_need_perm need_perm)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(key_permission, key_ref_t key_ref, const struct cred *cred,
	 enum key_need_perm need_perm)

	bpf_printk("lsm_hook: key_management: key_permission\n");
	return 0;
}

SEC("lsm/key_getsecurity")
int BPF_PROG(key_getsecurity, struct key *key, char **_buffer)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(key_getsecurity, struct key *key, char **_buffer)

	bpf_printk("lsm_hook: key_management: key_getsecurity\n");
	return 0;
}



/* Security hooks affecting all System V IPC operations. */

SEC("lsm/msg_msg_alloc_security")
int BPF_PROG(msg_msg_alloc_security, struct msg_msg *msg)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(msg_msg_alloc_security, struct msg_msg *msg)

	bpf_printk("lsm_hook: systemv_ipc: msg_msg_alloc_security\n");
	return 0;
}

SEC("lsm/msg_msg_free_security")
void BPF_PROG(msg_msg_free_security, struct msg_msg *msg)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(msg_msg_free_security, struct msg_msg *msg)

	bpf_printk("lsm_hook: systemv_ipc: msg_msg_free_security\n");
	return;
}


/* Security hooks for System V IPC Message Queues */


SEC("lsm/msg_queue_alloc_security")
int BPF_PROG(msg_queue_alloc_security, struct kern_ipc_perm *perm)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(msg_queue_alloc_security, struct msg_msg *msg)

	bpf_printk("lsm_hook: systemv_ipc_msgqueue: msg_queue_alloc_security\n");
	return 0;
}

SEC("lsm/msg_queue_free_security")
void BPF_PROG(msg_queue_free_security, struct kern_ipc_perm *perm)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(msg_queue_free_security, struct kern_ipc_perm *perm)

	bpf_printk("lsm_hook: systemv_ipc_msgqueue: msg_queue_free_security\n");
	return;
}

SEC("lsm/msg_queue_associate")
int BPF_PROG(msg_queue_associate, struct kern_ipc_perm *perm, int msqflg)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(msg_queue_associate, struct kern_ipc_perm *perm, int msqflg)

	bpf_printk("lsm_hook: systemv_ipc_msgqueue: msg_queue_associate\n");
	return 0;
}

SEC("lsm/msg_queue_msgctl")
int BPF_PROG(msg_queue_msgctl, struct kern_ipc_perm *perm, int cmd)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(msg_queue_msgctl, struct kern_ipc_perm *perm, int cmd)

	bpf_printk("lsm_hook: systemv_ipc_msgqueue: msg_queue_msgctl\n");
	return 0;
}

SEC("lsm/msg_queue_msgsnd")
int BPF_PROG(msg_queue_msgsnd, struct kern_ipc_perm *perm,
	 struct msg_msg *msg, int msqflg)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(msg_queue_msgsnd, struct kern_ipc_perm *perm,
	 struct msg_msg *msg, int msqflg)

	bpf_printk("lsm_hook: systemv_ipc_msgqueue: msg_queue_msgsnd\n");
	return 0;
}

SEC("lsm/msg_queue_msgrcv")
int BPF_PROG(msg_queue_msgrcv, struct kern_ipc_perm *perm,
	 struct msg_msg *msg, struct task_struct *target, long type, int mode)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(msg_queue_msgrcv, struct kern_ipc_perm *perm,
	 struct msg_msg *msg, struct task_struct *target, long type, int mode)

	bpf_printk("lsm_hook: systemv_ipc_msgqueue: msg_queue_msgrcv\n");
	return 0;
}


/* Security hooks for System V Shared Memory Segments */

SEC("lsm/shm_alloc_security")
int BPF_PROG(shm_alloc_security, struct kern_ipc_perm *perm)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(shm_alloc_security, struct kern_ipc_perm *perm)

	bpf_printk("lsm_hook: systemv_ipc_shmem: shm_alloc_security\n");
	return 0;
}

SEC("lsm/shm_free_security")
void BPF_PROG(shm_free_security, struct kern_ipc_perm *perm)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(shm_free_security, struct kern_ipc_perm *perm)

	bpf_printk("lsm_hook: systemv_ipc_shmem: shm_free_security\n");
	return;
}

SEC("lsm/shm_associate")
int BPF_PROG(shm_associate, struct kern_ipc_perm *perm, int shmflg)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(shm_associate, struct kern_ipc_perm *perm, int shmflg)

	bpf_printk("lsm_hook: systemv_ipc_shmem: shm_associate\n");
	return 0;
}

SEC("lsm/shm_shmctl")
int BPF_PROG(shm_shmctl, struct kern_ipc_perm *perm, int cmd)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(shm_shmctl, struct kern_ipc_perm *perm, int cmd)

	bpf_printk("lsm_hook: systemv_ipc_shmem: shm_shmctl\n");
	return 0;
}

//SEC("lsm/shm_shmat")
//int BPF_PROG(shm_shmat, struct kern_ipc_perm *perm, char __user *shmaddr,
//	 int shmflg)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(shm_shmat, struct kern_ipc_perm *perm, char __user *shmaddr,
//	 int shmflg)
//
//	bpf_printk("lsm_hook: systemv_ipc_shmem: shm_shmat\n");
//	return 0;
//}



/* Security hooks for System V Semaphores */

SEC("lsm/sem_alloc_security")
int BPF_PROG(sem_alloc_security, struct kern_ipc_perm *perm)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sem_alloc_security, struct kern_ipc_perm *perm)

	bpf_printk("lsm_hook: systemv_ipc_shmem: sem_alloc_security\n");
	return 0;
}

SEC("lsm/sem_free_security")
void BPF_PROG(sem_free_security, struct kern_ipc_perm *perm)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(sem_free_security, struct kern_ipc_perm *perm)

	bpf_printk("lsm_hook: systemv_ipc_shmem: sem_free_security\n");
	return;
}

SEC("lsm/sem_associate")
int BPF_PROG(sem_associate, struct kern_ipc_perm *perm, int semflg)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sem_associate, struct kern_ipc_perm *perm, int semflg)

	bpf_printk("lsm_hook: systemv_ipc_shmem: sem_associate\n");
	return 0;
}

SEC("lsm/sem_semctl")
int BPF_PROG(sem_semctl, struct kern_ipc_perm *perm, int cmd)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sem_semctl, struct kern_ipc_perm *perm, int cmd)

	bpf_printk("lsm_hook: systemv_ipc_shmem: sem_semctl\n");
	return 0;
}

SEC("lsm/sem_semop")
int BPF_PROG(sem_semop, struct kern_ipc_perm *perm, struct sembuf *sops,
	 unsigned nsops, int alter)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(sem_semop, struct kern_ipc_perm *perm, struct sembuf *sops,
	 unsigned nsops, int alter)

	bpf_printk("lsm_hook: systemv_ipc_shmem: sem_semop\n");
	return 0;
}

SEC("lsm/binder_set_context_mgr")
int BPF_PROG(binder_set_context_mgr, struct task_struct *mgr)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(binder_set_context_mgr, struct task_struct *mgr)

	bpf_printk("lsm_hook: systemv_ipc_shmem: binder_set_context_mgr\n");
	return 0;
}

SEC("lsm/binder_transaction")
int BPF_PROG(binder_transaction, struct task_struct *from,
	 struct task_struct *to)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(binder_transaction, struct task_struct *from,
	 struct task_struct *to)

	bpf_printk("lsm_hook: systemv_ipc_shmem: binder_transaction\n");
	return 0;
}

SEC("lsm/binder_transfer_binder")
int BPF_PROG(binder_transfer_binder, struct task_struct *from,
	 struct task_struct *to)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(binder_transfer_binder, struct task_struct *from,
	 struct task_struct *to)

	bpf_printk("lsm_hook: systemv_ipc_shmem: binder_transfer_binder\n");
	return 0;
}

SEC("lsm/binder_transfer_file")
int BPF_PROG(binder_transfer_file, struct task_struct *from,
	 struct task_struct *to, struct file *file)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(binder_transfer_file, struct task_struct *from,
	 struct task_struct *to, struct file *file)

	bpf_printk("lsm_hook: systemv_ipc_shmem: binder_transfer_file\n");
	return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child,
	 unsigned int mode)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(ptrace_access_check, struct task_struct *child,
	 unsigned int mode)

	bpf_printk("lsm_hook: systemv_ipc_shmem: ptrace_access_check\n");
	return 0;
}

SEC("lsm/ptrace_traceme")
int BPF_PROG(ptrace_traceme, struct task_struct *parent)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(ptrace_traceme, struct task_struct *parent)

	bpf_printk("lsm_hook: systemv_ipc_shmem: ptrace_traceme\n");
	return 0;
}

SEC("lsm/capget")
int BPF_PROG(capget, struct task_struct *target, kernel_cap_t *effective,
	 kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(capget, struct task_struct *target, kernel_cap_t *effective,
	 kernel_cap_t *inheritable, kernel_cap_t *permitted)

	bpf_printk("lsm_hook: systemv_ipc_shmem: capget\n");
	return 0;
}

SEC("lsm/capset")
int BPF_PROG(capset, struct cred *new, const struct cred *old,
	 const kernel_cap_t *effective, const kernel_cap_t *inheritable,
	 const kernel_cap_t *permitted)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(capset, struct cred *new, const struct cred *old,
	 const kernel_cap_t *effective, const kernel_cap_t *inheritable,
	 const kernel_cap_t *permitted)

	bpf_printk("lsm_hook: systemv_ipc_shmem: capset\n");
	return 0;
}

SEC("lsm/capable")
int BPF_PROG(capable, const struct cred *cred, struct user_namespace *ns,
	 int cap, unsigned int opts)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(capable, const struct cred *cred, struct user_namespace *ns,
	 int cap, unsigned int opts)

	bpf_printk("lsm_hook: systemv_ipc_shmem: capable\n");
	return 0;
}

SEC("lsm/quotactl")
int BPF_PROG(quotactl, int cmds, int type, int id, struct super_block *sb)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(quotactl, int cmds, int type, int id, struct super_block *sb)

	bpf_printk("lsm_hook: systemv_ipc_shmem: quotactl\n");
	return 0;
}

SEC("lsm/quota_on")
int BPF_PROG(quota_on, struct dentry *dentry)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(quota_on, struct dentry *dentry)

	bpf_printk("lsm_hook: systemv_ipc_shmem: quota_on\n");
	return 0;
}

SEC("lsm/syslog")
int BPF_PROG(syslog, int type)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(syslog, int type)

	bpf_printk("lsm_hook: systemv_ipc_shmem: syslog\n");
	return 0;
}

SEC("lsm/settime")
int BPF_PROG(settime, const struct timespec64 *ts,
	 const struct timezone *tz)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(settime, const struct timespec64 *ts,
	 const struct timezone *tz)

	bpf_printk("lsm_hook: systemv_ipc_shmem: settime\n");
	return 0;
}

SEC("lsm/vm_enough_memory")
int BPF_PROG(vm_enough_memory, struct mm_struct *mm, long pages)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(vm_enough_memory, struct mm_struct *mm, long pages)

	bpf_printk("lsm_hook: systemv_ipc_shmem: vm_enough_memory\n");
	return 0;
}

SEC("lsm/ismaclabel")
int BPF_PROG(ismaclabel, const char *name)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(ismaclabel, const char *name)

	bpf_printk("lsm_hook: systemv_ipc_shmem: ismaclabel\n");
	return 0;
}

SEC("lsm/secid_to_secctx")
int BPF_PROG(secid_to_secctx, u32 secid, char **secdata,
	 u32 *seclen)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(secid_to_secctx, u32 secid, char **secdata,
	 u32 *seclen)

	bpf_printk("lsm_hook: systemv_ipc_shmem: secid_to_secctx\n");
	return 0;
}

SEC("lsm/secctx_to_secid")
int BPF_PROG(secctx_to_secid, const char *secdata, u32 seclen, u32 *secid)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(secctx_to_secid, const char *secdata, u32 seclen, u32 *secid)

	bpf_printk("lsm_hook: systemv_ipc_shmem: secctx_to_secid\n");
	return 0;
}

SEC("lsm/release_secctx")
void BPF_PROG(release_secctx, char *secdata, u32 seclen)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(release_secctx, char *secdata, u32 seclen)

	bpf_printk("lsm_hook: systemv_ipc_shmem: release_secctx\n");
	return;
}


/* Security hooks for Audit */

SEC("lsm/audit_rule_init")
int BPF_PROG(audit_rule_init, u32 field, u32 op, char *rulestr,
	 void **lsmrule)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(audit_rule_init, u32 field, u32 op, char *rulestr,
	 void **lsmrule)

	bpf_printk("lsm_hook: audit: audit_rule_init\n");
	return 0;
}

SEC("lsm/audit_rule_known")
int BPF_PROG(audit_rule_known, struct audit_krule *krule)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(audit_rule_known, struct audit_krule *krule)

	bpf_printk("lsm_hook: audit: audit_rule_known\n");
	return 0;
}

SEC("lsm/audit_rule_match")
int BPF_PROG(audit_rule_match, u32 secid, u32 field, u32 op, void *lsmrule)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(audit_rule_match, u32 secid, u32 field, u32 op, void *lsmrule)

	bpf_printk("lsm_hook: audit: audit_rule_match\n");
	return 0;
}

SEC("lsm/audit_rule_free")
void BPF_PROG(audit_rule_free, void *lsmrule)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(audit_rule_free, void *lsmrule)

	bpf_printk("lsm_hook: audit: audit_rule_free\n");
	return;
}

SEC("lsm/inode_invalidate_secctx")
void BPF_PROG(inode_invalidate_secctx, struct inode *inode)
{
	FILTER_OWN_PID_VOID()
	DUMP_FUNC(inode_invalidate_secctx, struct inode *inode)

	bpf_printk("lsm_hook: audit: inode_invalidate_secctx\n");
	return;
}

SEC("lsm/inode_notifysecctx")
int BPF_PROG(inode_notifysecctx, struct inode *inode, void *void_ctx, u32 ctxlen)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_notifysecctx, struct inode *inode, void *void_ctx, u32 ctxlen)

	bpf_printk("lsm_hook: audit: inode_notifysecctx\n");
	return 0;
}

SEC("lsm/inode_setsecctx")
int BPF_PROG(inode_setsecctx, struct dentry *dentry, void *void_ctx, u32 ctxlen)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_setsecctx, struct dentry *dentry, void *void_ctx, u32 ctxlen)

	bpf_printk("lsm_hook: audit: inode_setsecctx\n");
	return 0;
}

SEC("lsm/inode_getsecctx")
int BPF_PROG(inode_getsecctx, struct inode *inode, void **void_ctx,
	 u32 *ctxlen)
{
	FILTER_OWN_PID_INT()
	DUMP_FUNC(inode_getsecctx, struct inode *inode, void **void_ctx,
	 u32 *ctxlen)

	bpf_printk("lsm_hook: audit: inode_getsecctx\n");
	return 0;
}


///* Security hooks for the general notification queue: */
//
//
//SEC("lsm/post_notification")
//int BPF_PROG(post_notification, const struct cred *w_cred,
//	 const struct cred *cred, struct watch_notification *n)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(post_notification, const struct cred *w_cred,
//	 const struct cred *cred, struct watch_notification *n)
//
//	bpf_printk("lsm_hook: notification_queue: post_notification\n");
//	return 0;
//}
//
//SEC("lsm/watch_key")
//int BPF_PROG(watch_key, struct key *key)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(watch_key, struct key *key)
//
//	bpf_printk("lsm_hook: notification_queue: watch_key\n");
//	return 0;
//}
//
//
///* Security hooks for using the eBPF maps and programs functionalities through 
//  eBPF syscalls. */
//
//SEC("lsm/bpf")
//int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(bpf, int cmd, union bpf_attr *attr, unsigned int size)
//
//	bpf_printk("lsm_hook: bpf: bpf\n");
//	return 0;
//}
//
//SEC("lsm/bpf_map")
//int BPF_PROG(bpf_map, struct bpf_map *map, fmode_t fmode)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(bpf_map, struct bpf_map *map, fmode_t fmode)
//
//	bpf_printk("lsm_hook: bpf: bpf_map\n");
//	return 0;
//}
//
//SEC("lsm/bpf_prog")
//int BPF_PROG(bpf_prog, struct bpf_prog *prog)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(bpf_prog, struct bpf_prog *prog)
//
//	bpf_printk("lsm_hook: bpf: bpf_prog\n");
//	return 0;
//}
//
//SEC("lsm/bpf_map_alloc_security")
//int BPF_PROG(bpf_map_alloc_security, struct bpf_map *map)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(bpf_map_alloc_security, struct bpf_map *map)
//
//	bpf_printk("lsm_hook: bpf: bpf_map_alloc_security\n");
//	return 0;
//}
//
//SEC("lsm/bpf_map_free_security")
//void BPF_PROG(bpf_map_free_security, struct bpf_map *map)
//{
//	FILTER_OWN_PID_VOID()
//	DUMP_FUNC(bpf_map_free_security, struct bpf_map *map)
//
//	bpf_printk("lsm_hook: bpf: bpf_map_alloc_security\n");
//	return;
//}
//
//SEC("lsm/bpf_prog_alloc_security")
//int BPF_PROG(bpf_prog_alloc_security, struct bpf_prog_aux *aux)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(bpf_prog_alloc_security, struct bpf_prog_aux *aux)
//
//	bpf_printk("lsm_hook: bpf: bpf_prog_alloc_security\n");
//	return 0;
//}
//
//SEC("lsm/bpf_prog_free_security")
//void BPF_PROG(bpf_prog_free_security, struct bpf_prog_aux *aux)
//{
//	FILTER_OWN_PID_VOID()
//	DUMP_FUNC(bpf_prog_free_security, struct bpf_prog_aux *aux)
//
//	bpf_printk("lsm_hook: bpf: bpf_prog_free_security\n");
//	return;
//}
//
//SEC("lsm/locked_down")
//int BPF_PROG(locked_down, enum lockdown_reason what)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(locked_down, enum lockdown_reason what)
//
//	bpf_printk("lsm_hook: bpf: locked_down\n");
//	return 0;
//}
//
//
///* Security hooks for perf events */
//
//SEC("lsm/perf_event_open")
//int BPF_PROG(perf_event_open, struct perf_event_attr *attr, int type)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(perf_event_open, struct perf_event_attr *attr, int type)
//
//	bpf_printk("lsm_hook: perf_events: perf_event_open\n");
//	return 0;
//}
//
//SEC("lsm/perf_event_alloc")
//int BPF_PROG(perf_event_alloc, struct perf_event *event)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(perf_event_alloc, struct perf_event *event)
//
//	bpf_printk("lsm_hook: perf_events: perf_event_alloc\n");
//	return 0;
//}
//
//SEC("lsm/perf_event_free")
//void BPF_PROG(perf_event_free, struct perf_event *event)
//{
//	FILTER_OWN_PID_VOID()
//	DUMP_FUNC(perf_event_free, struct perf_event *event)
//
//	bpf_printk("lsm_hook: perf_events: perf_event_free\n");
//	return;
//}
//
//SEC("lsm/perf_event_read")
//int BPF_PROG(perf_event_read, struct perf_event *event)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(perf_event_read, struct perf_event *event)
//
//	bpf_printk("lsm_hook: perf_events: perf_event_read\n");
//	return 0;
//}
//
//SEC("lsm/perf_event_write")
//int BPF_PROG(perf_event_write, struct perf_event *event)
//{
//	FILTER_OWN_PID_INT()
//	DUMP_FUNC(perf_event_write, struct perf_event *event)
//
//	bpf_printk("lsm_hook: perf_events: perf_event_write\n");
//	return 0;
//}














char _license[] SEC("license") = "GPL";


// Not implemented:
// sb_copy_data
// sb_parse_opts_str
// chown

