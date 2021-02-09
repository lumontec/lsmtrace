//   Copyright 2020 (C) Luca Montechiesi <lucamontechiesi@gmail.com>
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

#ifndef __BPF_STRUCT_HELPERS_H
#define __BPF_STRUCT_HELPERS_H

#include "vmlinux.h"
#include "bpf_dump_helpers.h"

/* linux_binprm */
#define DUMP_LINUX_BINPRM_STRUCT(...) {					\
	DUMP_FILE_STRUCT(__VA_ARGS__,executable)			\
	DUMP_FILE_STRUCT(__VA_ARGS__,interpreter)			\
	DUMP_FILE_STRUCT(__VA_ARGS__,file)				\
	DUMP_MEMBER_STR (__VA_ARGS__,filename)				\
	DUMP_MEMBER_STR (__VA_ARGS__,interp)				\
	DUMP_MEMBER_STR (__VA_ARGS__,fdpath)				\
	DUMP_MEMBER_UINT(__VA_ARGS__,interp_flags)			\
}

/* file */
#define DUMP_FILE_STRUCT(...) {						\
/*	DUMP_MEMBER_LLINT(__VA_ARGS__,f_pos)		*/		\
	DUMP_MEMBER_UINT(__VA_ARGS__,f_mode)				\
	DUMP_DENTRY_STRUCT(__VA_ARGS__,f_path.dentry)			\
}	

/* dentry */
#define DUMP_DENTRY_STRUCT(...) {					\
	DUMP_MEMBER_UINT(__VA_ARGS__,d_flags)				\
	DUMP_MEMBER_USTR (__VA_ARGS__,d_name.name)			\
	DUMP_INODE_STRUCT (__VA_ARGS__,d_inode)				\
}									\
									\

/* inode */
#define DUMP_INODE_STRUCT(...) {					\
	DUMP_MEMBER_LUINT(__VA_ARGS__,i_ino)				\
	DUMP_MEMBER_SUINT(__VA_ARGS__,i_mode)				\
	DUMP_MEMBER_UINT(__VA_ARGS__,i_flags)				\
	DUMP_MEMBER_LLINT(__VA_ARGS__,i_size)				\
	DUMP_MEMBER_UINT(__VA_ARGS__,i_uid.val)				\
	DUMP_MEMBER_UINT(__VA_ARGS__,i_gid.val)				\
/*	DUMP_MEMBER_UINT(__VA_ARGS__,i_nlink)		*/		\
/*	DUMP_MEMBER_LLINT(__VA_ARGS__,i_atime.tv_sec)			\
	DUMP_MEMBER_LLINT(__VA_ARGS__,i_mtime.tv_sec)			\
	DUMP_MEMBER_LLINT(__VA_ARGS__,i_ctime.tv_sec)	*/		\
}									\
	


#endif /* __BPF_STRUCT_HELPERS_H */

