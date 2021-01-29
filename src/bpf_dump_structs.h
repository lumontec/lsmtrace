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
	DUMP_MEMBER_LLINT(__VA_ARGS__,f_pos)				\
	DUMP_MEMBER_UINT(__VA_ARGS__,f_mode)				\
	DUMP_DENTRY_STRUCT(__VA_ARGS__,f_path.dentry)			\
}	

/* dentry */
#define DUMP_DENTRY_STRUCT(...) {					\
	DUMP_MEMBER_UINT(__VA_ARGS__,d_flags)				\
	DUMP_MEMBER_USTR (__VA_ARGS__,d_name.name)			\
}									\
									\


#endif /* __BPF_STRUCT_HELPERS_H */

