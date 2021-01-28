#ifndef __BPF_STRUCT_HELPERS_H
#define __BPF_STRUCT_HELPERS_H

#include "vmlinux.h"
#include "bpf_dump_helpers.h"

#define DUMP_FILE_STRUCT(FILE) {					\
	DUMP_MEMBER_LLINT(FILE,f_pos)					\
	DUMP_MEMBER_UINT(FILE,f_mode)					\
	DUMP_MEMBER_UINT(FILE,f_path.dentry,d_flags)			\
	DUMP_MEMBER_STR (FILE,f_path.dentry,d_name.name)		\
}	


#endif /* __BPF_STRUCT_HELPERS_H */

