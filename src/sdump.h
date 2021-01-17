#ifndef __SDUMP_H
#define __SDUMP_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "lsmtrace.h"

const char stext[100] = "%s";
const char dtext[100] = "%s";
char dst[100] = "";

static int sdump_helper (const char *fmt, ...) {

	const char *fmtcp = fmt;
	long size = 0;
	char tmp[1] = "1";

	for (int i=0; i<1000; i++) {

		__builtin_memcpy(tmp, fmtcp, 1);

		if (tmp[0] == 0) {
			size++;
			break;
		}

		size++;
		fmtcp++;
	}

//	bpf_printk("size: %d", size);
	__builtin_memcpy(dst, fmt, size);
	bpf_printk("%s", dst);

	return 0;

}

#endif /* __SDUMP_H */




//int getsize (const char *fmt) {
//
//	int size = 0;
//	for (int i=0; i<10000; i++) {
//
//		__builtin_memcpy(dst, fmt, 100);
//		bpf_printk("data: %s", dst);
//
////		if (tmp[0] == 0) {
////			return size;
////		}
//		fmt++;
//	}
//	return -1; 
//}
//

