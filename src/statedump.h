#ifndef __SDUMP_H
#define __SDUMP_H

#include <stdio.h>
//#include "lsmtrace.h"

/* Dump typed event */
int dumpEvent( void*, size_t);

int printTest();



















//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_tracing.h>
//#include <bpf/bpf_core_read.h>

//const char stext[100] = "%s";
//const char dtext[100] = "%s";




//static int sdump (const char *fmt, void* arg1) {
//	const char *fmtcp = fmt;
////	const char *fmtinit = fmt;
//	long size = 0;
//	char tmp[1] = "1";
//
//	for (int i=0; i<1000; i++) {
//
//		__builtin_memcpy(tmp, fmtcp, 1);
//
//		if (tmp[0] == 0) {
//			size++;
//			break;
//		}
//
//		size++;
//		fmtcp++;
//	}
//
////	bpf_printk("size: %d", size);
//
////	__builtin_memcpy(dst, fmtinit, size);
////
////	if (__builtin_memcmp(dst, "%d", 2) == 0) {
////		bpf_printk("%d\n", (int)arg1);
////		return 0;
////	}
////
////	if (__builtin_memcmp(dst, "%u", 2) == 0) {
////		bpf_printk("%u\n", (unsigned int)arg1);
////		return 0;
////	}
//
//
//	bpf_printk("%s", dst);
//
//	return 0;
//
//}


//static int sdump (const char *fmt, ...) {
//
//	const char *fmtcp = fmt;
//	long size = 0;
//	char tmp[1] = "1";
//
//	for (int i=0; i<1000; i++) {
//
//		__builtin_memcpy(tmp, fmtcp, 1);
//
//		if (tmp[0] == 0) {
//			size++;
//			break;
//		}
//
//		size++;
//		fmtcp++;
//	}
//
////	bpf_printk("size: %d", size);
//	__builtin_memcpy(dst, fmt, size);
//	bpf_printk("%s", dst);
//
//	return 0;
//
//}








#endif /* __SDUMP_H */


