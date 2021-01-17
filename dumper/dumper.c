#include "dumper.h"

//int my_printf(const char *fmt, ...) {
//	va_list args;
//	char buffer[256];
//	va_start(args, fmt);
//	vsnprintf (buffer, 255, fmt, args);
//	printf(buffer);
//	va_end(args);
//	return 0;
//}
//
//int dump(void *myStruct, long size)
//{
//    unsigned int i;
//    const unsigned char * const px = (unsigned char*)myStruct;
//    for (i = 0; i < size; ++i) {
//        if( i % (sizeof(int) * 8) == 0){
//            printf("\n%08X ", i);
//        }
//        else if( i % 4 == 0){
//            printf(" ");
//        }
//        printf("%02X", px[i]);
//    }
//
//    printf("\n\n");
//    return 0;
//}
//

