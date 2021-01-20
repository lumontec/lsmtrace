#include "dumper.h"

struct nested {
    int aa;
};

struct pointed {
    int bb;
};

struct dumpme {
    int a;
    int b;
    struct nested n;
    struct pointed *p;
};


int main(void) {
    struct nested n;
    struct pointed p;
    n.aa = 12;
    p.bb = 22;
    struct dumpme d;
    d.a = 1;
    d.b = 2;
    d.n = n;
    d.p = &p;
    __builtin_dump_struct(&d, sdump_helper);
//    dump(&d,sizeof(d));
    return 0;
}
