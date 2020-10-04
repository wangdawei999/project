/* User defined types */


#define LOOPS_PER_THREAD 500

typedef void *buffer_t;
typedef int array_t[10];
struct bindsicv{
    unsigned char si[16];
    int c;
    int v;
    uint8_t hc[32];
};
struct bindhcv{
    uint8_t hc[32];
    int c;
    int v;
};
