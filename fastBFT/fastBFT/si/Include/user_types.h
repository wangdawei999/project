/* User defined types */


#define LOOPS_PER_THREAD 500

typedef void *buffer_t;
typedef int array_t[10];

struct bindscv{
    uint32_t c;
    uint32_t v;
    uint8_t secret[16];
};
struct bindsicv{
    
    uint32_t c;
    uint32_t v;
    uint8_t si[16];
    uint8_t hc[32];
};
struct bindhcv{
    uint32_t c;
    uint32_t v;
    uint8_t hc[32];
};
