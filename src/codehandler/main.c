#include <stdint.h>

extern void _start();
extern void *codelist_ptr;

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

void* user_slot[0x100] __attribute__((section ("data")));

void _main() {}
