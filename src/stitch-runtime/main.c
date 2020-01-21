#include <stdint.h>

extern void _start();
extern void *config_region;

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

enum platform_type
{
	PLATFORM_GC,
	PLATFORM_WII,
};

enum region_type
{
	REGION_TEXT,
	REGION_DATA,
};

// A user may specify a region of memory to which something will be applied
// after the target program has been loaded into memory, just before boot. 
// Typically these are assumed to be "nonvolatile" during runtime, i.e. some 
// block of unused program .text, unused data segments, etc.
//
// By the time execution has started in the codehandler, we expect that the
// software installing the codehandler has already applied these to memory
// and has just booted the game.

struct runtime_region
{
	u32 base;
	u32 len;
};

// A patch on some memory where the memory is assumed to be "volatile," and
// the user wants to continously overwrite it (where the frequency of writes
// is determined by however the codehandler is hooked into the game).

struct v_patch
{
	u32 base;
	u32 len;
};

struct linkage
{
	u32 base;
};


// The host platform fills out this structure in our data segment after 
// writing the codehandler into memory. The size of this configuration data
// may exceed the size of the available data segment in the codehandler 
// itself. In order to account for this case, the procedure must be:
//
//	1. The user provides a configuration to the host platform
//	2. Host platform determines the size of the binary configuration
//	3. If the configuration size exceeds the size of the codehandler's
//	   data segment, the host checks a user-configured memory range
//	   to see if the configuration will fit
//	4. The host writes the global config_region pointer
//
// Otherwise, if the global config_region pointer is unset, the codehandler
// assumes that the data segment will contain all necessary data necessary
// for doing things during runtime 

struct config 
{
	// Host platform
	u8 platform;

	// A list of static patches applied by the host platform that the user
	// requested linkage information about
	struct linkage linkage[]
};

//void* user_slot[0x100] __attribute__((section ("data")));




void _main() 
{
}
