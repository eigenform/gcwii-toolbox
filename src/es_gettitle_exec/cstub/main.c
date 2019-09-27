#include "syscall.h"

// I *think* this is correct
#define	IOS58_VERSION 0x00501b20

typedef struct elfldr_hdr
{
	unsigned int hdr_len;
	unsigned int elf_off;
	unsigned int elf_len;
	unsigned int pad;
} elfldr_hdr;


/* boot_new_ios_kernel() typically expects a pointer to an ARM ELF with some
 * embedded stub loader. Here, we can just embed the expected header in the
 * .text section immediately before some code [that we want to run in the 
 * context of the currently running kernel], and then point the syscall at the
 * header.
 *
 * Typically this syscall reloads a new kernel, so we need to account for the
 * fact that some state has changed (icache, MMU, interrupts disabled). 
 * Other side effects to-be-addressed:
 *
 *	 - on low MEM1 (PPC globals)
 *	 - some NAND register
 *	 - HW_ARMIRQMASK is set to zero
 *
 */

elfldr_hdr header __attribute__((section (".text"))) = { 0x10 };
void __attribute__((naked)) __kernel_stub()
{
	asm volatile 
	(

	// Restore the original state of the MMU register.
	// I *think* this is always the correct value.

		"ldr r0, =0x0005307f\n"
		"mcr p15,0x0,r0,cr1,cr0,0x0\n"

	// Re-enable interrupts?

		"mrs r1, cpsr\n"
		"bic r1, r1, #0xc0\n"
		"orr r1, r1, r0\n"
		"msr cpsr_c, r1\n"
	);

	// Do things in the kernel
	// ...

	asm volatile ("bx lr\n");
}

void __main()
{
	// Grant PPC access on Hollywood registers
	set_ahbprot(1);

	// Run some code in the context of the running kernel
	boot_new_ios_kernel(&header, IOS58_VERSION);

	return;
}
