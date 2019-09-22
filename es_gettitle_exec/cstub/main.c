#include "syscall.h"

// I *think* this is correct
#define	IOS58_VERSION 0x00501b20


/* boot_new_ios_kernel() typically expects a pointer to an ARM ELF with some
 * embedded stub loader. Here, we can just embed the expected header in the
 * .text section and branch to __kernel_main() in the context of the currently
 * running kernel *without* actually reloading it.
 *
 * The syscall expects the new kernel entrypoint to deal with the fact that
 * interrupts, icache, and the MMU are all disabled before branching. We can 
 * just account for this here by restoring everything.
 *
 * There are some other side effects:
 *
 *	 - on low MEM1 (PPC globals)
 *	 - some NAND register
 *	 - HW_ARMIRQMASK is set to zero
 *
 */

// `int __kernel_stub` should be `(u32)&__kernel_main - (u32)&__kernel_stub`
int __kernel_stub __attribute__ ((section (".text"))) = 0x10;
int padding[3] __attribute__ ((section (".text"))) = { 0 };
void __attribute__((naked)) __kernel_main()
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

	// Do things in kernel context
	// ...

	asm volatile ("bx lr\n");
}


void __main()
{
	// Grant PPC access on Hollywood registers
	set_ahbprot(1);

	// This syscall can just be used to run in the kernel context
	boot_new_ios_kernel(&__kernel_stub, IOS58_VERSION);

	return;
}
