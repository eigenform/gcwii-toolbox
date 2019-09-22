# stub.S
# Sample stub code; branch into __main() in main.c, then return from the 
# ES_GetTitles() handler after we're done.

# Load the address of a label
.macro load_ptr reg, label
	adr \reg, \label
	adrl \reg, \label
	ldr \reg, =\label
	sub \reg, pc, #(.+8-\label)
.endm

# -----------------------------------------------------------------------------

.extern __main

.thumb
.thumb_func
.global _start
_start:
	# Branch to __arm_start
	add r1, pc, #0x0c
	bx r1
.word 0, 0, 0

.arm
__arm_start:

	# Restore the two words we clobbered on the stack
	ldr r1, =0x1c0
	str r1, [sp]
	ldr r1, =0x20100869
	str r1, [sp, #-4]

	# Branch into __main() in main.c
	bl __main

	# Return to the original LR with return code -1337
	ldr r0, =0xfffffac7
	ldr r3, =0x20100869
	mov lr, r3
	bx lr

# -----------------------------------------------------------------------------
# Embed a syscall table for main.c

.global boot_new_ios_kernel
boot_new_ios_kernel:
	.long 0xe6000870
	bx lr

.global set_ahbprot
set_ahbprot:
	.long 0xe6000a90
	bx lr
