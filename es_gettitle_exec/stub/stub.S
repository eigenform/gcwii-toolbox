.thumb
.thumb_func
__start:
	add r1, pc, #0x0c
	bx r1
.word 0, 0, 0
.arm
__arm_start:
	ldr r1, =0x1c0
	str r1, [sp]
	ldr r1, =0x20100869
	str r1, [sp, #-4]

main:
	# Do things here ...
	mov r0, #1
	bl __syscall_set_ahbprot

restore_state:
	ldr r0, =0xfffffac7
	ldr r3, =0x20100869
	mov lr, r3
	bx lr

__syscall_set_ahbprot:
	.word 0xe6000a90
	bx lr
