
# We enter from eticket context, in THUMB mode (0x00010001)
.thumb
.thumb_func
__start:
	add r1, pc, #0x0c
	bx r1

.word 0, 0, 0

.arm
__arm_start:
	# Fix the part of the stack we clobbered
	ldr r1, =0x1c0
	str r1, [sp]
	ldr r1, =0x20100869
	mov r2, sp
	sub r2, #4
	str r1, [r2]

	# Return to the original saved LR that we clobbered
	ldr r3, =0x20100869
	mov lr, r3

	# Return -1337 to PPC-land
	ldr r0, =0xfffffac7
	bx lr

