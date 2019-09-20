# stub.s
# We enter from (eticket) context, in THUMB mode at 0x00010001.

.thumb
.thumb_func
__start:
	add r1, pc, #0x0c
	bx r1
.word 0, 0, 0
.arm
__arm_start:
	# Fix the two words we clobbered on the stack
	ldr r1, =0x1c0
	str r1, [sp]
	ldr r1, =0x20100869
	str r1, [sp, #-4]

#set_uid:
#	mov r0, #1
#	mov r1, #0
#	bl __syscall_set_uid
#
#set_ahbprot
#	mov r0, #1
#	bl __syscall_set_ahbprot
#
#
#set_perms:
#	# Grant eticket rw permissions on hollywood registers
#	ldr r1, =0xffff9c94
#	mov r2, #0x03
#	str r2, [r1]
#	
#disable_memprot:
#	ldr r1, =0x0d8b420a
#	mov r2, #0x0
#	strh r2, [r1]

restore_state:
	# Return -1337 to PPC-land (verify that we did something)
	ldr r0, =0xfffffac7

	# Return to the original saved LR that we clobbered
	ldr r3, =0x20100869
	mov lr, r3
	bx lr

# Syscall table
__syscall_set_uid:
	.word 0xe6000570
	bx lr
__syscall_set_ahbprot:
	.word 0xe6000a90
	bx lr

# Some saved state
context:
	.word 0
