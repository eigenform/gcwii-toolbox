# MIT License
# Copyright (c) 2010-2020 
# Nuke, brkirch, Y.S, Kenobi, gamemasterplc, meta
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy 
# of this software and associated documentation files (the "Software"), to 
# deal in the Software without restriction, including without limitation the 
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is 
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
# DEALINGS IN THE SOFTWARE.

.extern _main
.global _start
_start:

	b _save_context

# Try to pad things out here, saving a little bit of space for future storage.
# This also guarantees that these variables will always live at a particular
# offset relative to the start of the codehandler.

.fill 3, 4, 0xdeadc0de

# Pointer to the list of gecko codes in memory.
# The value of the pointer MUST be filled in by the software responsible for
# installing this codehandler into memory. 

.global codelist_ptr
codelist_ptr:
.long 0x00000000

# Save context before branching into the actual codehandler.
# Whether or not this is necessary probably depends on how the codehandler
# is actually installed in memory and hooked during runtime.

_save_context:
	# Save context
	stwu r1, -0xac(r1)
	stw r0, 0x8(r1)
	mflr r0
	stw r0, 0xb0(r1)
	mfcr r0
	stw r0, 0x0c(r1)
	mfctr r0
	stw r0, 0x10(r1)
	mfxer r0
	stw r0, 0x14(r1)
	stmw r3, 0x18(r1)
	mfmsr r25
	stw r25, 0xa8(r1)

	# Enable floating-point and save f2, f3
	ori r26, r25, 0x2000
	andi. r26, r26, 0xf9ff
	mtmsr r26
	stfd f2, 0x98(r1)
	stfd f3, 0xa0(r1)

	# Save Memory Interface permissions (?)
	lis r20, 0xcc00
	lhz r28, 0x4010(r20)

	# Set all Memory Interface permission bits (?)
	ori r21, r28, 0xff
	sth r21, 0x4010(r20)

# Validate that the current pointer to the codelist is not null.
# Then, validate the magic bytes (0x00d0c0de) on the codelist. 
# If the codelist isn't valid, just die.

_check_codelist_ptr:
	lis r13, codelist_ptr@h
	ori r13, r13, codelist_ptr@l
	lwz r15, 0x0(r13)
	cmpwi r15, 0
	beq _exit

_check_codelist_header:
	lis r3, 0x00d0
	ori r3, r3, 0xc0de

	lwz r4, 0x0(r15)
	cmpw r3, r4
	bne- _exit

	lwz r4, 0x4(r15)
	cmpw r3, r4
	bne- _exit

	#lwz r4, 0x8(r15)
	#cmpwi r4, 0
	#be- _exit

	addi r15, r15, 0x8
	bl _main

# Restore state and return to the caller.
_exit:
	# Restore Memory Interface permissions (?)
	sth r28, 0x4010(r20)

	# Restore context
	lfd f2, 0x98(r1)
	lfd f3, 0xa0(r1)
	lwz r25, 0xa8(r1)
	mtmsr r25
	lwz r0, 0xb0(r1)
	mtlr r0
	lwz r0, 0x0c(r1)
	mtcr r0
	lwz r0, 0x10(r1)
	mtctr r0
	lwz r0, 0x14(r1)
	mtxer r0
	lmw r3, 0x18(r1)
	lwz r0, 0x08(r1)
	addi r1, r1, 0xac

	isync 
	blr
