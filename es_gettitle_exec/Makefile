PREFIX	:= arm-none-eabi
OBJCOPY	:= $(PREFIX)-objcopy
AS	:= $(PREFIX)-as
GCC	:= $(PREFIX)-gcc

ASFLAGS	:= -mbig-endian -mcpu=arm926ej-s
A_SRC	:= stub/stub.S

CFLAGS	:= -mbig-endian -I. -mcpu=arm926ej-s -nostdlib
C_SRC	:= cstub/stub.S cstub/main.c
ENTRYPT	:= 0x00010000

.PHONY: all clean
all:
	@# This is the simple stub example in assembly
	$(AS) $(ASFLAGS) $(A_SRC) -o stub.elf
	$(OBJCOPY) -O binary stub.elf stub.bin

	@echo ""

	@# This is a more complex example of a stub with C code
	$(GCC) $(CFLAGS) $(C_SRC) -Wl,--section-start=.text=$(ENTRYPT) -o cstub.elf
	$(OBJCOPY) -S -O binary cstub.elf cstub.bin

clean:
	rm -rf *.bin *.elf
