CC		:= powerpc-eabi-gcc
LD		:= powerpc-eabi-ld
OBJCOPY		:= powerpc-eabi-objcopy

BASE_ADDR	:= 0x80001800

ASFLAGS		:= -mregnames
LDFLAGS		:= --section-start=.text=$(BASE_ADDR)
CFLAGS		:= -O3 -fno-asynchronous-unwind-tables -nostdlib --entry=_start

.PHONY: all clean
all: codehandler.bin

codehandler.bin: stub.s linker.ld main.c
	$(CC) $(CFLAGS) -Wa,$(ASFLAGS) -T linker.ld stub.s main.c
clean:
	rm -vf codehandler.bin
