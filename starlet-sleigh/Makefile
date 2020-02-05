KERNEL	:= ./kernel.elf
TARGET	:= starlet_ios.sinc
GEN	:= ../bin/gen-ios-sleigh

.PHONY: $(TARGET) clean
all: $(TARGET)
$(TARGET): 
	@echo "[*] Writing to $(TARGET) ..."
	$(GEN) $(KERNEL) > $@
clean:
	rm -vf $(TARGET)
