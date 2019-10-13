TARGET=mysha

all: $(TARGET).so

$(TARGET).o: sha1.c
	gcc -c -fPIC $< -o $@
$(TARGET).so: $(TARGET).o
	gcc -shared $< -o $@
clean:
	rm -vf $(TARGET).o $(TARGET).so

.PHONY: clean all
