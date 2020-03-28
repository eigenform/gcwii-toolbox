TARGET_EXTR 	:= ../../bin/boot1-extract
TARGET_HASH 	:= ../../bin/boot1-hash
.PHONY: all clean
all:
	gcc -lcrypto boot1_extract.c sha1.c -o $(TARGET_EXTR)
	gcc -lcrypto boot1_hash.c sha1.c -o $(TARGET_HASH)
	gcc -lcrypto sha1_test.c sha1.c -o sha1-test
clean:
	rm -fv $(TARGET_EXTR) $(TARGET_HASH) sha1-test *.o
