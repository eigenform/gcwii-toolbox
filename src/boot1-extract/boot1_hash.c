/* boot1_hash.c
 *
 * Verify the hash of a boot1 dump on the host machine. 
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include <openssl/aes.h>
#include "sha1.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

// A NAND flash page looks like this
#define PAGEDATA_LEN 0x800
typedef struct _page
{
	u8 data[PAGEDATA_LEN];	// Actual content
	u8 metadata[0x40];	// Metadata
} page;


char current_hash_string[0x40];
int main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("usage: %s <boot1.bin>\n\n", argv[0]);
		printf("\tHash some boot1 dump.\n");
		exit(-1);
	}

	FILE *fp;

	// Open a file descriptor to a boot1 dump
	fp = fopen(argv[1], "rb");
	if (!fp)
	{
		printf("[!] Couldn't open boot1 dump at %s\n", argv[1]);
		exit(-1);
	}

	page dec_page;
	SHA1Context ctx;
	SHA1Reset(&ctx);

	// Hash the boot1 dump
	for (int pnum = 0; pnum < 0x2f; pnum++)
	{
		// Clear scratch memory for decrypting pages
		memset((void*)&dec_page, 0, sizeof(page));

		// Read a decrypted page from the boot1 dump
		fread(&dec_page, PAGEDATA_LEN, 1, fp);

		// Update the computed boot1 digest
		SHA1Input(&ctx, (void*)&dec_page, PAGEDATA_LEN);
	}

	printf("[*] Computed digest:\t ");
	for (int j = 0; j < 5; j++)
		printf("%08x", ctx.Message_Digest[j]);
	printf("\n");
	fclose(fp);
}

