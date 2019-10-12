/* main.c
 *
 * Based on implementation in segher's tools, see the following:
 *
 *	http://git.infradead.org/?p=users/segher/wii.git
 *
 * I'm not sure if this particular SHA1 implementation is actually necessary
 * and sufficient or not; can't tell. 
 *
 * FIXME: I have a Python version of this which is much terser, but tt seems 
 * like I can't get Python to compute the correct SHA1 digest, so I assume it 
 * either involves *THIS PARTICULAR* SHA1 implementation from segher's tools, 
 * or it has something to do with how PyCrypto actually does the hashing?
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


char otp_path[0x100];
char key_path[0x100];
char otp_hash_string[0x40];
char current_hash_string[0x40];
char *home_path;

// Reference boot1 digest from some OTP dump
u8 otp_boot1_hash[0x14];
bool use_otp = false;

// The boot1 key/IV
u8 boot1_key[0x10];
u8 boot1_iv[0x10] = { 0 };

void render_hash(u8 *hash, void *str)
{
	for (int i = 0; i < 0x14; i++)
		sprintf((char*)&(str[i*2]), "%02x", hash[i]);
}

void decrypt(u8 *key, u8 *iv, u8 *input, u8 *output, u32 len)
{
	AES_KEY k;
	AES_set_decrypt_key(key, 128, &k);
	AES_cbc_encrypt(input, output, len, &k, iv, AES_DECRYPT);
}


int main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("usage: %s <nand.bin>\n\n", argv[0]);
		printf("\tHash boot1 and write a dump to './boot1.bin'.\n");
		printf("\tReads the boot1 key from '~/.wii/boot1'.\n");
		printf("\n");
		exit(-1);
	}

	FILE *fp;
	home_path = getenv("HOME");
	snprintf(otp_path, sizeof(otp_path), "%s/.wii/otp.bin", home_path);
	snprintf(key_path, sizeof(key_path), "%s/.wii/boot1", home_path);

	// Optionally compare against hash in an OTP dump
	fp = fopen(otp_path, "rb");
	if (fp)
	{
		use_otp = true;
		fread(otp_boot1_hash, 0x14, 1, fp);
		render_hash(otp_boot1_hash, otp_hash_string);
		printf("[*] OTP digest:\t\t %s\n", otp_hash_string);
		fclose(fp);
	}

	// Read in the boot1 key
	fp = fopen(key_path, "rb");
	if (!fp)
	{
		printf("[!] Couldn't open key at %s\n", key_path);
		exit(-1);
	}
	fread(boot1_key, 0x10, 1, fp);
	fclose(fp);

	// Open a file descriptor to a NAND dump
	fp = fopen(argv[1], "rb");
	if (!fp)
	{
		printf("[!] Couldn't open NAND at %s\n", argv[1]);
		exit(-1);
	}

	page raw_page;
	page dec_page;
	SHA1Context ctx;
	SHA1Reset(&ctx);
	page output[0x2f];

	// Decrypt and hash boot1 (the first 0x2f pages in NAND flash)
	for (int pnum = 0; pnum < 0x2f; pnum++)
	{
		// Clear scratch memory for decrypting pages
		memset((void*)&raw_page, 0, sizeof(page));
		memset((void*)&dec_page, 0, sizeof(page));

		// Read a raw page from NAND, then decrypt it
		fread(&raw_page, sizeof(page), 1, fp);
		decrypt(boot1_key, boot1_iv, (void*)&raw_page, 
			(void*)&dec_page, PAGEDATA_LEN);

		// Update the computed boot1 digest
		SHA1Input(&ctx, (void*)&dec_page, PAGEDATA_LEN);

		memcpy(&output[pnum], &dec_page, sizeof(dec_page));
	}

	printf("[*] Computed digest:\t ");
	for (int j = 0; j < 5; j++)
		printf("%08x", ctx.Message_Digest[j]);
	printf("\n");
	fclose(fp);

	fp = fopen("boot1.bin", "wb");
	if (!fp)
	{
		printf("[!] Couldn't open ./boot1.bin for writing\n");
		exit(-1);
	}

	for (int pnum = 0; pnum < 0x2f; pnum++)
		fwrite(&output[pnum].data, PAGEDATA_LEN, 1, fp);
	fclose(fp);

	printf("[*] Wrote %08x bytes to ./boot1.bin\n", sizeof(output));
}

