/* boot1_extract.c
 *
 * Based on implementation in segher's tools, see the following:
 *
 *	http://git.infradead.org/?p=users/segher/wii.git
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include <openssl/sha.h>

#include <openssl/aes.h>
#include "sha1.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

// The length of the actual data section in a NAND flash page
#define PAGEDATA_LEN 0x800

// The length of the metadata section in a NAND flash page
#define METADATA_LEN 0x040

// Structure representing a raw NAND flash page
typedef struct _page
{
	u8 data[PAGEDATA_LEN];
	u8 metadata[METADATA_LEN];
} page;


static char key_path[0x100];
static char current_hash_string[0x40];
static char *home_path;

// The boot1 key and boot1 IV
u8 boot1_key[0x10] = { 0 };
u8 boot1_iv[0x10] = { 0 };

void hexdump (const char * desc, const void * addr, const int len)
{
    int i;
    unsigned char buff[17];
    const unsigned char * pc = (const unsigned char *)addr;
    if (desc != NULL) printf ("%s:\n", desc);
    if (len == 0) { printf("  ZERO LENGTH\n"); return; }
    else if (len < 0) { printf("  NEGATIVE LENGTH: %d\n", len); return; }
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0) printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }
        printf (" %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) buff[i % 16] = '.';
        else buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0) { printf ("   "); i++; }
    printf ("  %s\n", buff);
}



// Print the program usage and exit
void usage(const char* fn) { printf("usage: %s <nand.bin>\n", fn); exit(0); }

/* decrypt()
 * Given some AES key and IV, decrypt some buffer into an output buffer. */
void decrypt(u8 *key, u8 *iv, u8 *input, u8 *output, u32 len)
{
	AES_KEY k;
	AES_set_decrypt_key(key, 128, &k);
	AES_cbc_encrypt(input, output, len, &k, iv, AES_DECRYPT);
}


/* read_boot1_key()
 * Read the boot1 key into memory; just die if we can't read it. */
void read_boot1_key()
{
	FILE *fp;

	home_path = getenv("HOME");
	snprintf(key_path, sizeof(key_path), "%s/.wii/boot1", home_path);

	fp = fopen(key_path, "rb");
	if (!fp) 
	{ 
		printf("[!] Couldn't open key %s\n", key_path); 
		exit(-1);
	}
	fread(boot1_key, 0x10, 1, fp);
	fclose(fp);
}

/* read_boot1_pages()
 * Read all the raw boot1 NAND pages into a buffer. */
static page raw_pages[0x2f];
void read_boot1_pages(const char* fn)
{
	FILE *fp;

	// Open file descriptor to a NAND dump
	fp = fopen(fn, "rb");
	if (!fp) { printf("[!] Couldn't open NAND %s\n", fn); exit(-1); }

	fread(raw_pages, sizeof(page), 0x2f, fp);
	fclose(fp);
}

/* decrypt_boot1_pages()
 * Produce a buffer of decrypted boot1 pages [including the metadata]. */
static page decrypted_pages[0x2f];
void decrypt_pages()
{
	// Iterate over all the raw pages
	for (int pnum = 0; pnum < 0x2f; pnum++)
	{
		// Decrypt the first 0x800 bytes of data from this page
		decrypt(boot1_key, boot1_iv, (void*)raw_pages[pnum].data, 
			(void*)decrypted_pages[pnum].data, PAGEDATA_LEN);

		// Copy over the metadata segment from this page
		memcpy(decrypted_pages[pnum].metadata, 
			raw_pages[pnum].metadata, METADATA_LEN);
	}
}

/* hash_boot1_data()
 * Produce the boot1 hash. This is the hash burned into EFUSE/OTP memory. */
static SHA1Context boot1_data_ctx;
void hash_boot1_data()
{
	SHA1Reset(&boot1_data_ctx);
	for (int pnum = 0; pnum < 0x2f; pnum++)
	{
		SHA1Input(&boot1_data_ctx, (void*)decrypted_pages[pnum].data, 
			PAGEDATA_LEN);
	}
}

/* write_file()
 * Flush some data to disk. */
void write_file(const char* filename, void *buf, u32 len)
{
	FILE *fp;
	size_t res;
	fp = fopen(filename, "wb");
	if (!fp)
	{
		printf("[!] Couldn't write output %s\n", filename);
		exit(-1);
	}
	res = fwrite(buf, len, 1, fp);
	fclose(fp);
	printf("[*] Wrote %08x bytes to %s\n", res, filename);
}

void write_decrypted_data(const char* filename)
{
	FILE *fp;
	fp = fopen(filename, "wb");
	if (!fp)
	{
		printf("[!] Couldn't write output %s\n", filename);
		exit(-1);
	}
	for (int pnum = 0; pnum < 0x2f; pnum++)
	{
		fwrite((void*)&decrypted_pages[pnum], PAGEDATA_LEN, 1, fp);
	}
	fclose(fp);
	printf("[*] Wrote decrypted boot1 data to %s\n", filename);
}


/* print_hash()
 * Write some hash to stdout. */
void print_hash(const char* hash_name, SHA1Context *ctx)
{
	printf("[*] %s digest:\t ", hash_name);
	for (int j = 0; j < 5; j++) 
		printf("%08x", ctx->Message_Digest[j]);
	printf("\n");
}


/* boot1 consists of the first 0x2f NAND pages. The EFUSE/OTP hash of boot1 
 * is a SHA-1 digest of *the data segment* in each pages, and does not include
 * the 0x40-byte metadata segments on the end of each NAND page.
 */

int main(int argc, char **argv)
{
	if (argc < 2) usage(argv[0]);

	memset(&raw_pages, 0, sizeof(raw_pages));
	memset(&decrypted_pages, 0, sizeof(decrypted_pages));

	// Read in the boot1 key
	read_boot1_key();

	// Read in the raw set of boot1 pages from a NAND
	read_boot1_pages(argv[1]);

	// Produce a decrypted set of boot1 pages
	decrypt_pages();

	// Hash all the data segments in the decrypted boot1 pages
	hash_boot1_data();
	print_hash("boot1 data", &boot1_data_ctx);
	write_decrypted_data("boot1.bin");


	//SHA1Context old_ctx;
	//SHA1Reset(&old_ctx);
	//u32 message_length_bytes;
	//for (int pnum = 0; pnum < 0x2f; pnum++)
	//{
	//	SHA1Input(&old_ctx, (void*)decrypted_pages[pnum].data, 
	//		PAGEDATA_LEN);
	//	message_length_bytes += PAGEDATA_LEN;
	//}
	//hexdump("Unpadded, old impl", &old_ctx.Message_Digest[0], 20);
	//for (int j = 0; j < 5; j++) printf("%08x", old_ctx.Message_Digest[j]);
	//printf("\n\n");
	//SHA1Result(&old_ctx);
	//hexdump("Padded, old impl", &old_ctx.Message_Digest[0], 20);
	//for (int j = 0; j < 5; j++) printf("%08x", old_ctx.Message_Digest[j]);
	//printf("\n\n");

	//SHA_CTX new_ctx;
	//SHA1_Init(&new_ctx);
	//for (int pnum = 0; pnum < 0x2f; pnum++)
	//{
	//	SHA1_Update(&new_ctx, (void*)decrypted_pages[pnum].data, 
	//		PAGEDATA_LEN);
	//}
	//u32 Message_Digest[5] = { new_ctx.h0, new_ctx.h1, new_ctx.h2, new_ctx.h3, new_ctx.h4 };
	//hexdump("Unpadded, openssl", &Message_Digest[0], 20);
	//for (int j = 0; j < 5; j++) printf("%08x", Message_Digest[j]);
	//printf("\n\n");

	//SHA1_Final((unsigned char*)&Message_Digest, &new_ctx);
	//hexdump("Padded, openssl", &Message_Digest[0], 20);
	//for (int j = 0; j < 5; j++) printf("%08x", Message_Digest[j]);
	//printf("\n");

}

