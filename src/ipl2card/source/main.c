#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <ogcsys.h>
#include <gccore.h>

#define IPL_SIZE 0x200000
#define CARDBUF_SIZE 0xA000

static void *xfb = NULL;
static GXRModeObj *rmode = NULL;

static void *card_buf = NULL;
static u8 *ipl_buf = NULL;

void null_cb(int x, int y){};
extern void __SYS_ReadROM(void *buf, u32 len, u32 off);

void *init_fb() {

	void *framebuffer;

	VIDEO_Init();
	PAD_Init();
	
	rmode = VIDEO_GetPreferredMode(NULL);

	framebuffer = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
	console_init(framebuffer,20,20,rmode->fbWidth,rmode->xfbHeight,rmode->fbWidth*VI_DISPLAY_PIX_SZ);
	
	VIDEO_Configure(rmode);
	VIDEO_SetNextFramebuffer(framebuffer);
	VIDEO_SetBlack(FALSE);
	VIDEO_Flush();
	VIDEO_WaitVSync();
	if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();

	return framebuffer;

}

int main(int argc, char **argv)
{
	u32 sector_size;
	card_file file;

	xfb = init_fb();

	// Map IPL into memory
	ipl_buf = memalign(32, IPL_SIZE);
	__SYS_ReadROM(ipl_buf, IPL_SIZE, 0);
	printf("Mapped IPL to %p\n", ipl_buf);

	// Mount card in slot A
	card_buf = memalign(32, CARDBUF_SIZE);
	CARD_Init("DOLX", "00");
	while (CARD_Mount(0, card_buf, null_cb) < 0) {};
	CARD_GetSectorSize(0,&sector_size);
	printf("Mounted card in slot A, sector size is 0x%08x\n", sector_size);

	// Write to card
	printf("Writing ipl.bin ...\n");
	if (CARD_Create(0, "ipl.bin", IPL_SIZE, &file) == 0)
	{
		for (int i = 0; i < IPL_SIZE; i += sector_size)
			CARD_Write(&file, ipl_buf + i, sector_size, i);
	} 
	else 
	{
		printf("Couldn't write ipl.bin to card\n");
		CARD_Close(&file);
	}

	// Unmount card
	CARD_Close(&file);
	CARD_Unmount(0);

	// Wait for the user to do something
	while(1) 
	{
		VIDEO_WaitVSync();
		PAD_ScanPads();

		int buttonsDown = PAD_ButtonsDown(0);
		if (buttonsDown & PAD_BUTTON_A)
			printf(".\n");
		if (buttonsDown & PAD_BUTTON_START)
			exit(0);
	}
	return 0;
}


