#include <stdint.h>

static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" : : "a" (value), "Nd" (port) : "memory");
}

static void outl(uint16_t port, uint32_t value) {
	 asm("outl %0, %1" : : "a"(value), "Nd"(port) : "memory");
}

void strcpy(char* src, char* dst);
int strlen(char* str);
void print(char* str);
int fopen(char* path, int mode);
int fread(int fd, void* buff, uint64_t size);
int fwrite(int fd, void* buff, uint64_t size);
int fclose(int fd);

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
	// read and write to local file
	int fd = fopen("shared.txt", 1); // open file for read/write
	if (fd >= 0) {
		char wb1[256] = "Write to shared file\n";
		fd = fwrite(fd, wb1, strlen(wb1));

		char rb[1024];
		fread(fd, rb, sizeof(rb));
		print(rb);
	}

	fclose(fd);

	for (;;)
		asm("hlt");
}


struct file {
    char path[256]; // path to file
    uint64_t fd; // file descriptor for the file
	int mode; // 0 - read, 1 - read/write
    int shared; // indicates whether file is local or shared between vms

    int op; // operation on file
    void* buff; // buffer to read from / write into
    uint64_t temp; // for storing buffer size, receiving return values, etc...
};

enum { OPEN, CLOSE, READ, WRITE };

int fopen(char* path, int mode) {
	struct file f;
	f.op = OPEN;
	f.mode = mode;
	strcpy(path, f.path);

	uint64_t addr = (uint64_t)&f;
	uint32_t lo = (uint32_t)(addr & 0xFFFFFFFF);
	uint32_t hi = (uint32_t)(addr >> 32);

	outl(0x278, lo);
	outl(0x278, hi);

	return f.fd;
}

int fread(int fd, void* buff, uint64_t size) {
	struct file f;
	f.op = READ;
	f.fd = fd;
	f.buff = buff;
	f.temp = size;

	uint64_t addr = (uint64_t)&f;
	uint32_t lo = (uint32_t)(addr & 0xFFFFFFFF);
	uint32_t hi = (uint32_t)(addr >> 32);

	outl(0x278, lo);
	outl(0x278, hi);

	return f.temp;
}

int fwrite(int fd, void* buff, uint64_t size) {
	struct file f;
	f.op = WRITE;
	f.fd = fd;
	f.buff = buff;
	f.temp = size;

	uint64_t addr = (uint64_t)&f;
	uint32_t lo = (uint32_t)(addr & 0xFFFFFFFF);
	uint32_t hi = (uint32_t)(addr >> 32);

	outl(0x278, lo);
	outl(0x278, hi);

	return f.fd;
}

int fclose(int fd) {
	struct file f;
	f.op = CLOSE;
	f.fd = fd;

	uint64_t addr = (uint64_t)&f;
	uint32_t lo = (uint32_t)(addr & 0xFFFFFFFF);
	uint32_t hi = (uint32_t)(addr >> 32);

	outl(0x278, lo);
	outl(0x278, hi);

	return f.temp;
}

void strcpy(char* src, char* dst) {
	char* d = dst;
	while ((*d++ = *src++) != '\0');
}

int strlen(char* str) {
	int len = 0;
	char* s = str;
	while (*s++ != '\0') len++;
	return len;
}

void print(char* str) {
	for (; *str; ++str) outb(0xE9, *str);
}