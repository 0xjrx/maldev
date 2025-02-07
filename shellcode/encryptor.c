#include <stddef.h>
#include <stdio.h>
#include <string.h>

// Function to perform RC4 encryption/decryption
void rc4_crypt(const unsigned char *key, size_t key_len,
               const unsigned char *input, unsigned char *output,
               size_t data_len) {
  if (key_len < 5 || key_len > 256) {
    printf("Error: Key length must be between 5 and 256 bytes.\n");
    return;
  }

  unsigned char s[256];
  int i, j = 0;

  // Initialize S-box
  for (i = 0; i < 256; i++) {
    s[i] = i;
  }

  // Key Scheduling Algorithm (KSA)
  for (i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key_len]) % 256;
    // Swap s[i] and s[j]
    unsigned char tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
  }

  // Pseudo-Random Generation Algorithm (PRGA) and encryption/decryption
  i = j = 0;
  for (size_t n = 0; n < data_len; n++) {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;

    // Swap s[i] and s[j]
    unsigned char tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;

    // Generate keystream byte and XOR with input
    unsigned char k = s[(s[i] + s[j]) % 256];
    output[n] = input[n] ^ k;
  }
}

int main() {
  // Example usage
  const char *message = "Wello Horld!";
  unsigned char key[] = "SecretKey1337";
  size_t key_len = strlen((char *)key);
  size_t msg_len = strlen(message);

  unsigned char encrypted[1024];
  unsigned char decrypted[1024];

  // Encrypt
  printf("Original message: %s\n", message);
  rc4_crypt(key, key_len, (const unsigned char *)message, encrypted, msg_len);

  printf("Encrypted (hex): ");
  for (size_t i = 0; i < msg_len; i++) {
    printf("%02x ", encrypted[i]);
  }
  printf("\n");

  // Decrypt (RC4 is symmetric, so we use the same operation)
  rc4_crypt(key, key_len, encrypted, decrypted, msg_len);
  decrypted[msg_len] = '\0'; // Null terminate the decrypted string
  printf("Decrypted: %s\n", decrypted);

  return 0;
}
