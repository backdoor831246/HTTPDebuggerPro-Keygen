// patcher4.cpp
// Patches HTTPDebuggerUI.exe: sub_436B60 (activation thread)
// Forces success: sets *(v70+0x1C0)=1 and jumps to LABEL_47
//
// Compile:
//   MSVC:  cl patcher4.cpp /EHsc /Fe:patcher4.exe
//   MinGW: g++ patcher4.cpp -o patcher4.exe

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// sub_436B60 prologue (32 bytes), VA 0x436B60, file off 0x35F60
static const uint8_t g_pattern[] = {
	0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x28, 0xBE,
	0x8F, 0x00, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00,
	0x50, 0x83, 0xEC, 0x6C, 0xA1, 0x44, 0x4E, 0xA3,
	0x00, 0x33, 0xC5, 0x89, 0x45, 0xF0, 0x53, 0x56
};
static const size_t g_pattern_len = sizeof(g_pattern);

// Patch bytes:
//   mov eax, [esp+4]           ; 8B 44 24 04        (4 bytes) load lpThreadParameter
//   mov dword [eax+0x1C0], 1   ; C7 80 C0 01 00 00  (10 bytes) set success flag
//                                01 00 00 00
//   jmp LABEL_47 (0x437031)    ; E9 xx xx xx xx     (5 bytes)
//   total: 19 bytes
//
// patch_va = 0x436B60
// jmp target = 0x437031
// jmp instr va = 0x436B60 + 14 = 0x436B6E
// rel32 = 0x437031 - (0x436B6E + 5) = 0x437031 - 0x436B73 = 0x4BE
static const uint8_t g_patch[] = {
	0x8B, 0x44, 0x24, 0x04,              // mov eax, [esp+4]
	0xC7, 0x80, 0xC0, 0x01, 0x00, 0x00,  // mov dword ptr [eax+0x1C0], 1
	0x01, 0x00, 0x00, 0x00,
	0xE9, 0xBE, 0x04, 0x00, 0x00         // jmp 0x437031
};
static const size_t g_patch_len = sizeof(g_patch);

int main(int argc, char *argv[])
{
	const char *input = (argc > 1) ? argv[1] : "HTTPDebuggerUI.exe";
	char output[512];
	snprintf(output, sizeof(output), "%s.patched4.exe", input);

	FILE *f = fopen(input, "rb");
	if (!f) { fprintf(stderr, "[-] cannot open %s\n", input); return 1; }

	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	rewind(f);

	uint8_t *buf = (uint8_t*)malloc(size);
	if (!buf) { fclose(f); fprintf(stderr, "[-] malloc failed\n"); return 1; }
	fread(buf, 1, size, f);
	fclose(f);

	// Verify patch fits in pattern
	if (g_patch_len > g_pattern_len) {
		fprintf(stderr, "[-] patch larger than pattern!\n");
		free(buf); return 1;
	}

	int count = 0;
	for (long i = 0; i <= size - (long)g_pattern_len; i++) {
		if (memcmp(buf + i, g_pattern, g_pattern_len) == 0) {
			printf("[+] found pattern at file offset 0x%05lX\n", i);
			memcpy(buf + i, g_patch, g_patch_len);
			// NOP out remaining bytes of pattern
			memset(buf + i + g_patch_len, 0x90, g_pattern_len - g_patch_len);
			count++;
		}
	}

	if (count == 0) {
		fprintf(stderr, "[-] pattern not found — wrong version?\n");
		free(buf); return 1;
	}

	FILE *out = fopen(output, "wb");
	if (!out) { fprintf(stderr, "[-] cannot write %s\n", output); free(buf); return 1; }
	fwrite(buf, 1, size, out);
	fclose(out);
	free(buf);

	printf("[+] patched: %d occurrence(s)\n", count);
	printf("[+] written: %s\n", output);
	return 0;
}