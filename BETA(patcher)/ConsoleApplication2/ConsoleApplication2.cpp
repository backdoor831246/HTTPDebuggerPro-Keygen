#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

// sub_4218F0 - trial days check, patch to always return 30
static const uint8_t g_pattern[] = {
	0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x81, 0xEC,
	0x38, 0x04, 0x00, 0x00, 0xA1, 0x44, 0x4E, 0xA3,
	0x00, 0x33, 0xC4, 0x89, 0x84, 0x24, 0x34, 0x04,
	0x00, 0x00, 0x56, 0x57, 0x6A, 0x7C, 0x0F, 0x57
};
static const size_t g_pattern_size = sizeof(g_pattern);

// mov eax, 30 ; ret
static const uint8_t g_patch[] = { 0xB8, 0x1E, 0x00, 0x00, 0x00, 0xC3 };
static const size_t  g_patch_size = sizeof(g_patch);

static const char    g_marker[] = "The evaluation period has expired.";
static const size_t  g_marker_len = sizeof(g_marker) - 1;

int main(int argc, char* argv[])
{
	if (argc < 2) {
		std::cerr << "234r.exe 34234.exe\n";
		return 1;
	}

	std::ifstream fin(argv[1], std::ios::binary);
	if (!fin) {
		std::cerr << "error: cannot open " << argv[1] << "\n";
		return 1;
	}

	std::vector<uint8_t> buf(
		(std::istreambuf_iterator<char>(fin)),
		(std::istreambuf_iterator<char>()));
	fin.close();

	if (buf.size() < 2 || buf[0] != 'M' || buf[1] != 'Z') {
		std::cerr << "error: not a valid PE\n";
		return 1;
	}

	bool marker_found = false;
	for (size_t i = 0; i + g_marker_len <= buf.size(); i++) {
		if (memcmp(buf.data() + i, g_marker, g_marker_len) == 0) {
			marker_found = true;
			break;
		}
	}
	if (!marker_found) {
		std::cerr << "error: target binary not recognized\n";
		return 1;
	}

	int count = 0;
	for (size_t i = 0; i + g_pattern_size <= buf.size(); i++) {
		if (memcmp(buf.data() + i, g_pattern, g_pattern_size) == 0) {
			printf("found   : 0x%X\n", (unsigned int)i);
			printf("before  : ");
			for (size_t j = 0; j < g_patch_size; j++) printf("%02X ", buf[i + j]);
			printf("\n");

			memcpy(buf.data() + i, g_patch, g_patch_size);

			printf("after   : ");
			for (size_t j = 0; j < g_patch_size; j++) printf("%02X ", g_patch[j]);
			printf("\n\n");

			count++;
		}
	}

	if (count == 0) {
		std::cerr << "error: pattern not found\n";
		return 1;
	}

	printf("patched : %d occurrence(s)\n\n", count);

	std::string out = std::string(argv[1]) + ".patched.exe";
	std::ofstream fout(out, std::ios::binary);
	if (!fout) {
		std::cerr << "error: cannot write " << out << "\n";
		return 1;
	}
	fout.write(reinterpret_cast<const char*>(buf.data()), buf.size());
	fout.close();

	std::cout << "done -> " << out << "\n";
	return 0;
}