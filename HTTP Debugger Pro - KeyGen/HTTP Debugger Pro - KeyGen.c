#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void printTime(void) {
	SYSTEMTIME st;
	GetLocalTime(&st);
	printf("[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
}

static void logInfo(const char *label, const char *val) {
	printTime();
	printf("%s%s\n", label, val);
}

static void logOk(const char *msg) {
	printTime();
	printf("%s\n", msg);
}

static void logErr(const char *msg) {
	printTime();
	printf("%s\n", msg);
}

int main(void) {
	HKEY hKey;
	char appVer[256] = { 0 };
	DWORD bufSize = sizeof(appVer);

	if (RegOpenKeyExA(HKEY_CURRENT_USER,
		"Software\\MadeForNet\\HTTPDebuggerPro",
		0, KEY_READ, &hKey) != ERROR_SUCCESS)
	{
		logErr("HTTP Debugger Pro installation not found");
		printf("\n  press any key to close\n");
		getchar(); return 1;
	}
	RegQueryValueExA(hKey, "AppVer", NULL, NULL, (LPBYTE)appVer, &bufSize);
	RegCloseKey(hKey);

	logInfo("detected  : ", appVer);

	char *lastSpace = strrchr(appVer, ' ');
	if (!lastSpace) { logErr("version parse failed"); getchar(); return 1; }

	char verDigits[64] = { 0 };
	int di = 0;
	for (int i = 1; lastSpace[i]; i++)
		if (lastSpace[i] != '.') verDigits[di++] = lastSpace[i];

	DWORD version = (DWORD)atol(verDigits);
	{
		char tmp[32]; sprintf(tmp, "%lu", version);
		logInfo("version   : ", tmp);
	}

	DWORD serial = 0;
	GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
	{
		char tmp[32]; sprintf(tmp, "0x%08X", serial);
		logInfo("hardware  : ", tmp);
	}

	DWORD snIndex = version ^ (((~serial) >> 1) + 736) ^ 0x590D4;
	char valueName[64] = { 0 };
	sprintf(valueName, "SN%lu", snIndex);
	logInfo("key name  : ", valueName);

	srand(GetTickCount());
	unsigned char v1 = (unsigned char)(rand() % 255);
	unsigned char v2 = (unsigned char)(rand() % 255);
	unsigned char v3 = (unsigned char)(rand() % 255);

	char licKey[20] = { 0 };
	sprintf(licKey, "%02X%02X%02X7C%02X%02X%02X%02X",
		(unsigned int)v1,
		(unsigned int)(v2 ^ 0x7C),
		(unsigned int)((~v1) & 0xFF),
		(unsigned int)v2,
		(unsigned int)(v3 % 255),
		(unsigned int)((v3 % 255) ^ 7),
		(unsigned int)(v1 ^ ((~(v3 % 255)) & 0xFF)));

	logInfo("license   : ", licKey);

	DWORD dwDisp;
	if (RegCreateKeyExA(HKEY_CURRENT_USER,
		"Software\\MadeForNet\\HTTPDebuggerPro",
		0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, &dwDisp) == ERROR_SUCCESS)
	{
		RegSetValueExA(hKey, valueName, 0, REG_SZ,
			(const BYTE*)licKey, (DWORD)strlen(licKey) + 1);
		RegCloseKey(hKey);
		printf("\n");
		logOk("done");
	}
	else
	{
		logErr("registry write failed");
	}

	printf("\n  press any key to close\n");
	getchar();
	return 0;
}