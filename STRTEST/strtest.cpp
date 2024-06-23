#include"Frost64.h"
#include<Windows.h>
#include<stdio.h>
#include<string>
#include<vector>

#define TEST_EXE_PATH_2 L"C:\\Users\\elfenlied\\Desktop\\Elfenlied\\IDB\\unpacked_MapleStory261.4.exe"

// string pool
// key addr 1464D5018
const BYTE StringPool__ms_aKey[16] = { 0xD6,0xDE,0x75,0x86,0x46,0x64,0xA3,0x71,0xE8,0xE6,0x7B,0xD3,0x33,0x30,0xE7,0x2E };
const int StringPool__ms_nKeySize = sizeof(StringPool__ms_aKey);
const ULONG_PTR StringPool__ms_aString = 0x1474C4240;
const int StringPool_Size = 17168;

#pragma pack(1)
typedef struct {
	BYTE seed;
	BYTE encrypted_string[1];
} StringPoolData;
#pragma pack()

bool rotatel(BYTE *key, BYTE seed) {
	if (!StringPool__ms_nKeySize) {
		return false;
	}

	if (!seed) {
		return false;
	}

	if (8 <= seed) {
		ULONG_PTR shift_1 = (seed >> 3) % StringPool__ms_nKeySize;
		for (int i = 0; i < StringPool__ms_nKeySize; i++) {
			key[i] = StringPool__ms_aKey[(i + shift_1) % StringPool__ms_nKeySize];
		}
	}

	BYTE bit = 0;
	if (seed & 7) {
		ULONG_PTR shift_2 = (seed & 7);
		bit = (BYTE)(key[0] >> (8 - shift_2));
		for (int i = 0; i < StringPool__ms_nKeySize; i++) {
			BYTE left = 0;
			if (i != (StringPool__ms_nKeySize - 1)) {
				left = (BYTE)(key[i + 1] >> (8 - shift_2));
			}
			BYTE right =  (BYTE)(key[i] << shift_2);
			key[i] = left | right;
		}
	}

	key[StringPool__ms_nKeySize - 1] |= bit;
	return true;
}

int DecodeStringPool(StringPoolData *spd, std::vector<BYTE> &decrypted_string) {
	BYTE key[StringPool__ms_nKeySize] = { 0 };
	// generate decryption key
	if (!rotatel(key, spd->seed)) {
		//puts("KEY ERR");
		return 1;
	}

	for (int i = 0; spd->encrypted_string[i]; i++) {
		BYTE chr = spd->encrypted_string[i] ^ key[i % 0x10];
		// CRLF check
		switch (chr) {
		case '\r': {
			decrypted_string.push_back('\\');
			decrypted_string.push_back('r');
			break;
		}
		case '\n': {
			decrypted_string.push_back('\\');
			decrypted_string.push_back('n');
			break;
		}
		default:
		{
			decrypted_string.push_back(chr);
			break;
		}
		}
	}
	// null terminating
	decrypted_string.push_back('\0');

	// length check
	if (decrypted_string[0] == '\0') {
		//puts("EMPTY STR ERR");
		return 2;
	}

	//printf("%s\n", &decrypted_sting[0]);
	return 0;
}
// CP_ACP
#define MS_SJIS 932
#define MS_BIG5 950
bool toUTF8(UINT codepage, std::vector<BYTE> &str, std::string &utf8, std::wstring &utf16) {
	try {
		// UTF16�֕ϊ�����ۂ̕K�v�ȃo�C�g�����擾
		int len = MultiByteToWideChar(codepage, 0, (char *)&str[0], -1, 0, 0);
		if (!len) {
			return false;
		}

		// UTF16�֕ϊ�
		std::vector<BYTE> b((len + 1) * sizeof(WORD));
		if (!MultiByteToWideChar(codepage, 0, (char *)&str[0], -1, (WCHAR *)&b[0], len)) {
			return false;
		}

		utf16 = std::wstring((WCHAR *)&b[0]);

		// UTF8
		b.clear();
		len = WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, 0, 0, 0, 0);
		b.resize(len + 1);
		WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, (char *)&b[0], len, 0, 0);
		utf8 = std::string((char *)&b[0]);
		return true;
	}
	catch (...) {
		return false;
	}

	return true;
}

int wmain(int argc, wchar_t **argv) {
	if (argc < 2) {
		puts("drop exe client file please.");
		system("pause");
		return 1;
	}

	Frost f(argv[1]);
	SetConsoleOutputCP(CP_UTF8);

	//Frost f(TEST_EXE_PATH_2);

	if (!f.Parse()) {
		puts("Parse err");
		system("pause");
		return 1;
	}

	ULONG_PTR *StringPoolArray = (ULONG_PTR *)f.GetRawAddress(StringPool__ms_aString);
	for (int i = 0; i < StringPool_Size; i++) {
		StringPoolData *spd = (StringPoolData *)f.GetRawAddress(StringPoolArray[i]);
		std::vector<BYTE> decrypted_string;
		int err = DecodeStringPool(spd, decrypted_string);
		if (err == 0) {
			/*
			for (auto &v : decrypted_string) {
				printf("%02X ", v);
			}
			printf("\n");
			*/
			std::string text = std::string((char *)&decrypted_string[0]);
			printf("%d : %llX : %s", i, StringPoolArray[i], text.c_str());
			printf(" (HEX: ");
			for (auto &v : decrypted_string) {
				printf("%02X ", v);
			}
			printf(")\n");
		}
		else {
			printf("%d : %llX : err = %d\n", i, StringPoolArray[i], err);
		}
	}

	system("pause");
	return 0;
}