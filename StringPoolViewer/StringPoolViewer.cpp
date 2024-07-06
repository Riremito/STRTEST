// https://github.com/Riremito/tools/tree/develop
#include"Simple.h"
#include"Frost.h"

#define TEST_EXE_PATH_2 L"C:\\Users\\elfenlied\\Desktop\\Elfenlied\\IDB\\unpacked_MapleStory261.4.exe"

// string pool part
BYTE StringPool__ms_aKey[16] = { 0xD6,0xDE,0x75,0x86,0x46,0x64,0xA3,0x71,0xE8,0xE6,0x7B,0xD3,0x33,0x30,0xE7,0x2E };
const int StringPool__ms_nKeySize = sizeof(StringPool__ms_aKey);
ULONG_PTR StringPool__ms_aString = 0x1474C4240;
int StringPool_Size = 17168;

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

	// rotate
	if ((seed >> 3)) {
		BYTE shift = (seed >> 3) % StringPool__ms_nKeySize;
		if (shift) {
			for (int i = 0; i < StringPool__ms_nKeySize; i++) {
				key[i] = StringPool__ms_aKey[(i + shift) % StringPool__ms_nKeySize];
			}
		}
	}
	else {
		// no rotate
		for (int i = 0; i < StringPool__ms_nKeySize; i++) {
			key[i] = StringPool__ms_aKey[i];
		}
	}

	// generate key
	if (seed & 7) {
		BYTE shift = seed & 7;
		if (shift) {
			BYTE bit = 0;
			bit = (BYTE)(key[0] >> (8 - shift));

			for (int i = 0; i < StringPool__ms_nKeySize; i++) {
				BYTE left = 0;
				if (i != (StringPool__ms_nKeySize - 1)) {
					left = (BYTE)(key[i + 1] >> (8 - shift));
				}
				BYTE right = (BYTE)(key[i] << shift);
				key[i] = left | right;
			}
			key[StringPool__ms_nKeySize - 1] |= bit;
		}
	}

	return true;
}

int DecodeStringPool(StringPoolData *spd, std::vector<BYTE> &decrypted_string) {
	BYTE key[StringPool__ms_nKeySize] = { 0 };
	// generate decryption key
	if (!rotatel(key, spd->seed & ~0x80)) {
		return 1;
	}

	for (int i = 0; spd->encrypted_string[i]; i++) {
		BYTE chr = spd->encrypted_string[i];
		if (chr != key[i % 0x10]) {
			chr ^= key[i % 0x10];
		}
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
		case '\t': {
			decrypted_string.push_back('\\');
			decrypted_string.push_back('t');
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
		return 2;
	}

	return 0;
}

// data to string part
std::wstring BYTEtoString(BYTE b) {
	std::wstring wb;
	WCHAR high = (b >> 4) & 0x0F;
	WCHAR low = b & 0x0F;

	high += (high <= 0x09) ? 0x30 : 0x37;
	low += (low <= 0x09) ? 0x30 : 0x37;

	wb.push_back(high);
	wb.push_back(low);

	return wb;
}

std::wstring WORDtoString(WORD w) {
	std::wstring ww;

	ww += BYTEtoString((w >> 8) & 0xFF);
	ww += BYTEtoString(w & 0xFF);

	return ww;
}

std::wstring DWORDtoString(DWORD dw) {
	std::wstring wdw;

	wdw += BYTEtoString((dw >> 24) & 0xFF);
	wdw += BYTEtoString((dw >> 16) & 0xFF);
	wdw += BYTEtoString((dw >> 8) & 0xFF);
	wdw += BYTEtoString(dw & 0xFF);
	return wdw;
}

std::wstring DatatoString(BYTE *b, ULONG_PTR Length, bool space) {
	std::wstring wdata;

	for (ULONG_PTR i = 0; i < Length; i++) {
		if (space) {
			if (i) {
				wdata.push_back(L' ');
			}
		}
		wdata += BYTEtoString(b[i]);
	}

	return wdata;
}

std::wstring QWORDtoString(ULONG_PTR u) {
	std::wstring wdw;

	wdw += BYTEtoString((u >> 56) & 0xFF);
	wdw += BYTEtoString((u >> 48) & 0xFF);
	wdw += BYTEtoString((u >> 40) & 0xFF);
	wdw += BYTEtoString((u >> 32) & 0xFF);
	wdw += BYTEtoString((u >> 24) & 0xFF);
	wdw += BYTEtoString((u >> 16) & 0xFF);
	wdw += BYTEtoString((u >> 8) & 0xFF);
	wdw += BYTEtoString(u & 0xFF);
	return wdw;
}

bool to_wstring(UINT codepage, std::vector<BYTE> &str, std::wstring &utf16) {
	try {
		// UTF16へ変換する際の必要なバイト数を取得
		int len = MultiByteToWideChar(codepage, 0, (char *)&str[0], -1, 0, 0);
		if (!len) {
			return false;
		}

		// UTF16へ変換
		std::vector<BYTE> b((len + 1) * sizeof(WORD));
		if (!MultiByteToWideChar(codepage, 0, (char *)&str[0], -1, (WCHAR *)&b[0], len)) {
			return false;
		}

		utf16 = std::wstring((WCHAR *)&b[0]);
		return true;
	}
	catch (...) {
		return false;
	}

	return true;
}

// gui part
enum SubControl {
	RESERVED,
	LISTVIEW_VIEWER,
	EDIT_SELECTED,
	STATIC_PATH,
	STATIC_ADDR_ARRAY,
	STATIC_ADDR_CODEPAGE,
	STATIC_ADDR_SIZE,
	EDIT_PATH,
	EDIT_ADDR_ARRAY,
	EDIT_ADDR_CODEPAGE,
	EDIT_ADDR_SIZE,
	BUTTON_AOBSCAN,
	BUTTON_LOAD,
	TEXTAREA_INFO,
	BUTTON_DUMP,
};

enum ListViewIndex {
	LV_ID,
	LV_VA,
	//LV_RA,
	LV_STRING,
};

#define VIEWER_WIDTH 800
#define VIEWER_HEIGHT 600

bool LoadData(Alice &a) {
	Frost f(TEST_EXE_PATH_2);

	if (!f.Parse()) {
		return false;
	}

	ULONG_PTR *StringPoolArray = (ULONG_PTR *)f.GetRawAddress(StringPool__ms_aString);

	for (int i = 0; i < StringPool_Size; i++) {
		StringPoolData *spd = (StringPoolData *)f.GetRawAddress(StringPoolArray[i]);
		std::vector<BYTE> decrypted_string;
		int err = DecodeStringPool(spd, decrypted_string);
		if (err == 0) {
			std::string text = std::string((char *)&decrypted_string[0]);
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_ID, std::to_wstring(i));
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_VA, QWORDtoString(StringPoolArray[i]));
			std::wstring wtext;
			to_wstring(CP_UTF8, decrypted_string, wtext);
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_STRING, L"\"" + wtext + L"\"");
		}
		else {
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_ID, std::to_wstring(i));
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_VA, QWORDtoString(StringPoolArray[i]));
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_STRING, L"ERROR = " + std::to_wstring(err));
		}
	}
	return true;
}

typedef struct {
	bool OK;
	Alice *a;
	std::wstring path;
	ULONG_PTR uStringPoolArrayAddr;
	int ArraySize;
	UINT codepage;
} ThreadArg;

ThreadArg gThreadArg;
std::vector<std::wstring> dumpdata;
bool LoadDataThread() {
	Alice &a = *gThreadArg.a;
	std::wstring path = gThreadArg.path;
	ULONG_PTR uStringPoolArrayAddr = gThreadArg.uStringPoolArrayAddr;
	int ArraySize = gThreadArg.ArraySize;
	UINT codepage = gThreadArg.codepage;

	a.ListView_Clear(LISTVIEW_VIEWER);
	a.SetText(TEXTAREA_INFO, L"Loading StringPool Data...");
	dumpdata.clear();

	Frost f(path.c_str());

	if (!f.Parse()) {
		a.SetText(TEXTAREA_INFO, L"unable to open exe file.");
		return false;
	}

	ULONG_PTR *StringPoolArray = (ULONG_PTR *)f.GetRawAddress(uStringPoolArrayAddr);

	for (int i = 0; i < ArraySize; i++) {
		StringPoolData *spd = (StringPoolData *)f.GetRawAddress(StringPoolArray[i]);
		std::vector<BYTE> decrypted_string;
		int err = DecodeStringPool(spd, decrypted_string);
		if (err == 0) {
			std::string text = std::string((char *)&decrypted_string[0]);
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_ID, std::to_wstring(i));
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_VA, QWORDtoString(StringPoolArray[i]));
			std::wstring wtext;
			to_wstring(codepage, decrypted_string, wtext);
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_STRING, L"\"" + wtext + L"\"");
			dumpdata.push_back(std::to_wstring(i) + L" | " + QWORDtoString(StringPoolArray[i]) + L" | " + L"\"" + wtext + L"\"");
		}
		else {
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_ID, std::to_wstring(i));
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_VA, QWORDtoString(StringPoolArray[i]));
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_STRING, L"ERROR = " + std::to_wstring(err));
			dumpdata.push_back(std::to_wstring(i) + L" | " + QWORDtoString(StringPoolArray[i]) + L" | " + L"ERROR = " + std::to_wstring(err));
		}
	}

	gThreadArg.OK = true;
	a.SetText(TEXTAREA_INFO, L"String Pool is loaded! OK!");
	return true;
}
bool LoadData(Alice &a, std::wstring path, ULONG_PTR uStringPoolArrayAddr, int ArraySize, UINT codepage) {
	if (!gThreadArg.OK) {
		return false;
	}

	gThreadArg.OK = false;
	gThreadArg.a = &a;
	gThreadArg.path = path;
	gThreadArg.uStringPoolArrayAddr = uStringPoolArrayAddr;
	gThreadArg.ArraySize = ArraySize;
	gThreadArg.codepage = codepage;

	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)LoadDataThread, NULL, NULL, NULL);
	if (hThread) {
		CloseHandle(hThread);
	}

	return true;
}

bool OnCreate(Alice &a) {
	a.ListView(LISTVIEW_VIEWER, 3, 3, (VIEWER_WIDTH - 6), (VIEWER_HEIGHT * 2 / 3 - 6));
	a.ListView_AddHeader(LISTVIEW_VIEWER, L"ID", 60);
	a.ListView_AddHeader(LISTVIEW_VIEWER, L"VA", 120);
	a.ListView_AddHeader(LISTVIEW_VIEWER, L"String", (VIEWER_WIDTH - 200));
	a.EditBox(EDIT_SELECTED, 3, (VIEWER_HEIGHT * 2 / 3), L"", (VIEWER_WIDTH - 6));

	a.TextArea(TEXTAREA_INFO, 3, 450, 394, 130);
	a.ReadOnly(TEXTAREA_INFO);

	a.StaticText(STATIC_PATH,       L"Path  :", 400, 450);
	a.StaticText(STATIC_ADDR_ARRAY, L"Array :", 400, 470);
	a.StaticText(STATIC_ADDR_CODEPAGE,   L"CP    :", 400, 490);
	a.StaticText(STATIC_ADDR_SIZE,  L"Size  :", 400, 510);
	a.EditBox(EDIT_PATH,       450, 450, TEST_EXE_PATH_2, 300);
	a.EditBox(EDIT_ADDR_ARRAY, 450, 470, L"1474C4240", 300);
	a.EditBox(EDIT_ADDR_CODEPAGE,   450, 490, L"65001", 300);
	a.EditBox(EDIT_ADDR_SIZE,  450, 510, L"17168", 300);
	a.Button(BUTTON_DUMP, L"Dump", 640, 530, 50);
	a.Button(BUTTON_LOAD, L"Load", 700, 530, 50);
	DragAcceptFiles(a.GetMainHWND(), TRUE);
	return true;
}

bool OnCommand(Alice &a, int nIDDlgItem) {
	if (nIDDlgItem == BUTTON_LOAD) {
		std::wstring path = a.GetText(EDIT_PATH);
		std::wstring text_array = a.GetText(EDIT_ADDR_ARRAY);
		ULONG_PTR addr_array = 0;
		swscanf_s(text_array.c_str(), L"%llX", &addr_array);
		std::wstring text_cp = a.GetText(EDIT_ADDR_CODEPAGE);
		std::wstring text_size = a.GetText(EDIT_ADDR_SIZE);
		a.ListView_Clear(LISTVIEW_VIEWER);
		LoadData(a, path, addr_array, _wtoi(text_size.c_str()), _wtoi(text_cp.c_str()));
		return true;
	}
	if (nIDDlgItem == BUTTON_DUMP && dumpdata.size() && gThreadArg.OK == true) {
		a.SetText(TEXTAREA_INFO, L"Dumping StringPool Data...");
		FILE *fp = NULL;
		if (fopen_s(&fp, "StringPoolDump.txt", "wb") == 0) {
			for (auto &v : dumpdata) {
				fwprintf_s(fp, L"%s\n", v.c_str());
			}
			fclose(fp);
		}
		a.SetText(TEXTAREA_INFO, L"StringPool is dumped!");
		return true;
	}
	return true;
}

bool OnNotify(Alice &a, int nIDDlgItem) {
	if (nIDDlgItem == LISTVIEW_VIEWER) {
		std::wstring text_id;
		std::wstring text_va;
		std::wstring text_string;

		a.ListView_Copy(LISTVIEW_VIEWER, LV_ID, text_id, false);
		a.ListView_Copy(LISTVIEW_VIEWER, LV_VA, text_va, false);
		a.ListView_Copy(LISTVIEW_VIEWER, LV_STRING, text_string, true, 4096);
		a.SetText(EDIT_SELECTED, text_id + L" | " + text_va + L" | " + text_string);
		return true;
	}

	return true;
}

bool OnDropFile(Alice &a, wchar_t *drop) {
	a.SetText(EDIT_PATH, drop);
	return true;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
	gThreadArg.OK = true;
	Alice a(L"StringPoolViewerClass", L"StringPoolViewer test ver", 800, 600, hInstance);
	a.SetOnCreate(OnCreate);
	a.SetOnCommand(OnCommand);
	a.SetOnNotify(OnNotify);
	a.SetOnDropFile(OnDropFile);
	a.Run();
	a.Wait();
	return 0;
}
