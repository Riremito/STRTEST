// https://github.com/Riremito/tools/tree/develop
#include"Simple.h"
#include"Frost.h"
#include"StringPool.h"
#include"Formatter.h"
#include"AobScanner.h"

// gui part
enum SubControl {
	RESERVED,
	LISTVIEW_VIEWER,
	EDIT_SELECTED,
	STATIC_PATH,
	STATIC_ADDR_KEY,
	STATIC_ADDR_ARRAY,
	STATIC_ADDR_CODEPAGE,
	STATIC_ADDR_SIZE,
	EDIT_PATH,
	EDIT_ADDR_KEY,
	EDIT_ADDR_ARRAY,
	EDIT_CODEPAGE,
	EDIT_ARRAY_SIZE,
	COMBOBOX_CODEPAGE,
	BUTTON_AOBSCAN,
	BUTTON_LOAD,
	TEXTAREA_INFO,
	BUTTON_DUMP,
	BUTTON_SCAN,
};

enum ListViewIndex {
	LV_ID,
	LV_VA,
	//LV_RA,
	LV_STRING,
};

#define VIEWER_WIDTH 800
#define VIEWER_HEIGHT 600

typedef struct {
	bool OK;
	Alice *a;
	std::wstring path;
	ULONG_PTR Addr_Key;
	ULONG_PTR Addr_Array;
	int ArraySize;
	UINT codepage;
} ThreadArg;

ThreadArg gThreadArg;
std::vector<std::wstring> dumpdata;
#define ADDINFO(str) a.AddText(TEXTAREA_INFO, str)
#define SCANINFO(asr) ADDINFO(L"[" #asr L"]\r\nAddress: " + (f.Isx64() ? QWORDtoString(asr.VA, true) : DWORDtoString((DWORD)asr.VA)) + L"\r\nOffset : " + DWORDtoString((DWORD)asr._RRA))
#define ADDRTOSTRING(ai) (f.Isx64() ? QWORDtoString(ai.VA, true) : DWORDtoString((DWORD)ai.VA))

bool AccessTest(ULONG_PTR uAddr) {
	__try {
		if (IsBadReadPtr((void *)uAddr, 2)) {
			return false;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}

	return true;
}

bool LoadDataThread() {
	Alice &a = *gThreadArg.a;
	std::wstring path = gThreadArg.path;
	ULONG_PTR uAddrKey = gThreadArg.Addr_Key;
	ULONG_PTR uAddrArray = gThreadArg.Addr_Array;
	int ArraySize = gThreadArg.ArraySize;
	UINT codepage = gThreadArg.codepage;

	a.ListView_Clear(LISTVIEW_VIEWER);
	ADDINFO(L"Loading...");
	dumpdata.clear();

	Frost f(path.c_str());

	if (!f.Parse()) {
		gThreadArg.OK = true;
		ADDINFO(L"Error! unable to open exe file.");
		return false;
	}

	AddrInfo StringPool__ms_aKey = { 0 };
	if (!uAddrKey) {
		ADDINFO(L"checking KEY...");
		StringPool__ms_aKey = FindDecKEY(f);
		if (!StringPool__ms_aKey.VA) {
			gThreadArg.OK = true;
			ADDINFO(L"Error! KEY not found.");
			return false;
		}
		a.SetText(EDIT_ADDR_KEY, ADDRTOSTRING(StringPool__ms_aKey));
	}
	else {
		StringPool__ms_aKey = f.GetAddrInfo(uAddrKey);
	}
	SCANINFO(StringPool__ms_aKey);

	AddrInfo StringPool__Array = { 0 };
	if (!uAddrArray) {
		ADDINFO(L"finding Array...");
		std::wstring wAobRes;
		StringPool__Array = FindArray(f, wAobRes);
		if (!StringPool__Array.VA) {
			gThreadArg.OK = true;
			ADDINFO(L"Error! Array not found");
			return false;
		}
		a.SetText(EDIT_ADDR_ARRAY, ADDRTOSTRING(StringPool__Array));
		ADDINFO(wAobRes);
	}
	else {
		StringPool__Array = f.GetAddrInfo(uAddrArray);
	}
	SCANINFO(StringPool__Array);

	ADDINFO(L"loading...");
	StringPool sp(codepage, (BYTE *)StringPool__ms_aKey.RA, 16);
	if (f.Isx64()) {
		ULONG_PTR *StringPool__Array64 = (ULONG_PTR *)StringPool__Array.RA;
		for (int i = 0; i < ArraySize; i++) {
			StringPoolData *spd = (StringPoolData *)f.GetRawAddress(StringPool__Array64[i]);
			if (!spd) {
				ADDINFO(L"Warning! Array reached null ptr. size = " + std::to_wstring(i));
				a.SetText(EDIT_ARRAY_SIZE, std::to_wstring(i));
				break;
			}
			if (strncmp((char *)&spd->shift, "SID_", 4) == 0 || strncmp((char *)&spd->shift, " _-:", 4) == 0) {
				ADDINFO(L"Warning! Array size seems wrong. real size = " + std::to_wstring(i));
				a.SetText(EDIT_ARRAY_SIZE, std::to_wstring(i));
				break;
			}
			std::wstring wtext = sp.DecodeWStr(spd);
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_ID, std::to_wstring(i));
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_VA, QWORDtoString(StringPool__Array64[i], true));
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_STRING, L"\"" + wtext + L"\"");
			dumpdata.push_back(std::to_wstring(i) + L" | " + QWORDtoString(StringPool__Array64[i], true) + L" | " + L"\"" + wtext + L"\"");
		}
	}
	else {
		DWORD *StringPool__Array32 = (DWORD *)StringPool__Array.RA;
		for (int i = 0; i < ArraySize; i++) {
			StringPoolData *spd = (StringPoolData *)f.GetRawAddress(StringPool__Array32[i]);
			if (!AccessTest((ULONG_PTR)spd)) {
				ADDINFO(L"Error! Array reached invalid ptr. size = " + std::to_wstring(i));
				a.SetText(EDIT_ARRAY_SIZE, std::to_wstring(i));
				break;
			}
			if (!spd) {
				ADDINFO(L"Warning! Array reached null ptr. size = " + std::to_wstring(i));
				a.SetText(EDIT_ARRAY_SIZE, std::to_wstring(i));
				break;
			}
			if (strncmp((char *)&spd->shift, "SID_", 4) == 0 || strncmp((char *)&spd->shift, " _-:", 4) == 0) {
				ADDINFO(L"Warning! Array size seems wrong. real size = " + std::to_wstring(i));
				a.SetText(EDIT_ARRAY_SIZE, std::to_wstring(i));
				break;
			}
			std::wstring wtext = sp.DecodeWStr(spd);
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_ID, std::to_wstring(i));
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_VA, DWORDtoString(StringPool__Array32[i]));
			a.ListView_AddItemWOS(LISTVIEW_VIEWER, LV_STRING, L"\"" + wtext + L"\"");
			dumpdata.push_back(std::to_wstring(i) + L" | " + DWORDtoString(StringPool__Array32[i]) + L" | " + L"\"" + wtext + L"\"");
		}
	}
	gThreadArg.OK = true;
	ADDINFO(L"OK!");
	return true;
}

bool LoadData(Alice &a, std::wstring path, ULONG_PTR uAddrKey, ULONG_PTR uAddrArray, int ArraySize, UINT codepage) {
	if (!gThreadArg.OK) {
		return false;
	}

	gThreadArg.OK = false;
	gThreadArg.a = &a;
	gThreadArg.path = path;
	gThreadArg.Addr_Key = uAddrKey;
	gThreadArg.Addr_Array = uAddrArray;
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
	a.StaticText(STATIC_ADDR_KEY,   L"KEY   :", 400, 470);
	a.StaticText(STATIC_ADDR_ARRAY, L"Array :", 400, 490);
	a.StaticText(STATIC_ADDR_CODEPAGE,   L"CP    :", 400, 510);
	a.StaticText(STATIC_ADDR_SIZE,  L"Size  :", 400, 530);
	a.EditBox(EDIT_PATH,       450, 450, L"Please Drop File", 300);
	a.EditBox(EDIT_ADDR_KEY, 450, 470, L"0", 300);
	a.EditBox(EDIT_ADDR_ARRAY, 450, 490, L"0", 300);
	a.ComboBox(COMBOBOX_CODEPAGE, 450, 510, 80);
	a.ComboBoxAdd(COMBOBOX_CODEPAGE, L"BIG5");
	a.ComboBoxAdd(COMBOBOX_CODEPAGE, L"EUC-KR");
	a.ComboBoxAdd(COMBOBOX_CODEPAGE, L"GBK");
	a.ComboBoxAdd(COMBOBOX_CODEPAGE, L"SHIFT-JIS");
	a.ComboBoxAdd(COMBOBOX_CODEPAGE, L"UTF8");
	a.ComboBoxSelect(COMBOBOX_CODEPAGE, 0);
	a.EditBox(EDIT_CODEPAGE, 550, 510, L"65001", 200);
	a.EditBox(EDIT_ARRAY_SIZE,  450, 530, L"30000", 300);
	a.Button(BUTTON_SCAN, L"Scan", 580, 550, 50);
	a.Button(BUTTON_DUMP, L"Dump", 640, 550, 50);
	a.Button(BUTTON_LOAD, L"Load", 700, 550, 50);
	return true;
}


UINT GetCodePage(std::wstring name) {
	if (name.compare(L"UTF8") == 0) {
		return CP_UTF8;
	}
	if (name.compare(L"SHIFT-JIS") == 0) {
		return 932;
	}
	if (name.compare(L"GBK") == 0) {
		return 936;
	}
	if (name.compare(L"EUC-KR") == 0) {
		return 949;
	}
	if (name.compare(L"BIG5") == 0) {
		return 950;
	}
	return CP_UTF8;
}

bool OnCommandEx(Alice &a, int nIDDlgItem, int msg) {
	if (nIDDlgItem == COMBOBOX_CODEPAGE && msg == CBN_SELCHANGE) {
		std::wstring wtext = a.ComboBoxGetSelectedText(COMBOBOX_CODEPAGE);
		UINT cp = GetCodePage(wtext);
		a.SetText(EDIT_CODEPAGE, std::to_wstring(cp));
		return true;
	}
	if (nIDDlgItem == BUTTON_LOAD) {
		std::wstring path = a.GetText(EDIT_PATH);
		std::wstring text_key = a.GetText(EDIT_ADDR_KEY);
		ULONG_PTR addr_key = 0;
		swscanf_s(text_key.c_str(), L"%llX", &addr_key);
		std::wstring text_array = a.GetText(EDIT_ADDR_ARRAY);
		ULONG_PTR addr_array = 0;
		swscanf_s(text_array.c_str(), L"%llX", &addr_array);
		std::wstring text_cp = a.GetText(EDIT_CODEPAGE);
		std::wstring text_size = a.GetText(EDIT_ARRAY_SIZE);
		a.ListView_Clear(LISTVIEW_VIEWER);
		LoadData(a, path, addr_key, addr_array, _wtoi(text_size.c_str()), _wtoi(text_cp.c_str()));
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
	if (nIDDlgItem == BUTTON_SCAN) {
		a.SetText(EDIT_ADDR_KEY, L"0");
		a.SetText(EDIT_ADDR_ARRAY, L"0");
		std::wstring path = a.GetText(EDIT_PATH);
		std::wstring text_cp = a.GetText(EDIT_CODEPAGE);
		a.ListView_Clear(LISTVIEW_VIEWER);
		a.SetText(EDIT_ARRAY_SIZE, L"30000");
		LoadData(a, path, 0, 0, 5, _wtoi(text_cp.c_str()));
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
	Alice a(L"StringPoolViewerClass", L"StringPool Viewer", VIEWER_WIDTH, VIEWER_HEIGHT, hInstance);
	a.SetOnCreate(OnCreate);
	a.SetOnCommandEx(OnCommandEx);
	a.SetOnNotify(OnNotify);
	a.SetOnDropFile(OnDropFile);
	a.Run();
	a.Wait();
	return 0;
}
