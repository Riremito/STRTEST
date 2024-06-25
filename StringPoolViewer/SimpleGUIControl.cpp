#include"Simple.h"

// create
bool Alice::StaticText(size_t nIDDlgItem, std::wstring wText, int X, int Y) {
	if (!main_hwnd) {
		return false;
	}

	HWND hWnd = CreateWindowExW(NULL, L"STATIC", wText.c_str(), WS_CHILD | WS_VISIBLE | ES_LEFT, X, (Y + 3), AutoWidth(wText), 13, main_hwnd, (HMENU)nIDDlgItem, main_instance, NULL);
	if (!hWnd) {
		return false;
	}

	control_hwnd_list.push_back(hWnd);
	control_id_list.push_back(nIDDlgItem);

	SetFont(nIDDlgItem);
	return true;
}

bool Alice::Button(size_t nIDDlgItem, std::wstring wText, int X, int Y, int nWidth) {
	if (!main_hwnd) {
		return false;
	}

	int width = nWidth;
	if (!width) {
		width = AutoWidth(wText) + 12;
	}

	HWND hWnd = CreateWindowExW(NULL, L"BUTTON", wText.c_str(), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, X, (Y + 1), width, 18, main_hwnd, (HMENU)nIDDlgItem, main_instance, NULL);
	if (!hWnd) {
		return false;
	}

	control_hwnd_list.push_back(hWnd);
	control_id_list.push_back(nIDDlgItem);

	SetFont(nIDDlgItem);
	return true;
}

bool Alice::CheckBox(size_t nIDDlgItem, std::wstring wText, int X, int Y, UINT uCheck) {
	if (!main_hwnd) {
		return false;
	}

	HWND hWnd = CreateWindowExW(NULL, L"BUTTON", wText.c_str(), WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, X, (Y + 3), AutoWidth(wText) + 15, 13, main_hwnd, (HMENU)nIDDlgItem, main_instance, NULL);
	if (!hWnd) {
		return false;
	}

	control_hwnd_list.push_back(hWnd);
	control_id_list.push_back(nIDDlgItem);

	SetFont(nIDDlgItem);
	CheckDlgButton(main_hwnd, (int)nIDDlgItem, uCheck);
	return true;
}

bool Alice::EditBox(size_t nIDDlgItem, int X, int Y, std::wstring wText, int nWidth) {
	if (!main_hwnd) {
		return false;
	}

	int width = nWidth;
	if (!width) {
		width = AutoWidth(wText) + 6;
	}

	HWND hWnd = CreateWindowExW(NULL, L"EDIT", wText.c_str(), WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL | WS_BORDER, X, (Y + 2), width, 16, main_hwnd, (HMENU)nIDDlgItem, main_instance, NULL);
	if (!hWnd) {
		return false;
	}

	control_hwnd_list.push_back(hWnd);
	control_id_list.push_back(nIDDlgItem);

	SetFont(nIDDlgItem);
	return true;
}

bool Alice::TextArea(size_t nIDDlgItem, int X, int Y, int nWidth, int nHeight) {
	if (!main_hwnd) {
		return false;
	}

	HWND hWnd = CreateWindowExW(NULL, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL | WS_BORDER | ES_MULTILINE | WS_VSCROLL, X, (Y + 2), nWidth, nHeight, main_hwnd, (HMENU)nIDDlgItem, main_instance, NULL);
	if (!hWnd) {
		return false;
	}

	control_hwnd_list.push_back(hWnd);
	control_id_list.push_back(nIDDlgItem);

	SetFont(nIDDlgItem);
	return true;
}

bool Alice::ListView(size_t nIDDlgItem, int X, int Y, int nWidth, int nHeight) {
	static bool init = false;
	if (!init) {
		init = true;
		INITCOMMONCONTROLSEX icex = { sizeof(icex) };
		icex.dwICC = ICC_LISTVIEW_CLASSES;
		InitCommonControlsEx(&icex);
	}

	if (!main_hwnd) {
		return false;
	}

	HWND hWnd = CreateWindowExW(NULL, L"SysListView32", NULL, LVS_REPORT | WS_CHILD | LVS_NOSORTHEADER | WS_BORDER | LVS_SINGLESEL | LVS_SHOWSELALWAYS, X, (Y + 1), nWidth, nHeight, main_hwnd, (HMENU)nIDDlgItem, main_instance, NULL);
	if (!hWnd) {
		return false;
	}

	LRESULT exstyle = SendMessageW(hWnd, LVM_GETEXTENDEDLISTVIEWSTYLE, 0, 0);
	SendMessageW(hWnd, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, exstyle | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	control_hwnd_list.push_back(hWnd);
	control_id_list.push_back(nIDDlgItem);
	listview_id_list.push_back(nIDDlgItem);
	listview_previous_selected.push_back(-1);

	SetFont(nIDDlgItem);
	ShowWindow(hWnd, SW_SHOW);
	return true;
}

bool Alice::ComboBox(size_t nIDDlgItem, int X, int Y, int nWidth) {
	if (!main_hwnd) {
		return false;
	}

	HWND hWnd = CreateWindowExW(NULL, L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_SORT | CBS_SIMPLE | CBS_DROPDOWNLIST, X, (Y + 2), nWidth, 16, main_hwnd, (HMENU)nIDDlgItem, main_instance, NULL);
	if (!hWnd) {
		return false;
	}

	SendMessageW(hWnd, CB_DIR, DDL_READWRITE, (LPARAM)L"C:\\Windows\\*.*");

	control_hwnd_list.push_back(hWnd);
	control_id_list.push_back(nIDDlgItem);

	SetFont(nIDDlgItem);
	return true;
}

// do something
bool Alice::ReadOnly(size_t nIDDlgItem, WPARAM wParam) {
	if (!main_hwnd) {
		return false;
	}

	SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, EM_SETREADONLY, wParam, NULL);
	return true;
}

bool Alice::SetText(size_t nIDDlgItem, std::wstring wText) {
	if (!main_hwnd) {
		return false;
	}

	SetDlgItemTextW(main_hwnd, (int)nIDDlgItem, wText.c_str());
	return true;
}

std::wstring Alice::GetText(size_t nIDDlgItem) {
	if (!main_hwnd) {
		return L"";
	}

	LRESULT length = SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, WM_GETTEXTLENGTH, NULL, NULL);
	std::vector<wchar_t> data;
	data.resize(length + 1);
	GetDlgItemTextW(main_hwnd, (int)nIDDlgItem, &data[0], (int)(length + 1));
	return std::wstring((wchar_t *)&data[0]);
}

bool Alice::AddText(size_t nIDDlgItem, std::wstring wText) {
	if (!main_hwnd) {
		return false;
	}

	LRESULT cursor = SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, WM_GETTEXTLENGTH, NULL, NULL);
	std::wstring text = wText;

	if (cursor != 0) {
		text = L"\r\n" + text;
	}

	SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, EM_SETSEL, cursor, cursor);
	SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, EM_REPLACESEL, NULL, (LPARAM)text.c_str());
	SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, EM_SCROLL, SB_BOTTOM, NULL);
	return true;
}

LRESULT Alice::CheckBoxStatus(size_t nIDDlgItem) {
	if (!main_hwnd) {
		return false;
	}

	return SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, BM_GETCHECK, 0, 0);
}

// private
bool Alice::SetFont(size_t nIDDlgItem) {
	static HFONT font = CreateFontW(12, NULL, NULL, NULL, FW_NORMAL, NULL, NULL, NULL, SHIFTJIS_CHARSET, NULL, NULL, NULL, NULL, L"�l�r �S�V�b�N");
	if (!font) {
		return false;
	}

	if (!main_hwnd) {
		return false;
	}

	SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, WM_SETFONT, (WPARAM)font, NULL);
	return true;
}

int Alice::AutoWidth(std::wstring wText) {
	return (int)(wText.length() * 6);
}

bool Alice::Embed(HWND hWnd, int nWidth, int nHeight) {
	SetWindowLongW(hWnd, GWL_STYLE, WS_CHILD | WS_POPUP);
	ShowWindow(hWnd, SW_SHOW);
	SetParent(hWnd, main_hwnd);
	SetWindowPos(hWnd, HWND_TOP, 0, 0, nWidth, nHeight, NULL);
	return true;
}