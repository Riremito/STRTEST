#ifndef __FROST_H__
#define __FROST_H__

#include<Windows.h>
#include<winternl.h>
#include<string>
#include<vector>

class Frost {
private:
	// input
	std::wstring input_file_path;
	HANDLE input_file_handle;
	HANDLE input_file_map;
	void *input_file_data;
	DWORD input_file_size;
	DWORD input_file_size_high;
	// reader
	ULONG_PTR ImageBase;
	std::vector<IMAGE_SECTION_HEADER> image_section_headers;

	bool Open();
public:
	Frost(const WCHAR *wPath);
	~Frost();
	bool Parse();
	ULONG_PTR GetRawAddress(ULONG_PTR uVirtualAddress);
	ULONG_PTR GetVirtualAddress(ULONG_PTR uRawAddress);
	ULONG_PTR AobScan(std::wstring wAob);
	void test();
};

#endif