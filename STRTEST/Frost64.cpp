#include"Frost64.h"

// public
Frost::Frost(const WCHAR *wPath) {
	input_file_path = wPath;
	input_file_handle = INVALID_HANDLE_VALUE;
	input_file_map = NULL;
	input_file_size = 0;
	input_file_size_high = 0;
	input_file_data = 0;
	ImageBase = 0;
}

Frost::~Frost() {
	if (input_file_data) {
		UnmapViewOfFile(input_file_data);
	}
	if (input_file_map) {
		CloseHandle(input_file_map);
	}
	if (input_file_handle != INVALID_HANDLE_VALUE) {
		CloseHandle(input_file_handle);
	}
}

bool Frost::Parse() {
	if (!Open()) {
		puts("Open failed");
		return false;
	}

	DWORD req_size = 0;
	ULONG_PTR base = (ULONG_PTR)input_file_data;

	req_size += sizeof(IMAGE_DOS_HEADER);
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)base;
	if (input_file_size < req_size) {
		return false;
	}
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}
	// IMAGE_DOS_HEADER
	req_size = idh->e_lfanew + sizeof(DWORD); // checkplz
	IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS *)(base + idh->e_lfanew);
	if (input_file_size < req_size) {
		return false;
	}
	if (inh->Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}
	req_size += sizeof(IMAGE_FILE_HEADER);
	if (input_file_size < req_size) {
		return false;
	}
	// x86
	if (inh->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		return false;
	}
	// x64
	else if (inh->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		// not coded yet
		if (inh->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) - (sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)) {
			return false;
		}
		req_size += inh->FileHeader.SizeOfOptionalHeader;
		if (input_file_size < req_size) {
			return false;
		}
		IMAGE_OPTIONAL_HEADER64 *ioh64 = &inh->OptionalHeader;
		if (ioh64->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			return false;
		}
		// IMAGE_SUBSYSTEM_WINDOWS_GUI or IMAGE_SUBSYSTEM_WINDOWS_CUI
		if (ioh64->NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
			// not supported now
			return false;
		}
		// Section Header
		req_size += sizeof(IMAGE_SECTION_HEADER) * inh->FileHeader.NumberOfSections;
		IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *)((ULONG_PTR)ioh64 + inh->FileHeader.SizeOfOptionalHeader);
		if (input_file_size < req_size) {
			return false;
		}
		// fixed base addr
		ImageBase = ioh64->ImageBase;
		// section info
		for (WORD i = 0; i < inh->FileHeader.NumberOfSections; i++) {
			image_section_headers.push_back(ish[i]);
		}
	}
	else {
		return false;
	}

	return true;
}

ULONG_PTR Frost::GetRawAddress(ULONG_PTR uVirtualAddress) {
	if (!ImageBase) {
		return 0;
	}

	for (size_t i = 0; image_section_headers.size(); i++) {
		ULONG_PTR section_start = ImageBase + image_section_headers[i].VirtualAddress;
		ULONG_PTR section_end = section_start + image_section_headers[i].Misc.VirtualSize;

		// convert
		if (section_start <= uVirtualAddress && uVirtualAddress <= section_end) {
			return uVirtualAddress - section_start + image_section_headers[i].PointerToRawData + (ULONG_PTR)input_file_data; // file offset
		}
	}
	return 0;
}

void Frost::test() {
	for (auto &v : image_section_headers) {
		char section_name[9] = { 0 };
		memcpy_s(section_name, 8, v.Name, 8);
		printf("%llX : \"%s\"\n", ImageBase + v.VirtualAddress ,section_name);
	}
}

// private
bool Frost::Open() {
	input_file_handle = CreateFileW(input_file_path.c_str(), GENERIC_READ, (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (input_file_handle == INVALID_HANDLE_VALUE) {
		return false;
	}

	input_file_size = GetFileSize(input_file_handle, &input_file_size_high);
	if (input_file_size_high || input_file_size < 2) {
		return false;
	}

	input_file_map = CreateFileMappingW(input_file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!input_file_map) {
		return false;
	}

	input_file_data = MapViewOfFile(input_file_map, FILE_MAP_READ, 0, 0, 0);
	if (!input_file_data) {
		return false;
	}

	return true;
}