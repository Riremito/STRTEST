#include"AobScanner.h"

#define AOB_DEC_KEY L"D6 DE 75 86 46 64 A3 71 E8 E6 7B D3 33 30 E7 2E"
AddrInfo FindDecKEY(Frost &f) {
	return f.AobScan(AOB_DEC_KEY);
}

AddrInfo FindArray(Frost &f) {
	AddrInfo ai = { 0 };
	// x64
	if (f.Isx64()) {
		AddrInfo StringPoolRefAddr = f.AobScan(L"48 81 EC ?? ?? ?? ?? 4? 8? ?? 48 63 C2 48 8D ?? ?? ?? ?? ?? 4? 8? ?? C?"); // JMS v425.1
		if (StringPoolRefAddr.VA) {
			return f.GetAddrInfo(StringPoolRefAddr.VA + 0x0D + *(signed long int *)(StringPoolRefAddr.RA + 0x0D + 0x03) + 0x07);
		}
		StringPoolRefAddr = f.AobScan(L"48 83 EC ?? 4? 8? ?? 48 63 C2 48 8D ?? ?? ?? ?? ?? 4? 8? ?? C?"); // KMS v2.388.3, MSEA v234.1, TWMS v261.4
		if (StringPoolRefAddr.VA) {
			return f.GetAddrInfo(StringPoolRefAddr.VA + 0x0A + *(signed long int *)(StringPoolRefAddr.RA + 0x0A + 0x03) + 0x07);
		}
		return ai;
	}
	// x86
	AddrInfo StringPoolRefAddr = f.AobScan(L"75 ?? 8B 86 ?? ?? ?? ?? 0F BE 00 6A 04"); // JMS v186.1
	if (StringPoolRefAddr.VA) {
		return f.GetAddrInfo(*(DWORD *)(StringPoolRefAddr.RA + 0x02 + 0x02));
	}
	StringPoolRefAddr = f.AobScan(L"75 ?? 8B 0C 9D ?? ?? ?? ?? 0F BE 11 6A 04"); // JMS v194.0
	if (StringPoolRefAddr.VA) {
		return f.GetAddrInfo(*(DWORD *)(StringPoolRefAddr.RA + 0x02 + 0x03));
	}
	StringPoolRefAddr = f.AobScan(L"0F 85 ?? ?? ?? ?? 8B 0C AD ?? ?? ?? ?? 0F BE 11 6A 04"); // CMS v86.1
	if (StringPoolRefAddr.VA) {
		return f.GetAddrInfo(*(DWORD *)(StringPoolRefAddr.RA + 0x06 + 0x03));
	}

	return ai;
}