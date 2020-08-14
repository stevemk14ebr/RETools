#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <map>

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

class ManualMapper {
public:
	HMODULE mapImage(std::wstring imagePath);
	std::vector<std::string> getExports(HMODULE moduleBase);
	uint64_t getProcAddress(HMODULE hModule, std::string procName);
private:
	struct ExportDirectoryPtrs {
		uint32_t* addressOfFunctions;
		uint32_t* addressOfNames;
		uint16_t* addressOfNameOrdinals;
		IMAGE_EXPORT_DIRECTORY* exports;
	};

	ExportDirectoryPtrs getExportDir(HMODULE moduleBase);
	bool loadImage(char* imageBase);
	bool validateImage(char* imageBase);
	std::map<HMODULE, std::wstring> loadedImages;
};

typedef bool (__stdcall*tDllMain)(char* hDll, uint32_t dwReason, char* pReserved);
