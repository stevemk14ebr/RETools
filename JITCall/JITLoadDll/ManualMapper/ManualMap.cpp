#include "ManualMap.hpp"


#include <memory>
#include <cassert>
#include <filesystem>

/*
Modified from: https://github.com/ItsJustMeChris/Manual-Mapper/blob/master/Heroin/needle.cpp
and
https://github.com/DarthTon/Blackbone/blob/master/src/BlackBone/ManualMap/MMap.cpp
*/

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

bool ManualMapper::loadImage(char* pBase) {
	if (!validateImage(pBase))
		return false;

	auto dosHeader = (IMAGE_DOS_HEADER*)pBase;
	auto ntHeader = (IMAGE_NT_HEADERS*)(pBase + dosHeader->e_lfanew);
	auto pOptionalHeader = &ntHeader->OptionalHeader;
	auto _DllMain = pOptionalHeader->AddressOfEntryPoint ? (tDllMain)(pBase + pOptionalHeader->AddressOfEntryPoint) : 0;

	// Fixup Relocs
	uint8_t* LocationDelta = (uint8_t*)(pBase - pOptionalHeader->ImageBase);
	if (LocationDelta) {
		if (!pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			std::cout << "[!] image not allocated at preffered base, but has no relocations, loading will attempt to continue" << std::endl;
		}

		auto pRelocData = (IMAGE_BASE_RELOCATION*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress) {
			uint32_t AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
			uint16_t* pRelativeInfo = ((uint16_t*)pRelocData + 1);

			for (uint32_t i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
				if (RELOC_FLAG(*pRelativeInfo)) {
					uintptr_t* pPatch = (uintptr_t*)(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += (uintptr_t)LocationDelta;
				}
			}
			pRelocData = (IMAGE_BASE_RELOCATION*)(((char*)pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	// Initialize security cookies (needed on drivers Win8+). They do a cmp against the constant in the header
	if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress) {
		uint64_t pCookie = 0;

		srand(time(0));
		switch (ntHeader->FileHeader.Machine) 
		case IMAGE_FILE_MACHINE_AMD64: {
			pCookie = (uint64_t)(((IMAGE_LOAD_CONFIG_DIRECTORY64*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress))->SecurityCookie);
			*(uint64_t*)pCookie = rand();

			// if we somehow hit default ++ it
			if (*(uint64_t*)pCookie == 0x2B992DDFA232)
				(*(uint64_t*)pCookie)++;

			break;
		case IMAGE_FILE_MACHINE_I386: 
			auto pLoadConfig32 = 
			pCookie = (uint64_t)(((IMAGE_LOAD_CONFIG_DIRECTORY32*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress))->SecurityCookie);
			*(uint32_t*)pCookie = rand();

			// if we somehow hit default ++ it
			if (*(uint32_t*)pCookie == 0xBB40E64E)
				(*(uint32_t*)pCookie)++;

			break;
		
		}
	}

	// Load deps and resolve imports
	if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		std::cout << "[+] loading images' dependency images and resolving imports" << std::endl;
		auto* pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = pBase + pImportDescr->Name;
			HINSTANCE hDll = LoadLibraryA(szMod);
			if (!hDll) {
				std::cout << "[!] Loading import module failed " << szMod << std::endl;
				continue;
			}

			uint64_t* pThunkRef = (uint64_t*)(pBase + pImportDescr->OriginalFirstThunk);
			uint64_t* pFuncRef = (uint64_t*)(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (uint64_t)GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				} else {
					auto pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
					*pFuncRef = (uint64_t)GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	// Execute TLS
	if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		std::cout << "[+] executing loaded images' TLS entries" << std::endl;
		auto pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback) {
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	// Execute main
	if (_DllMain) {
		std::cout << "[+] executing images' dllmain" << std::endl;
		_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);
	} else {
		std::cout << "[+] image has no dllmain" << std::endl;
	}
	std::cout << "[+] done" << std::endl;
	return true;
}

bool ManualMapper::validateImage(char* pBase) {
	assert(pBase);
	if (!pBase)
		return false;

	//Optional data
	auto dosHeader = (IMAGE_DOS_HEADER*)pBase;
	assert(dosHeader->e_magic == 0x5A4D);
	if (dosHeader->e_magic != 0x5A4D) {
		std::cout << "[!] image magic incorrect" << std::endl;
		return false;
	}
    
	auto ntHeader = (IMAGE_NT_HEADERS*)(pBase + dosHeader->e_lfanew);
	if (ntHeader->Signature != 0x4550) {
		std::cout << "[!] image nt header magic incorrect" << std::endl;
		return false;
	}

	return true;
}

HMODULE ManualMapper::mapImage(std::wstring imagePath) {
	std::unique_ptr<uint8_t> pSourceData = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptionalHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	uint8_t* pTargetBase = nullptr;

	//Check if the file exists
	if (!GetFileAttributesW(imagePath.c_str())) {
		std::cout << "[-] file doesn't exist" << std::endl;
		return NULL;
	}

	// Get the files data as binary
	std::ifstream file(std::filesystem::path(imagePath), std::ios::binary | std::ios::ate);

	// Check if we can open the file
	if (!file.good()) {
		std::cout << "[!] failed to open file" << std::endl;
		return NULL;
	}

	uintptr_t FileSize = file.tellg();
	pSourceData.reset(new uint8_t[FileSize]);
	if (!pSourceData) {
		std::cout << "[!] failed to allocate memory for file" << std::endl;
		return NULL;
	}

	file.seekg(0, std::ios::beg);
	file.read((char*)pSourceData.get(), FileSize);

	// close as soon as possible
	file.close();

	// Check if it's a valid PE file
	if (!validateImage((char*)pSourceData.get()))
		return NULL;

	// Save the old NT Header
	pOldNtHeader = (IMAGE_NT_HEADERS*)(pSourceData.get() + ((IMAGE_DOS_HEADER*)pSourceData.get())->e_lfanew);
	
	// Save the old optional header
	pOldOptionalHeader = &pOldNtHeader->OptionalHeader;
	
	// Save the old file header
	pOldFileHeader = &pOldNtHeader->FileHeader;
	
	if (FileSize < pOldOptionalHeader->SizeOfHeaders) {
		return NULL;
	}

	// Handle X86 and X64
#ifdef _WIN64
	// If the machine type is not the current file type we fail
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		std::cout << "[!] invalid platform: Loading x86 image via x64 process" << std::endl;
		printf("\n");
		return NULL;
	}
#else
	//If the machine type is not the current file type we fail
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
		std::cout << "[!] invalid platform: Loading x64 image via x86 process" << std::endl;
		return NULL;
	}
#endif

	// try to load at image base of the old optional header, the size of the optional header image, commit = make , reserve it, execute read write to write the memory
	pTargetBase = (uint8_t*)VirtualAlloc((char*)pOldOptionalHeader->ImageBase, pOldOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pTargetBase) {

		// try any old address now, image base taken probably 
		pTargetBase = (uint8_t*)VirtualAlloc(nullptr, pOldOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pTargetBase) {
			std::cout << "[!] failed to allocate final mapped image memory at any address" << std::endl;
			return NULL;
		}
	}

	if (pOldFileHeader->NumberOfSections <= 0) {
		std::cout << "[!] file has no section, loading aborted" << std::endl;
		return NULL;
	}

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

	// copy mem up until first section [0, section1)
	uint64_t rollingImageSize = pOldOptionalHeader->SizeOfHeaders;
	memcpy(pTargetBase, pSourceData.get(), pOldOptionalHeader->SizeOfHeaders);

	// copy all the sections // [sec1, secN)
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		// Each section is a buffer of raw data
		rollingImageSize += pSectionHeader->SizeOfRawData;
		if (FileSize < rollingImageSize) {
			return NULL;
		}

		memcpy(pTargetBase + pSectionHeader->VirtualAddress, pSourceData.get() + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
	}

	if (!loadImage((char*)pTargetBase)) {
		std::cout << "[!] image load failed" << std::endl;
		return NULL;
	}

	loadedImages.insert({ (HMODULE)pTargetBase, imagePath });
	return (HMODULE)pTargetBase;
}

ManualMapper::ExportDirectoryPtrs ManualMapper::getExportDir(HMODULE hModule) {
	ExportDirectoryPtrs exportPtrs;
	exportPtrs.addressOfFunctions = nullptr;
	exportPtrs.addressOfNameOrdinals = nullptr;
	exportPtrs.addressOfNames = nullptr;
	exportPtrs.exports = nullptr;

	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* pNT = RVA2VA(IMAGE_NT_HEADERS*, hModule, pDos->e_lfanew);
	IMAGE_DATA_DIRECTORY* pDataDir = (IMAGE_DATA_DIRECTORY*)pNT->OptionalHeader.DataDirectory;

	if (pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL) {
		return exportPtrs;
	}

	IMAGE_EXPORT_DIRECTORY* pExports = RVA2VA(IMAGE_EXPORT_DIRECTORY*, hModule, pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	exportPtrs.addressOfFunctions = RVA2VA(uint32_t*, hModule, pExports->AddressOfFunctions);
	exportPtrs.addressOfNames = RVA2VA(uint32_t*, hModule, pExports->AddressOfNames);
	exportPtrs.addressOfNameOrdinals = RVA2VA(uint16_t*, hModule, pExports->AddressOfNameOrdinals);
	exportPtrs.exports = pExports;
	return exportPtrs;
}

std::vector<std::string> ManualMapper::getExports(HMODULE hModule) {
	std::vector<std::string> exports;
	ExportDirectoryPtrs exportPtrs = getExportDir(hModule);
	if (!exportPtrs.exports) {
		return exports;
	}

	exports.reserve(exportPtrs.exports->NumberOfNames);
	for (uint32_t i = 0; i < exportPtrs.exports->NumberOfNames; i++) {
		char* exportName = RVA2VA(char*, hModule, exportPtrs.addressOfNames[i]);
		exports.push_back(exportName);
	}
	return exports;
}

uint64_t ManualMapper::getProcAddress(HMODULE hModule, std::string procName) {
	ExportDirectoryPtrs exportPtrs = getExportDir(hModule);
	if (!exportPtrs.exports) {
		return 0;
	}

	for (uint32_t i = 0; i < exportPtrs.exports->NumberOfNames; i++) {
		char* exportName = RVA2VA(char*, hModule, exportPtrs.addressOfNames[i]);
		if (_stricmp(exportName, procName.c_str()) == 0)
			return RVA2VA(uint64_t, hModule, exportPtrs.addressOfFunctions[i]);
	}
	return 0;
}