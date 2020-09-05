#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "JITCall.hpp"
#include "CmdParser/parser.hpp"
#include "ManualMapper/ManualMap.hpp"

#include <optional>
#include <string>
#include <stdio.h>

// Represents a single jit'd stub & it's execution environment
class JITEnv {
public:
	JITEnv(BoundFNTypeDef&& boundFn, const uint64_t exportAddr) : boundFn(std::move(boundFn)) {
		jit = std::make_unique<JITCall>((char*)exportAddr);
	}

	void invokeJit(JITCall::WaitType waitType) {
		call = jit->getJitFunc(boundFn.typeDef.retType, boundFn.typeDef.argTypes, boundFn.typeDef.callConv, waitType);
	}

	// holds jit runtime and builder (allocated runtime environment)
	std::unique_ptr<JITCall> jit;

	// holds jitted stub (final asm stub)
	JITCall::tJitCall call;

	// holds the function def + allocated parameters
	BoundFNTypeDef boundFn;
};

// VirtualFree this when done
std::byte* loadShellcode(std::wstring filePath) {
	std::ifstream file(filePath.c_str(), std::ios::binary);
	if (!file.good()) {
		std::wcout << L"[!] Unable to open given file: " << filePath << L" this is fatal!" << std::endl;
		return nullptr;
	}

	// Stop eating new lines in binary mode
	file.unsetf(std::ios::skipws);

	file.seekg(0, std::ios::end);
	std::streampos fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	std::byte* data = (std::byte*)VirtualAlloc(0, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	file.read((char*)data, fileSize);

	return data;
}

int wmain(int argc, wchar_t* argv[]) {
	std::vector<std::wstring> raw;

	// skip exe path always
	for (uint16_t i = 1; i < argc; i++) {
		raw.push_back(std::wstring(argv[i]));
	}

	///*
	//	x64Dbg passes the library path via a mapped file so that the commandline
	//	can be freely set. Argv[0] will be the path to the loader executable, we
	//	shall insert this library path just after argv[0] but before the rest of the 
	//	arguments.
	//*/
	//wchar_t szName[256];
	//wsprintfW(szName, L"Local\\szLibraryName%X", (unsigned int)GetCurrentProcessId());
	//HANDLE hMapFile = OpenFileMappingW(FILE_MAP_READ, false, szName);
	//if (hMapFile) {
	//	const wchar_t* szLibraryPath = (const wchar_t*)MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 512);
	//	if (szLibraryPath) {
	//		std::cout << "[!] Using x64Dbg classic mode compatability mode" << std::endl;
	//		// insert between if args exist
	//		if (raw.size() > 0) {
	//			raw.insert(raw.begin() + 1, std::wstring(szLibraryPath));
	//		} else if (raw.size() == 0) {
	//			// append if only exe path exists
	//			raw.push_back(std::wstring(szLibraryPath));
	//		}
	//		
	//		UnmapViewOfFile(szLibraryPath);
	//	}
	//	CloseHandle(hMapFile);
	//}
	
	std::wcout << L"[+] Echoing Arguments..." << std::endl;
	for (uint8_t i = 0; i < raw.size(); i++) {
		std::wcout << L"[+] " + std::to_wstring(i) + L": " << raw[i] << std::endl;
	}
	std::wcout << L"[+] Done." << std::endl;

	auto cmdLine = parseCommandLine(raw);
	if (!cmdLine) {
		std::cout << "[!] Error parsing commandline, exiting" << std::endl;
		return 1;
	}

	std::vector<JITEnv> jitEnvs;
	if (cmdLine->loadType == JITCall::LoadType::SHELLCODE) {
		// TODO: pSC is leaked atm, free this eventually
		std::byte* pSC = loadShellcode(cmdLine->loadFilePath);
		if (pSC == nullptr) {
			std::cout << "[!] Shellcode load failed...fatal!" << std::endl;
			return 0;
		}

		uint64_t pSCEntryPoint = (uint64_t)pSC + cmdLine->scBase;

		std::cout << "[+] Adding JIT Stub for shellcode at base: " << std::hex << (uint64_t)pSC << " with entrypoint: " << pSCEntryPoint << std::dec << " ..." << std::endl;

		// only 1 SC entrpoint allowed
		JITEnv env(std::move(cmdLine->boundFunctions.at(0)), pSCEntryPoint);
		env.invokeJit(cmdLine->waitType);

		jitEnvs.push_back(std::move(env));
		std::cout << "[+] Done." << std::endl;
	} else {
		HMODULE loadedModule = NULL;
		std::optional<ManualMapper> manualMapper;
		if (cmdLine->loadType == JITCall::LoadType::MANUAL_BASIC) {
			std::cout << "[+] Manual load selected!" << std::endl;
			manualMapper = ManualMapper();
			loadedModule = manualMapper->mapImage(cmdLine->loadFilePath.c_str());
		} else if (cmdLine->loadType == JITCall::LoadType::NT_LOADLIB) {
			loadedModule = LoadLibraryW(cmdLine->loadFilePath.c_str());
		}

		if (loadedModule == NULL) {
			std::cout << "[!] Module load failed...fatal!" << std::endl;
			return 0;
		}

		for (uint8_t i = 0; i < cmdLine->exportFnMap.size(); i++) {
			std::string exportName = cmdLine->exportFnMap.at(i);
			uint64_t exportAddr = 0;
			if (manualMapper) {
				exportAddr = (uint64_t)manualMapper->getProcAddress(loadedModule, exportName.c_str());
			} else {
				exportAddr = (uint64_t)GetProcAddress(loadedModule, exportName.c_str());
			}

			if (exportAddr == 0) {
				std::cout << "[!] Export: " << exportName << "failed to resolve, is the name correct?" << std::endl;
				continue;
			}

			std::cout << "[+] Adding JIT Stub for Export: " << exportName << " at: " << std::hex << exportAddr << std::dec << " ..." << std::endl;
			JITEnv env(std::move(cmdLine->boundFunctions.at(i)), exportAddr);
			env.invokeJit(cmdLine->waitType);

			jitEnvs.push_back(std::move(env));
			std::cout << "[+] Done." << std::endl;
		}
	}

	// Invoke in order
	for (uint8_t i = 0; i < jitEnvs.size(); i++) {
		JITEnv& env = jitEnvs.at(i);
		auto args = env.boundFn.params.getDataPtr();

		// This logic is inserted by the JIT, just print the messages here
		// because it's hard to JIT std::cout or printf
		if (cmdLine->waitType == JITCall::WaitType::WAIT_KEYPRESS) {
			std::cout << "[+] Press any key to invoke: " << cmdLine->exportFnMap.at(i) << "..." << std::endl;
		} else if (cmdLine->waitType == JITCall::WaitType::INT3) {
			std::cout << "[+] INT3 will hit before invoking: " << cmdLine->exportFnMap.at(i) << "..." << std::endl;
		}
		env.call(args);
	}

	std::cout << "[+] Done invoking everything...press any key to exit" << std::endl;
	getchar();
	return 0;
}

