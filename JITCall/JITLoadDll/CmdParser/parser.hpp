#pragma once

#include "JITCall.hpp"

#include <set>
#include <vector>
#include <regex>
#include <sstream>
#include <optional>
#include <string>
#include <iostream>
#include <algorithm> 
#include <cctype>
#include <locale>
#include <cassert>
#include <fstream>
#include <functional>
#include <unordered_map>

#include <stdio.h>
#include <stringapiset.h>
#include <cwctype>
/***
*	This file is responsible for parsing the command line into objects that are JIT-able.
*   A JIT-able object only requires the complete function typedef and the argument byte to be passed.
*
*	The commandline format is a function typedef with X number of args specified as strings.
*   The parsing will take the typedef into accounts, interpret that argument strings via the types in the typedefs,
*   and then alloc memory and read the args into argument buffers according to their true types. Ex:
*   -f void(float a) "0.1337" is read into a byte buffer so that it's bytes are the same as float a = 0.1337;
*   It's also responsible for verifying arg counts match the typedef given counts, and that types are valid.
*
*   TODO: In the future it will be responsible for reading files into byte buffers and opening handles and such.
***/

// trim from start (in place)
static inline void ltrim(std::string& s) {
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
		return !std::isspace(ch);
		}));
}

// trim from end (in place)
static inline void rtrim(std::string& s) {
	s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
		return !std::isspace(ch);
		}).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string& s) {
	ltrim(s);
	rtrim(s);
}

static inline std::string ltrim_copy(std::string s) {
	ltrim(s);
	return s;
}

// trim from end (copying)
static inline std::string rtrim_copy(std::string s) {
	rtrim(s);
	return s;
}

// trim from both ends (copying)
static inline std::string trim_copy(std::string s) {
	trim(s);
	return s;
}

std::vector<std::string> split(const std::string s, char delim) {
	std::stringstream ss(s);
	std::string item;
	std::vector<std::string> elems;
	while (std::getline(ss, item, delim)) {
		elems.push_back(std::move(item));
	}
	return elems;
}

bool starts_with(const std::string search, const std::string needle) {
	if (search.compare(0, needle.length(), needle) == 0)
		return true;
	return false;
}

std::string u16Tou8(const std::wstring s) {
	int len;
	int slength = (int)s.length() + 1;
	len = WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, 0, 0, 0, 0);
	std::string r(len, '\0');
	WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, &r[0], len, 0, 0);
	return r;
}

std::vector<std::string> supportedCallConvs{ "stdcall", "cdecl", "fastcall" };

struct DataTypeInfo {
	uint8_t size;
	std::string formatStr;
	std::string hexFormatStr;
};

std::unordered_map<std::string, DataTypeInfo> typeFormats{
	{"void", {0, "", ""}},
	{"int8_t", {1, "%d","%x"}},
	{"char", {1, "%d","%x"}},
	{"uint8_t", {1, "%u", "%x"}},
	{"int16_t", {sizeof(int16_t), "%d", "%x"}},
	{"uint16_t", {sizeof(uint16_t), "%u", "%x"}},
	{"int32_t",  {sizeof(int32_t), "%d","%x"}},
	{"int",  {sizeof(int32_t), "%d","%x"}},
	{"uint32_t", {sizeof(uint32_t), "%u","%x"}},
#ifdef _MSC_VER
	{"int64_t", {sizeof(int64_t), "%I64d","%llx"}},
	{"uint64_t", {sizeof(uint64_t), "%I64u", "%llx"}},
#else
	{"int64_t", {sizeof(int64_t), "%lld", "%llx"}},
	{"uint64_t", {sizeof(uint64_t), "%llu", "%llx"}},
#endif
	{"float", {sizeof(float), "%f", "%x"}},
	{"double", {sizeof(double), "%lf", "%lx"}}
};

struct FNTypeDef {
	FNTypeDef() {
		argTypes = std::vector<std::string>();
	}

	std::string retType;
	std::string callConv;
	std::vector<std::string> argTypes;
};

// A FNTypeDef w/ associated parameters
struct BoundFNTypeDef {
	// variable length data pinned to a certain memory address.
	// The vector gets heap allocated and we can freely move the pointer 
	// to that around by std::move-ing the unique_ptr, but the vectors' 
	// heap allocated array always stays in the same place. This lets
	// us 'return' the vector without worrying its underlying memory moves.
	// Sooooo, we can freely take dangerous types of pointers like &vec[0]
	// and not worry about dangling references ever as the vector will never re-alloc.
	typedef std::unique_ptr<std::vector<std::byte>> PinnedData;

	BoundFNTypeDef() = delete;

	BoundFNTypeDef(const uint8_t numArgs) :
		params(JITCall::Parameters(numArgs)) {
	}

	FNTypeDef typeDef;

	// holds param values
	JITCall::Parameters params;

	// holds arbitray backing data for params
	std::vector<PinnedData> arbitraryParamData;
};

std::optional<FNTypeDef> regex_typedef(std::string input) {
	//"([a-zA-Z_][a-zA-Z0-9_*]*)\s*([a-zA-Z_][a-zA-Z0-9_*]*\s*)?(?:[a-zA-Z_][a-zA-Z0-9_]*)?\s*\((.*)\)" 
	//ex: void (int a, int*,int64_t ,int *b, char) or void stdcall (int a, int*,int64_t ,int *b, char)
	std::regex fnTypeDefRgx("([a-zA-Z_][a-zA-Z0-9_*]*)\\s*([a-zA-Z_][a-zA-Z0-9_*]*\\s*)?(?:[a-zA-Z_][a-zA-Z0-9_]*)?\\s*\\((.*)\\)");

	std::smatch matches;
	if (std::regex_search(input, matches, fnTypeDefRgx)) {
		FNTypeDef functionDefinition;
		functionDefinition.retType = trim_copy(matches[1].str());
		functionDefinition.callConv = trim_copy(matches[2].str());

		// if none specified, use fastcall for x64 or cdecl for x86. These are ABI defined defaults
		if (functionDefinition.callConv.length() == 0) {
			functionDefinition.callConv = sizeof(char*) == 4 ? "cdecl" : "fastcall";
		}

		bool found = false;
		for (auto str : supportedCallConvs) {
			if (str == functionDefinition.callConv) {
				found = true;
				break;
			}
		}

		if (!found) {
			std::cout << "[!] Calling convention not supported" << std::endl;
			return {};
		}

		// check for empty params case ex: void (   ) i.e.: is all spaces
		auto params = split(matches[3].str(), ',');
		if (params.size() == 1 && params.at(0).find_first_not_of(' ') == std::string::npos)
			return functionDefinition;

		// split the arguments, they are all captured as one big group
		for (std::string argStr : params) {
			std::regex fnArgRgx("([a-zA-Z_][a-zA-Z0-9_*]*)");

			if (std::regex_search(argStr, fnArgRgx)) {
				// trim off variable names by space, take care if * is attached to name
				std::string argTrimmed = trim_copy(argStr);
				auto space_idx = argTrimmed.find_first_of(' ');
				if (space_idx == std::string::npos) {
					functionDefinition.argTypes.push_back(argTrimmed);
				} else {
					// whoops we lost the * by trimming by space, add it back.
					std::string argType = argTrimmed.substr(0, space_idx);
					if (argTrimmed.find("*") != std::string::npos && argType.find("*") == std::string::npos) {
						argType += "*";
					}
					functionDefinition.argTypes.push_back(argType);
				}
			} else {
				std::cout << "[!] Invalid function argument definition: " << argStr << std::endl;
				return {};
			}
		}
		return functionDefinition;
	} else {
		std::cout << "[!] Invalid function definition given: " << input << std::endl;
		return {};
	}
}

/*
*  WARNING: AsmJit MUST have ASMJIT_STATIC set and use /MT or /MTd for static linking
*  due to the fact that the source code is embedded. This is an artifact of our project structure
*/

// type is what to interpret data as when we write into outData. Arbitrary data is 
// a generic void* like type that anything can be storde in. It's intended to be used
// by types such as char*, or files where backing data must be allocated and outData is
// meant to hold a pointer to that data.
bool formatType(std::string* type, std::string data, uint64_t* outData, BoundFNTypeDef::PinnedData* arbitraryData) {
	assert(outData != nullptr);
	assert(type != nullptr);
	if (outData == nullptr || type == nullptr)
		return false;

	// if any type is ptr, make it the arch's int ptr type
	size_t idx = type->find("*");
	if (idx != std::string::npos) {
		auto realType = type->substr(0, idx);
		*type = sizeof(char*) == 4 ? "uint32_t" : "uint64_t";

		// if underlying type is supported and arbitraryData pointer was passed, read data into that pointer
		if ((realType == "char" || realType == "void*" || realType == "uint8_t") && arbitraryData) {
			assert(arbitraryData != nullptr);
			if (arbitraryData == nullptr)
				return false;

			// parse as a file path if @ given, or as literal string if not
			if (data.at(0) == '@' && data.size() > 1) {
				auto filename = data.substr(1, data.length() - 1);
				std::ifstream file(filename.c_str(), std::ios::binary);
				if (!file.good()) {
					std::cout << "[!] Unable to open given file: " << filename << " this is fatal!" << std::endl;
					return false;
				}

				// Stop eating new lines in binary mode
				file.unsetf(std::ios::skipws);

				file.seekg(0, std::ios::end);
				std::streampos fileSize = file.tellg();
				file.seekg(0, std::ios::beg);

				// reserve capacity
				arbitraryData->reset(new std::vector<std::byte>(fileSize, (std::byte)0));
				
				// read the file data
				file.read((char*)arbitraryData->get()->data(), fileSize);
			} else {
				// alloc and null terminate
				arbitraryData->reset(new std::vector<std::byte>(data.size() + 1, (std::byte)0));

				// copy the data, valid as we really inserted 0's in the vector so backing mem is there
				memcpy(arbitraryData->get()->data(), data.data(), data.size());
			}

			// reset data string to the address of the arbitrary data
			data = std::to_string((uint64_t)arbitraryData->get()->data());
		}
	}

	if (typeFormats.count(*type) == 0)
		return false;

	DataTypeInfo typeInfo = typeFormats.at(*type);

	std::string formatStr = typeInfo.formatStr;
	if (data.at(0) == '0' && data.size() > 1 && (data.at(1) == 'x' || data.at(1) == 'X')) {
		formatStr = typeInfo.hexFormatStr;
	}

	// sscanf using possibly wider format code
	uint64_t tmp = 0;
	bool success = sscanf_s(data.c_str(), formatStr.c_str(), &tmp) == 1;
	if (!success)
		return false;

	// copy up to specified type width to narrow down value (truncate)
	memset(outData, 0, sizeof(uint64_t));
	memcpy(outData, &tmp, typeInfo.size);
	return true;
}

void printUsage() {
	std::cout << "[+] Usage Format" << std::endl;
	std::cout << "--------------------------" << std::endl;
	//std::cout << clipp::make_man_page(cli, argv[0]) << std::endl << std::endl;

	std::cout << "[+] Supported calling conventions " << std::endl;
	std::cout << "--------------------------" << std::endl;
	for (auto& conv : supportedCallConvs)
		std::cout << conv << std::endl;
	std::cout << std::endl;

	std::cout << "[+] Supported types " << std::endl;
	std::cout << "--------------------------" << std::endl;
	for (auto& t : typeFormats)
		std::cout << t.first << std::endl;
	std::cout << "char*" << std::endl;
	std::cout << "uint8_t*" << std::endl;
	std::cout << "void*" << std::endl;

	std::cout << "Pointer types may have their argument values passed as a string literal, or opened as @path\\to\\file.bin" << std::endl;
	std::cout << "Example 1: <exename> usersMngr.dll -f addUserToList \"void cdecl (char* name, uint8_t)\" \"Tom Sawyer\" 35" << std::endl;
	std::cout << "Example 2: <exename> usersMngr.dll -f addUserToList \"void cdecl (void* ,void* userAges)\" \"@C:\\Desktop\\users.txt\" \"@D:\\ages.txt\"" << std::endl;
	std::cout << "Example 3: <exename> mal.dll -f initialize \"void stdcall ()\" -f callout \"int ( int8_t, float sleepInterval)\" 80 1338. -f configureC2 \"bool cdecl (char* url)\" \"127.0.0.1\"" << std::endl;
	std::cout << "Exports are invoked in numerical order f1, f2, f3, ... up to f5" << std::endl;
}

struct CommandLineInput {
	std::vector<BoundFNTypeDef> boundFunctions;

	// boundFunction idx -> export name
	std::unordered_map<uint8_t, std::string> exportFnMap;
	
	std::wstring loadFilePath;
	uint64_t scBase;
	JITCall::WaitType waitType;
	JITCall::LoadType loadType;
};

struct RawCmdArgs {
	std::wstring cmdInputFile;
	std::vector<std::string> cmdFnExport;
	std::vector<std::string> cmdFnTypeDef;
	std::vector<std::vector<std::string>> cmdFnArgs;
	JITCall::WaitType waitType;
	JITCall::LoadType loadType;

	std::string cmdSCBase;

	RawCmdArgs() {
		const uint8_t fnMaxCount = 5;
		cmdFnArgs.reserve(fnMaxCount);
		cmdFnTypeDef.reserve(fnMaxCount);
		cmdFnExport.reserve(fnMaxCount);

		cmdSCBase = "0";

		waitType = JITCall::WaitType::NONE;
		loadType = JITCall::LoadType::NT_LOADLIB;
	}
};

bool parse(std::vector<std::wstring> args, RawCmdArgs& cmdLine) {
	/*
	clipp::value(clipp::match::prefix_not("-"), "inputFilePath", cmdInputFile) % "Specify the filesystem path to the image"

	clipp::option("-bp", "--breakpoint").set(commandlineInput.waitType, JITCall::WaitType::INT3) % "Place an int3 instruction before invoking exports"
	| clipp::option("-w", "--wait").set(commandlineInput.waitType, JITCall::WaitType::WAIT_KEYPRESS) % "Wait for a keypress before invoking exports"
	| clipp::option("-m", "--manual").set(commandlineInput.loadType, JITCall::LoadType::MANUAL_BASIC) % "Manually load the image instead of using loadlibrary"

	for (uint8_t i = 0; i < fnMaxCount; i++) {
		(
			clipp::option("-f" + std::to_string(i + 1), "--func" + std::to_string(i + 1)) % "Adds a new function export typedef to invoke"
			& clipp::value("export", cmdFnExport[i]) % "The name of the export to invoke"
			& clipp::value("typedef", cmdFnTypeDef[i]) % "The typedef of the export, with optional calling convention"
			& clipp::opt_values("args", cmdFnArgs[i]) % "The arguments to invoke the export with, must match the type provided in the typedef"
		)
	}

	clipp::option("-h", "--help")
	*/
	//C:\TestDll.dll -f1 exportStringFloatInt8 "void stdcall (char*, float, uint8_t)" "hello there, this works!" 1337.1337 5
	
	// prevent underflow
	assert(args.size());
	if (!args.size())
		return false;

	// 1. Get Path of Dll to load
	cmdLine.cmdInputFile = args.at(0);

	// 2. Either optional values provided, or start function def parse, or no function definitions
	if (args.size() < 2)
		return true;

	// allowable argument states
	enum class ParserState {
		NEXT,
		FN_EXPORT,
		FN_TYPEDEF,
		SHELLCODE_BASE,
		OPT_FN_ARG,
	};

	// Every optional value could be a new flag, here's a convenience helper
	auto is_flag = [=](const std::wstring arg) -> bool {
		std::set<std::wstring> flags = { L"--help", L"-bp", L"--breakpoint", L"-w", L"--wait", L"-m", L"--manual", L"-f", L"--func", L"-scb", L"--shellcodebase" };
		return flags.find(arg) != flags.end();
	};

	// enter state machine to parse command line
	// valid exits are NEXT or OPT_FN_ARG when idx == args.size()
	ParserState parseState = ParserState::NEXT;
	uint16_t i = 1;
	for (; i < args.size(); i++) {
		std::wstring arg = args.at(i);
		reparse_state:
		switch (parseState) {
		case ParserState::NEXT:
			if (!is_flag(arg))
				return false;

			if (arg == L"--help") {
				printUsage();
			} else if (arg == L"-bp" || arg == L"--breakpoint") {
				cmdLine.waitType = JITCall::WaitType::INT3;
			} else if (arg == L"-w" || arg == L"--wait") {
				cmdLine.waitType = JITCall::WaitType::WAIT_KEYPRESS;
			} else if (arg == L"-m" || arg == L"--manual") {
				if (cmdLine.loadType == JITCall::LoadType::SHELLCODE) {
					std::wcout << L"[!] Shellcode already chosen, cannot set alternative load scheme" << std::endl;
					return false;
				}
				cmdLine.loadType = JITCall::LoadType::MANUAL_BASIC;
			} else if (arg == L"-f" || arg == L"--func") {
				// look for export name next
				parseState = ParserState::FN_EXPORT;
			} else if (arg == L"-scb" || arg == L"--shellcodebase") {
				// set shellcode load first, then read the base address next
				cmdLine.loadType = JITCall::LoadType::SHELLCODE;
				parseState = ParserState::SHELLCODE_BASE;
			} else {
				// there's a missing flag in the if statement
				assert(false);
				std::wcout << L"[!] Unkown flag: " << arg << std::endl;
				return false;
			}
			break;
		case ParserState::SHELLCODE_BASE:
			cmdLine.cmdSCBase = u16Tou8(arg);
			parseState = ParserState::NEXT;
			break;
		case ParserState::FN_EXPORT:
			cmdLine.cmdFnExport.push_back(u16Tou8(arg));
			parseState = ParserState::FN_TYPEDEF;
			break;
		case ParserState::FN_TYPEDEF:
			cmdLine.cmdFnTypeDef.push_back(u16Tou8(arg));

			// append optional args here
			cmdLine.cmdFnArgs.push_back({});
			parseState = ParserState::OPT_FN_ARG;
			break;
		case ParserState::OPT_FN_ARG:
			if (is_flag(arg)) {
				parseState = ParserState::NEXT;
				goto reparse_state;
			}

			cmdLine.cmdFnArgs.back().push_back(u16Tou8(arg));
			break;
		}
	}

	if (parseState == ParserState::NEXT || parseState == ParserState::OPT_FN_ARG) {
		// we're at a valid end state but haven't consumed everything
		if (i != args.size()) {
			std::cout << "[!] Invalid commandline options" << std::endl;
			return false;
		}
	} else {
		// invalid end state
		std::cout << "[!] Invalid commandline options" << std::endl;
		return false;
	}

	return true;
}

std::optional<CommandLineInput> parseCommandLine(std::vector<std::wstring> raw) {
	RawCmdArgs rawArgs; // in
	CommandLineInput commandlineInput; // out

	if (parse(raw, rawArgs)) {
		commandlineInput.loadFilePath = rawArgs.cmdInputFile;

		// for each typedef
		for (uint8_t i = 0; i < rawArgs.cmdFnTypeDef.size(); i++) {
			std::string typeDef = rawArgs.cmdFnTypeDef[i];
			std::vector<std::string> args = rawArgs.cmdFnArgs[i];
			if (!typeDef.size())
				break;

			// parse the typedef arg types via regex
			if (auto fnDef = regex_typedef(typeDef)) {
				if (fnDef->argTypes.size() != args.size()) {
					std::cout << "[!] Invalid parameter count supplied to function: " + std::to_string(i) << " exiting" << std::endl;
					return {};
				}

				std::cout << typeDef << "  ";
				// for each of the argument types, reinterpret the string data for that type
				BoundFNTypeDef jitTypeDef((uint8_t)fnDef->argTypes.size());
				for (uint8_t j = 0; j < fnDef->argTypes.size(); j++) {

					// take a ptr so formatType can modify array slot
					std::string& argType = fnDef->argTypes.at(j);
					std::cout << argType << "(" << args[j] << ")  ";

					// pack all types into a uint64_t
					uint64_t argBuf;

					// this vector can _never_ be moved, as it's backing memory is actually referred to by address
					BoundFNTypeDef::PinnedData arbitraryArgData(nullptr);
					if (!formatType(&argType, args[j], &argBuf, &arbitraryArgData)) {
						std::cout << "[!] Failed to parse argument with given type" << std::endl;
						return {};
					}

					// if arbitrary data got allocated, bind it to func so it stays alive
					if (arbitraryArgData) {
						uint64_t addr = (uint64_t)arbitraryArgData.get()->data();
						jitTypeDef.arbitraryParamData.push_back(std::move(arbitraryArgData));
					}

					jitTypeDef.params.setArg(j, argBuf);
				}

				jitTypeDef.typeDef = *fnDef;
				commandlineInput.boundFunctions.push_back(std::move(jitTypeDef));
				commandlineInput.exportFnMap[i] = rawArgs.cmdFnExport[i];
				std::cout << std::endl;
			} else {
				std::cout << "[!] Invalid function typedef provided, exiting" << std::endl;
			}
		}

		std::string scBaseFormat = "uint64_t";
		formatType(&scBaseFormat, rawArgs.cmdSCBase, &commandlineInput.scBase, nullptr);
		commandlineInput.loadType = rawArgs.loadType;
		commandlineInput.waitType = rawArgs.waitType;
	} else {
		printUsage();
	}
	return commandlineInput;
}