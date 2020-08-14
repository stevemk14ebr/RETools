#define CATCH_CONFIG_RUNNER
#include "catch.hpp"
#include <iostream>

/* WARNING: AsmJit MUST have ASMJIT_STATIC set and use /MT or /MTd for static linking
*  due to the fact that the source code is embedded. This is an artifact of our project structure
*/
int main(int argc, char* const argv[]) {
	std::cout << "Welcome to JITCall -By- Stevemk14ebr" << std::endl;
	int result = Catch::Session().run(argc, argv);

	getchar();
	return result;
}