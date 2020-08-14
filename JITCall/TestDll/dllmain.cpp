#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

extern "C" __declspec(dllexport) void exportOneCdecl(int i) {
	printf("Hello from export one: %d", i);
}

extern "C" __declspec(dllexport) void __stdcall exportOneStd(int i) {
    printf("Hello from export one stdcall: %d", i);
}

extern "C" __declspec(dllexport) void exportTwoCdecl(float i) {
    printf("Hello from export two: %f", i);
}

extern "C" __declspec(dllexport) void __stdcall exportTwoStd(float i) {
	printf("Hello from export two: %f", i);
}

extern "C" __declspec(dllexport) void __stdcall exportStringFloatInt8(char* s, float f, unsigned char i) {
    printf("Hello i print strings: %s %f %u", s, f, i);
}

extern "C" __declspec(dllexport) void exportNone() {
    printf("%s", "Hello");
}

extern "C" __declspec(dllexport) void exportWideArg(uint64_t a1, uint64_t a2, uint32_t a3) {
    printf("Hello from WideArgs %I64X %I64X %u\n", a1, a2, a3);
}

extern "C" __declspec(dllexport) int64_t Start() {
    printf("Hello from no args");
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    printf("%s: %d\n", "TestDLL Main Called!", ul_reason_for_call);
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

