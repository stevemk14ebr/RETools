# JITCall
An olly inspired dll loader for x64dbg using JIT compiling instead of asm. Now you can call exports in x64dbg, without rundll32

![Command line interface](https://i.imgur.com/8GsXvVq.png)

Test function, and JIT'd call stub output:
```
extern "C" __declspec(dllexport) void __stdcall exportStringFloatInt(char* s, float f, int i) {
    printf("Hello i print strings: %s %f %i", s, f, i);
}
```

```
JIT Wrapper:
[RAPass::BuildCFG]
  L0: void Func(u32@[0] %0)
  {#0}
    mov %1, 0
    mov %2, qword [%0+%1]
    add %1, 8
    movq %3, qword [%0+%1]
    add %1, 8
    mov %4, qword [%0+%1]
    mov dword [esp], %2
    movss dword [esp+4], %3
    mov dword [esp+8], %4
    call 0x7A3512BC
    sub esp, 0xC
    [FuncRet]
  {#1}
  L1:
    [FuncEnd]
[RAPass::BuildViews]
[RAPass::BuildDominators]
  IDom of #1 -> #0
  Done (2 iterations)
[RAPass::BuildLiveness]
  LiveIn/Out Done (4 visits)
  {#0}
    IN   [%0]
    GEN  [%1, %2, %0, %3, %4]
    KILL [%1, %2, %3, %4]
  {#1}
  %1 {id:0257 width: 10   freq: 0.6000 priority=0.6100}: [3:13]
  %2 {id:0258 width: 10   freq: 0.2000 priority=0.2100}: [5:15]
  %0 {id:0256 width: 11   freq: 0.2727 priority=0.2827}: [2:13]
  %3 {id:0259 width: 8    freq: 0.2500 priority=0.2600}: [9:17]
  %4 {id:0260 width: 6    freq: 0.3333 priority=0.3433}: [13:19]
[RAPass::BinPack] Available=7 (0x000000EF) Count=4
  00: [3:13@257], [13:19@260]
  01: [2:13@256]
  02: [5:15@258]
  Completed.
[RAPass::BinPack] Available=8 (0x000000FF) Count=1
  00: [9:17@259]
  Completed.
[RAPass::Rewrite]
.section .text {#0}
L0:
sub esp, 0xC                                ; 83EC0C
mov ecx, dword [esp+0x10]                   ; 8B4C2410
mov eax, 0                                  ; B800000000              | <00002> mov %1, 0                        | %1{W|Out}
mov edx, qword [ecx+eax]                    ; 8B1401                  | <00004> mov %2, qword [%0+%1]            | %2{W|Out} %0{R|Use} %1{R|Use}
add eax, 8                                  ; 83C008                  | <00006> add %1, 8                        | %1{X|Use}
movq xmm0, qword [ecx+eax]                  ; F30F7E0401              | <00008> movq %3, qword [%0+%1]           | %0{R|Use} %1{R|Use} %3{W|Out}
add eax, 8                                  ; 83C008                  | <00010> add %1, 8                        | %1{X|Use}
mov eax, qword [ecx+eax]                    ; 8B0401                  | <00012> mov %4, qword [%0+%1]            | %4{W|Out} %0{R|Use|Last|Kill} %1{R|Use|Last|Kill}
mov dword [esp], edx                        ; 891424                  | <00014> mov dword [esp], %2              | %2{R|Use|Last|Kill}
movss dword [esp+4], xmm0                   ; F30F11442404            | <00016> movss dword [esp+4], %3          | %3{R|Use|Last|Kill}
mov dword [esp+8], eax                      ; 89442408                | <00018> mov dword [esp+8], %4            | %4{R|Use|Last|Kill}
call 0x7A3512BC                             ; E800000000              | <00020> call 0x7A3512BC
sub esp, 0xC                                ; 83EC0C                  | <00022> sub esp, 0xC
L1:                                         ;                         | L1:
add esp, 0xC                                ; 83C40C
ret                                         ; C3
```

# Setup

```
git clone --recursive https://github.com/stevemk14ebr/JITCall.git
cd JITCall
git submodule update --init --recursive
```

Build in release mode, then debug this executable using x64 dbg and specify the commandline flags to JIT stubs for your dll exports.

# CommandLine Flag

```-f``` or ```--func``` declares a new export to JIT. This flag expects
   * ExportName as an unquoted string
   * The typedefinition as a C++ typdef in quotes, optional variable names. Use ```()``` instead of ```(void)``` for empty arguments.
   * The arguments in accordance with the typedef, for files you may use ```@``` prefix to load the file's contents
```-w``` or ```--wait``` call getchar() just before invoking each jit stub
```-bp``` or ```--breakpoint``` insert an int3 before invoking each jit stub
```-m``` use a minimal manual mapper to load the dll instead of LoadLibrary
```--help``` nah

Supported argument/return types:
```
void
int8_t
char
uint8_t
int16_t
uint16_t
int32_t
uint32_t
int
int64_t
uint64_t
float
double

optional * on any of the above.
```

Supported calling conventions:
```
cdecl
fastcall
stdcall
```

Example:
```
<JITCall.exe> C:\a.dll -w -m -f Setup "void (char* name, char)" "this is a test" 0x30 -f Run "char stdcall (char*)" "@C:\contents.txt"
```

# Implementation
Given a typdef of a function sscanf string arguments into uint64_t array based on given type. Then abuse ASMJit to JIT a little wrapper function that will take the parameter array as input and map the slots in the array to the correct ABI locations (stack/reg) for the call we are doing. Then invoke this JIT stub from C.

Because we just shove all params into a uint64_t array and push the actual call to runtime JIT we don't need to hand craft any fancy assembly, just need to provide the correct type def at runtime so that asmjit knows the ABI to map to. 
