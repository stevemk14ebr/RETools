# RETools
Random tools I made or otherwise just use for reversing quickly.

# PEDMPExtractor
* Search for PE files in a raw dump and display arch + pe file size to allow manual carving quickly

# REClass
* Live memory C, C++, and other structure rebuilding tool. Shows a structured view over live memory so you can see values as they change.

# GoReSym
* Extract GoLang function names, file paths, reconstruct user defined structures and interfaces, and print binary metadata. Amongst other things.

# STrace
* Syscall hooking framework. Modify args, return values, etc in a patchguard compatible way.
* Within this repo is a tool PDBReSym, which can download PDBs and Binaries from the MS symbol server, or symbolicate logs.

# demumble
* C++ library with python wrapper to demangle Itanium and MSVC symbols on all platforms (Linux, Mac, Windows)
  * Modified from: https://github.com/nico/demumble

# JITCall 
* Command line application to JIT (via asmjit) compile a calling stub around N number of dll exports with arguments provided the calling convention. Additionally can load shellcode or manual mapping of dlls to easily debug dllmain and can read binary files to pass arbitrary data as argument. Wait for execution by key press or int3.

# BlobRunner
* Allocate and run shellcode, print shellcode base and wait for execution by key press. Simpler alternative than JITCall, doesn't support arguments.

# COM-Code-Helper
* Com plugin for IDA pro to automatically identify and label many com interfaces and some vtable structures

# SingleFileExtractor
* A utility for extracting .NET single file bundles to disk while maintaining the internal bundle folder structure. Also supported by ILSpy fwiw.

# IdaScripts
Python helper scripts to do random stuff. May contain wrappers around ida operations, binja operations, or misc python utilities useful in low level stuff. See https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/ for the easiest way to use the plugins and configs.

 * Plugins:
     Ida plugins. Either raw binaries or submodules to the project if it's on github (and installable via src).
     * signsrch: easily create byte signatures of various forms and search for them. Auto-mask the opcode and some immediates
     * hexlight: highlight bracket pairs in hex-rays pseudocode, press 'b' to jump between start/end brackets
     * easy_nop: select and right click an assembly sequence to replace with 0x90 nops
     * flare-capa: find interesting functions in a binary
     * sigmaker: create and search for assembly patterns automatically in IDA
     * HexRaysPyTools (oopsmishap fork): C++ structure rebuilding tool, right click else conditions to swap if/then, much more. Fork includes new template build feature and fixes
     * IDAFuzzy: search plugin
     * Define String From Selection: Allows selecting a region of memory and defining a string of that specific selection length (not null terminated). Useful for Go and other languages with string length stored seperately from the non-null terminated string.
     
 * SLib:
     Steve's python lib. Simple python helpers to do binary work packaged into a nice python module.
 
 * Misc: Some example IDA python scripts to do common things. Just examples for common tasks.
     * reset_all_colors: Strip set_color's from an IDB received from someone else and reset to theme colors (remove call highlights etc).
     
 * Cfg: 
     * idagui.cfg: Escape closes windows disabled via OTHER_CLOSED_BY_ESC, TOOL_CLOSED_BY_ESC, CLOSED_BY_ESC. Hide/Unhide bindings changed to ctrl-shift-h and ctr-shift-u for tenkeyless keyboard support.
     * hexrays.cfg: COLLAPSE_LVARS true, GENERATE_EA_LABELS true, AUTO_UNHIDE true, MAX_FUNCSIZE expanded for stupid obfuscators, PSEUDOCODE_DOCKPOS DP_RIGHT, PSEUDOCODE_SYNCED true, HEXOPTIONS 0x821BF to mask off HO_ESC_CLOSES_VIEW and HO_CONST_STRINGS, MAX_NCOMMAS 1 for nicer conditional formatting
     * ida.cfg: PACK_DATABASE set to 2 for compressed idbs
