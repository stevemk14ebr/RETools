# RETools
Random tools I made or otherwise just use for reversing quickly.

# PEDMPExtractor
* Search for PE files in a raw dump and display arch + pe file size to allow manual carving quickly

# REClass
* Live memory C, C++, and other structure rebuilding tool

# GoReSym
* Extract GoLang function names, file paths, reconstruct user defined structures and interfaces, and print binary metadata. Amongst other things.

# demumble
* C++ library with python wrapper to demangle Itanium and MSVC symbols on all platforms (Linux, Mac, Windows)
  * Modified from: https://github.com/nico/demumble

# JITCall 
* Command line application to JIT compile a calling stub around N number of dll exports with arguments provided the calling convention. Additionally can load shellcode or manual mapping of dlls to easily debug dllmain and can read binary files to pass arbitrary data as argument. Wait for execution by key press or int3.

# BlobRunner
* Allocate and run shellcode, print shellcode base and wait for execution by key press.

# COM-Code-Helper
* Com plugin for IDA pro to automatically identify and label many com interfaces and some vtable structures

# pdbfetch
* Finds and downloads a PDB from the microsoft symbol server given an input binary. Caches to the symbol directory the same way windbg does.

# IdaScripts
Python helper scripts to do random stuff. May contain wrappers around ida operations, binja operations, or misc python utilities useful in low level stuff.

 * Plugins:
     Ida plugins. Either raw binaries or submodules to the project if it's on github (and installable via src).
     * signsrch: easily create byte signatures of various forms and search for them. Auto-mask the opcode and some immediates
     * hexlight: highlight bracket pairs in hex-rays pseudocode, press 'b' to jump between start/end brackets
     * easy_nop: select and right click an assembly sequence to replace with 0x90 nops
     * capa
     * HexRaysPyTools: C++ structure rebuilding tool, right click else conditions to swap if/then, much more.
     * IDAFuzzy: search plugin
     
 * SLib:
     Steve's python lib. Simple python helpers to do binary work packaged into a nice python module.
     
 * Cfg:
     My preferences for IDA configuration. 
     * idagui.cfg: Escape closes windows disabled via OTHER_CLOSED_BY_ESC, TOOL_CLOSED_BY_ESC, CLOSED_BY_ESC. Hide/Unhide bindings changed to ctrl-shift-h and ctr-shift-u for tenkeyless keyboard support.
     * hexrays.cfg: COLLAPSE_LVARS true, GENERATE_EA_LABELS true, AUTO_UNHIDE true, MAX_FUNCSIZE expanded for stupid obfuscators, PSEUDOCODE_DOCKPOS DP_RIGHT, PSEUDOCODE_SYNCED true, HEXOPTIONS 0x821FF to mask off HO_ESC_CLOSES_VIEW
     * ida.cfg: PACK_DATABASE set to 2 for compressed idbs
