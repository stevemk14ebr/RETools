# demumble

`demumble` is a python3 library that demangles both Itanium and Visual Studio symbols. It runs on both
POSIX and Windows. It also handles RTTI mangled types. This is a modification of https://github.com/nico/demumble

## Build

This is a cmake project, the windows build requires Visual Studio. You may build with the two included scripts:
`build_unix.sh` and `build_win.bat`. To create the python `.whl` run the respective build scripts on windows and linux machines and copy the build `.so` and `.dll` to the same machine. On that machine run `python3 setup.py bdist_wheel`. Alternatively just run `python3 setup.py install` for a local installation.

## Locally
clone this repo and run `python3 setup.py install`

# usage
The python script is a simple wrapper around the C++ library. There are 4 APIs

1. demangle(mangled_name): Demangle a msvc, itanium, or RTTI style name
2. is_mangle_char_itanium(c): Is the given character within the valid range for itanium, and RTTI style names
3. is_mangle_char_win(c): Is the given character within the valid range for windows, and RTTI style names
4. version(): Get the library version

The script may also be invoked on the command line directly
```
> python demumble.py _ZTS12CNetMidLayer
Loaded demumble version: 1.2.2
typeinfo name for CNetMidLayer
```
    
