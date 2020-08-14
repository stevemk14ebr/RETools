# demumble

`demumble` is a python3 library that demangles both Itanium and Visual Studio symbols. It runs on both
POSIX and Windows. It also handles RTTI mangled types. This is a modification of https://github.com/nico/demumble

# installation
Make sure pip version > 19.1. There is a bug in pip's index url handling before that.
```pip3 install --extra-index-url https://artifactory.services.fireeye.com/artifactory/api/pypi/flare-python/simple/ --trusted-host artifactory.services.fireeye.com demumble```

## locally
clone this repo and run `python3 setup.py install`

# build
This is a CMake project, it will build on unix based OS-es and windows. If you want to build manually you can run ```sudo apt-get install cmake``` then `build_unix.sh` or `build_win.bat` files. You may then run the python script directly. In order to build the python wheel run both of those scripts on a windows and linux machine, copy the dlls to the same machine, then run `python3 setup.py bdist_wheel`

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
    
