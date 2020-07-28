// PEDmpExtractor.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <Windows.h>

enum class Arch {
    x86,
    x64,
    unk
};

int main(int argc, char* argv[])
{
    std::cout << "Loading binary file: " << argv[1] << std::endl;

    std::vector<uint64_t> mz_offsets;
    std::ifstream f(argv[1], std::ios::binary);

    while (f) {
        uint64_t offset = f.tellg();

        uint16_t hdr = 0;
        f.read((char*)&hdr, sizeof(hdr));
        if (hdr == 0x5a4d) {
            mz_offsets.push_back(offset);
        }

        // go back 1 byte since we read 2
        f.seekg(-1, std::ios::cur);
    }

    f.clear();
    f.seekg(0, std::ios::end);
    uint64_t length = f.tellg();
    f.seekg(0, std::ios::beg);

    for (auto offset : mz_offsets) {
        f.clear();
        f.seekg(offset, std::ios::beg);

        IMAGE_DOS_HEADER dos = { 0 };
        f.read((char*)&dos, sizeof(IMAGE_DOS_HEADER));

        if (dos.e_magic != 0x5a4d)
            continue;

        uint64_t elfanew = offset + dos.e_lfanew;
        if (elfanew >= length)
            continue;

        IMAGE_NT_HEADERS hdr32 = { 0 };
        f.seekg(elfanew, std::ios::beg);
        f.read((char*)&hdr32, sizeof(IMAGE_NT_HEADERS));

        Arch arch = Arch::unk;
        if (hdr32.Signature != 0x4550)
            continue;
 
        uint64_t firstSection = elfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
            ((hdr32)).FileHeader.SizeOfOptionalHeader;

        uint64_t peSize = hdr32.OptionalHeader.SizeOfHeaders;
        for (uint32_t sec = 0; sec < hdr32.FileHeader.NumberOfSections; sec++) {
            uint64_t secOffset = firstSection + sec * sizeof(IMAGE_SECTION_HEADER);
            if (secOffset >= length)
                break;

            f.seekg(secOffset, std::ios::beg);

            IMAGE_SECTION_HEADER secHdr = { 0 };
            f.read((char*)&secHdr, sizeof(IMAGE_SECTION_HEADER));

            peSize += secHdr.SizeOfRawData;
        }

        std::cout << "PE @ " << std::hex << offset << std::dec;

        switch (hdr32.FileHeader.Machine) {
        case 0x14c:
            arch = Arch::x86;
            std::cout << " is 32bit";
            break;
        case 0x8664:
            arch = Arch::x64;
            std::cout << " is 64bit";
            break;
        default:
            std::cout << " is unknown: " << std::hex << hdr32.FileHeader.Machine << std::dec;
        }

        std::cout << " and of length: " << std::hex << peSize << std::dec << std::endl;

        std::cout << "save this binary (Y/N)" << std::endl;
        std::string save = "N";
        std::cin >> save;
        if (save == "Y" || save =="y") {
            std::string name = std::string(argv[1]) + "_" + std::to_string(offset) + "_" + std::to_string(peSize) + ".bin";
            std::cout << "saving binary:" << name << std::endl;

            char* buf = new char[peSize];
            f.seekg(offset, std::ios::beg);
            f.read(buf, peSize);

            std::ofstream fout(name, std::ios::binary);
            fout.write(buf, peSize);

            delete[] buf;
        }
    }
}
