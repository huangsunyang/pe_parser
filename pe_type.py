# -*- coding=utf8 -*-
from c_type import *
from expr import this


class DOS_HEADER(BaseType):
    e_magic = WORD()
    e_cblp = WORD()
    e_cp = WORD()
    e_crlc = WORD()
    e_cparhdr = WORD()
    e_minalloc = WORD()
    e_maxalloc = WORD()
    e_ss = WORD()
    e_sp = WORD()
    e_csum = WORD()
    e_ip = WORD()
    e_cs = WORD()
    e_lfarlc = WORD()
    e_ovno = WORD()
    e_res = WORD(4)
    e_oemid = WORD()
    e_oeminfo = WORD()
    e_res2 = WORD(10)
    e_lfanew = DWORD()


class IMAGE_FILE_HEADER(BaseType):
    Machine = WORD()
    NumberOfSections = WORD()
    TimeDateStamp = DWORD()
    PointerToSymbolTable = DWORD()
    NumberOfSymbols = DWORD()
    SizeOfOptionalHeader = WORD()
    Characteristics = WORD()


class IMAGE_DATA_DIRECTORY(BaseType):
    VirtualAddress = DWORD()
    Size = DWORD()


class IMAGE_OPTIONAL_HEADER(BaseType):
    Magic = WORD()
    MajorLinkerVersion = BYTE()
    MinorLinkerVersion = BYTE()
    SizeOfCode = DWORD()
    SizeOfInitializedData = DWORD()
    SizeOfUninitializedData = DWORD()
    AddressOfEntryPoint = DWORD()
    BaseOfCode = DWORD()
    BaseOfData = DWORD()
    ImageBase = DWORD()
    SectionAlignment = DWORD()
    FileAlignment = DWORD()
    MajorOperatingSystemVersion = WORD()
    MinorOperatingSystemVersion = WORD()
    MajorImageVersion = WORD()
    MinorImageVersion = WORD()
    MajorSubsystemVersion = WORD()
    MinorSubsystemVersion = WORD()
    Win32VersionValue = DWORD()
    SizeOfImage = DWORD()
    SizeOfHeaders = DWORD()
    CheckSum = DWORD()
    Subsystem = WORD()
    DllCharacteristics = WORD()
    SizeOfStackReserve = DWORD()
    SizeOfStackCommit = DWORD()
    SizeOfHeapReserve = DWORD()
    SizeOfHeapCommit = DWORD()
    LoaderFlags = DWORD()
    NumberOfRvaAndSizes = DWORD()
    DataDirectory = IMAGE_DATA_DIRECTORY(16)    # SizeOfOptionalHeader


class PE_HEADER(BaseType):
    Signature = BYTE(4)
    FileHeader = IMAGE_FILE_HEADER()
    OptionalHeader = IMAGE_OPTIONAL_HEADER()


class IMAGE_SECTION_HEADER(BaseType):
    Name = BYTE(8)
    VirtualSize = DWORD()
    VirtualAddress = DWORD()
    SizeOfRawData = DWORD()
    PointerToRawData = DWORD()
    PointerToRelocations = DWORD()
    PointerToLinenumbers = DWORD()
    NumberOfRelocations = WORD()
    NumberOfLinenumbers = WORD()
    Characteristics = DWORD()


class IMAGE_EXPORT_DIRECTORY(BaseType):
    Characteristics = DWORD()
    TimeDateStamp = DWORD()
    MajorVersion = WORD()
    MinorVersion = WORD()
    Name = DWORD()
    Base = DWORD()
    NumberOfFunctions = DWORD()
    NumberOfNames = DWORD()
    AddressOfFunctions = DWORD()
    AddressOfNames = DWORD()
    AddressOfNameOrdinals = DWORD()


class PE_FILE(BaseType):
    dos_header = DOS_HEADER()                    # type: DOS_HEADER
    pe_header = PE_HEADER()                      # type: PE_HEADER
    section_header = IMAGE_SECTION_HEADER(4)     # type: IMAGE_SECTION_HEADER
    export_directory = IMAGE_EXPORT_DIRECTORY()  # type: IMAGE_EXPORT_DIRECTORY
    export_func_names = STR(this.export_directory.NumberOfNames)

    def parse(self, stream):
        self.dos_header.parse(f)
        f.seek(self.dos_header.e_lfanew.value)
        self.pe_header.parse(f)
        self.section_header.parse(f)

        # 看一下dll输出表格
        export_rva = self.pe_header.OptionalHeader.DataDirectory[0].VirtualAddress.value
        export_size = self.pe_header.OptionalHeader.DataDirectory[0].Size.value
        if export_size:
            export_phy_addr = self.rva_to_addr(export_rva)
            f.seek(export_phy_addr)
            self.export_directory.parse(f)
            function_name_phy_addr = self.rva_to_addr(self.export_directory.AddressOfNames.value)
            f.seek(function_name_phy_addr)
            self.export_func_names.parse(f)

    def rva_to_addr(self, rva):
        image_base = self.pe_header.OptionalHeader.ImageBase
        section_list = self.section_header.list
        for section_header in section_list:
            if section_header.VirtualAddress.value <= rva <= section_header.VirtualAddress.value + section_header.VirtualSize.value:
                rva_diff = rva - section_header.VirtualAddress.value
                return section_header.PointerToRawData.value + rva_diff


if __name__ == '__main__':
    from file_reader import FileReader
    f = FileReader('kernel32.dll')
    pe_file = PE_FILE()
    pe_file.parse(f)
    print pe_file
