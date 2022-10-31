class PE_offsets:

    def __init__(self):

        # machine types are hex corresponding to the machine used to compile the exe.
        self.MACHINE_TYPES = {
            "0x0": "The contents of this field are assumed to be applicable to any machine type",
            "0x1d3": "Matsushita AM33",
            "0x8664": "AMD64(K8)",
            "0x1c0": "ARM little endian",
            "0x1c4": "ARMv7 (or higher) Thumb mode only",
            "0xaa64": "ARMv8 in 64-bit mode",
            "0xebc": "EFI byte code",
            "0x14c": "Intel 386 or later processors and compatible processors",
            "0x200": "Intel Itanium processor family",
            "0x9041": "Mitsubishi M32R little endian",
            "0x266": "MIPS16",
            "0x366": "MIPS with FPU",
            "0x466": "MIPS16 with FPU",
            "0x1f0": "Power PC little endian",
            "0x1f1": "Power PC with floating point support",
            "0x166": "MIPS little endian",
            "0x1a2": "Hitachi SH3",
            "0x1a3": "Hitachi SH3 DSP",
            "0x1a6": "Hitachi SH4",
            "0x1a8": "Hitachi SH5",
            "0x1c2": "ARM or Thumb (“interworking”)",
            "0x169": "MIPS little-endian WCE v2",
        }

        # hex value representing its subsystem string value
        self.SUBSYSTEMS = {
            "0x0": "IMAGE_SUBSYSTEM_UNKNOWN",
            "0x1": "IMAGE_SUBSYSTEM_NATIVE",
            "0x2": "IMAGE_SUBSYSTEM_WINDOWS_GUI",
            "0x3": "IMAGE_SUBSYSTEM_WINDOWS_CUI",
            "0x7": "IMAGE_SUBSYSTEM_POSIX_CUI",
            "0x9": "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
            "0x10": "IMAGE_SUBSYSTEM_EFI_APPLICATION",
            "0x11": "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
            "0x12": "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
            "0x13": "IMAGE_SUBSYSTEM_EFI_ROM",
            "0x14": "IMAGE_SUBSYSTEM_XBOX"
        }

        # exe image chars.
        self.IMAGE_CHARACTERISTICS = {
            1: "IMAGE_FILE_RELOCS_STRIPPED",
            2: "IMAGE_FILE_EXECUTABLE_IMAGE",
            4: "IMAGE_FILE_LINE_NUMS_STRIPPED",
            8: "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
            10: "IMAGE_FILE_AGGRESSIVE_WS_TRIM",
            20: "IMAGE_FILE_LARGE_ADDRESS_AWARE",
            40: "This flag is reserved for future use.",
            80: "IMAGE_FILE_BYTES_REVERSED_LO",
            100: "IMAGE_FILE_32BIT_MACHINE",
            200: "IMAGE_FILE_DEBUG_STRIPPED",
            400: "IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP",
            800: "IMAGE_FILE_NET_RUN_FROM_SWAP",
            1000: "IMAGE_FILE_SYSTEM",
            2000: "IMAGE_FILE_DLL",
            4000: "IMAGE_FILE_UP_SYSTEM_ONLY",
            8000: "IMAGE_FILE_BYTES_REVERSED_HI"
        }
        self.DLL_CHARACTERISTIC_FLAGS = {

            40: "IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE",
            80: "IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY",
            100: "IMAGE_DLL_CHARACTERISTICS_NX_COMPAT",
            200: "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
            400: "IMAGE_DLLCHARACTERISTICS_NO_SEH",
            800: "IMAGE_DLLCHARACTERISTICS_NO_BIND",
            2000: "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
            8000: "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"
        }

        # Contains IMAGE header offsets and byte allocations within list
        self.IMAGE_HEADER_OFFSETS = {
            "Signature": [int("0x0000000", base=16), 4],
            "Machine": [int("0x0000004", base=16), 2],
            "NumberOfSections": [int("0x0000006", base=16), 2],
            "TimeDateStamp": [int("0x0000008", base=16), 4],
            "PointerToSymbolTable": [int("0x000000C", base=16), 4],
            "NumberOfSymbols": [int("0x0000010", base=16), 4],
            "SizeOfOptionalHeader": [int("0x0000014", base=16), 2],
            "Characteristics": [int("0x0000016", base=16), 2]
        }

        self.DATA_DIRECTORIES_OFFSETS = {
            "Export Table": [int("0x0000078", base=16), 4],
            "size of Export Directory": [int("0x000007C", base=16), 4],
            "Import Table": [int("0x0000080", base=16), 4],
            "size of Import Directory": [int("0x0000084", base=16), 4],
            "Resource Table": [int("0x0000088", base=16), 4],
            "size of Resource Directory": [int("0x000008C", base=16), 4],
            "Exception Table": [int("0x0000090", base=16), 4],
            "size of Exception Directory": [int("0x0000094", base=16), 4],
            "Certificate Table": [int("0x0000098", base=16), 4],
            "size of Security Directory": [int("0x000009C", base=16), 4],
            "Base Relocation Table": [int("0x00000A0", base=16), 4],
            "size of Base Relocation Directory": [int("0x00000A4", base=16), 4],
            "Debug": [int("0x00000A8", base=16), 4],
            "size of Debug Directory": [int("0x00000AC", base=16), 4],
            "Architecture": [int("0x00000B0", base=16), 4],
            "size of Copyright Note": [int("0x00000B4", base=16), 4],
            "Global Ptr": [int("0x00000B8", base=16), 4],
            "Not used": [int("0x00000BC", base=16), 4],
            "TLS Table": [int("0x00000C0", base=16), 4],
            "size of Thread Local Storage Directory": [int("0x00000C4", base=16), 4],
            "Load Config Table": [int("0x00000C8", base=16), 4],
            "size of Load Configuration Directory": [int("0x00000CC", base=16), 4],
            "Bound Import": [int("0x00000D0", base=16), 4],
            "size of Bound Import Directory": [int("0x00000D4", base=16), 4],
            "IAT": [int("0x00000D8", base=16), 4],
            "total size of all Import Address Tables": [int("0x00000DC", base=16), 4],
            "Delay Import Descriptor": [int("0x00000E0", base=16), 4],
            "size of Delay Import Directory": [int("0x00000E4", base=16), 4],
            "CLR Runtime Header": [int("0x00000E8", base=16), 4],
            "size of COM Header": [int("0x00000EC", base=16), 4],
            "reserved": [int("0x00000F0", base=16), 4],
            "reservedtwo": [int("0x00000F4", base=16), 4]
        }

        # contains all optional header offsets
        self.OPTIONAL_HEADER_OFFSETS = {
            "Magic": [int("0x0000018", base=16), 2],
            "MajorLinkerVersion": [int("0x000001A", base=16), 1],
            "MinorLinkerVersion": [int("0x000001B", base=16), 1],
            "SizeOfCode": [int("0x000001C", base=16), 4],
            "SizeOfInitializedData": [int("0x0000020", base=16), 4],
            "SizeOfUninitializedData": [int("0x0000024", base=16), 4],
            "AddressOfEntryPoint": [int("0x0000028", base=16), 4],
            "BaseOfCode": [int("0x000002C", base=16), 4],
            "BaseOfData": [int("0x0000030", base=16), 4],
            "ImageBase": [int("0x0000034", base=16), 4],
            "SectionAlignment": [int("0x0000038", base=16), 4],
            "FileAlignment": [int("0x000003C", base=16), 4],
            "MajorOperatingSystemVersion": [int("0x0000040", base=16), 2],
            "MinorOperatingSystemVersion": [int("0x0000042", base=16), 2],
            "MajorImageVersion": [int("0x0000044", base=16), 2],
            "MinorImageVersion": [int("0x0000046", base=16), 2],
            "MajorSubsystemVersion": [int("0x0000048", base=16), 2],
            "MinorSubsystemVersion": [int("0x000004A", base=16), 2],
            "Win32VersionValue": [int("0x000004C", base=16), 4],
            "SizeOfImage": [int("0x0000050", base=16), 4],
            "SizeOfHeaders": [int("0x0000054", base=16), 4],
            "CheckSum": [int("0x0000058", base=16), 4],
            "Subsystem": [int("0x000005C", base=16), 2],
            "DllCharacteristics": [int("0x000005E", base=16), 2],
            "SizeOfStackReserve": [int("0x0000060", base=16), 4],
            "SizeOfStackCommit": [int("0x0000068", base=16), 4],
            "SizeOfHeapReserve": [int("0x0000070", base=16), 4],
            "SizeOfHeapCommit": [int("0x0000078", base=16), 4],
            "LoaderFlags": [int("0x0000080", base=16), 4],
            "NumberOfRvaAndSizes": [int("0x0000084", base=16), 4]
        }
        # MS dos stub contains important data, especially the PE header offset location
        self.MS_DOS_STUB = {
            'e_magic': [int('0x0000000', base=16), 2],
            'e_cblp': [int("0x0000002", base=16), 2],
            'e_crlc': [int("0x0000006", base=16), 2],
            'e_cparhdr': [int("0x0000008", base=16), 2],
            'e_minalloc': [int("0x000000A", base=16), 2],
            'e_maxalloc': [int("0x000000C", base=16), 2],
            'e_ss': [int("0x000000E", base=16), 2],
            'e_sp': [int("0x0000010", base=16), 2],
            'e_csum': [int("0x0000012", base=16), 2],
            'e_ip': [int("0x0000014", base=16), 2],
            'e_cs': [int("0x0000016", base=16), 2],
            'e_lfarlc': [int("0x0000018", base=16), 2],
            'e_ovno': [int("0x000001A", base=16), 2],
            'e_res': [int("0x0000001C", base=16), 2],
            'e_oemid': [int("0x0000024", base=16), 2],
            'e_oemidinfo': [int("0x0000026", base=16), 2],
            'e_res2': [int("0x0000002", base=16), 2],
            'pe_header_loc':[int("0x000003c", base=16),4]
        }

        self.SECTION_TABLE_OFFSETS = {
            "Name":["0x00",8],
            "VirtualSize":["0x08",4],
            "VirtualAddress":["0x0C",4],
            "SizeOfRawData":["0x10",4],
            "PointerToRawData":["0x14", 4],
            "PointerToRelocations":["0x18",4],
            "PointerToLinenumbers":["0x1C", 4],
            "NumberOfRelocations":["0x20", 2],
            "NumberOfLineNumbers":["0x22", 2],
            "Characteristics":["0x24", 4]
        }

        self.SECTION_TABLE_CHARS = {
            8: "IMAGE_SCN_TYPE_NO_PAD",
            32: "IMAGE_SCN_CNT_CODE",
            64: "IMAGE_SCN_CNT_INITIALIZED_DATA",
            128: "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
            256: "IMAGE_SCN_LNK_OTHER",
            512: "IMAGE_SCN_LNK_INFO",
            2048: "IMAGE_SCN_LNK_REMOVE",
            4096: "IMAGE_SCN_LNK_COMDAT",
            32768: "IMAGE_SCN_GPREL",
            16777216: "IMAGE_SCN_LNK_NRELOC_OVFL",
            33554432: "IMAGE_SCN_MEM_DISCARDABLE",
            67108864: "IMAGE_SCN_MEM_NOT_CACHED",
            134217728: "IMAGE_SCN_MEM_NOT_PAGED",
            268435456: "IMAGE_SCN_MEM_SHARED",
            536870912: "IMAGE_SCN_MEM_EXECUTE",
            1073741824: "IMAGE_SCN_MEM_READ",
            2147483648: "IMAGE_SCN_MEM_WRITE"
        }


        #  --- NOT USED UNTIL BUGS ARE FIXED ---

        # # Stores the amount of resources per category belonging to the DLL. All 0 inititally
        # self.RESOURCE_COUNT = {
        #     "Cursors": 0,
        #     "Bitmaps": 0,
        #     "Icons": 0,
        #     "Dialogs": 0,
        #     "StringTables": 0,
        #     "RCData": 0,
        #     "CursorGroups": 0,
        #     "IconGroups": 0,
        #     "VersionInfo": 0,
        #     "ConfigurationFiles": 0
        # }

        # self.LANG_CHARSET_IDENTIFIERS = {
        #     "0x0401":"Arabic",
        #     "0x0402": "Bulgarian",
        #     "0x0403": "Catalan",
        #     "0x0404": "Traditional Chinese",
        #     "0x0405": "Czech",
        #     "0x0406": "Danish",
        #     "0x0407": "German",
        #     "0x0408": "Greek",
        #     "0x0409": "U.S. English",
        #     "0x040A": "Castilian Spanish",
        #     "0x040B": "	Finnish",
        #     "0x040C": "French",
        #     "0x040D": "Hebrew",
        #     "0x040E": "Hungarian",
        #     "0x040F": "Icelandic",
        #     "0x0410": "Italian",
        #     "0x0411": "Japanese",
        #     "0x0412": "Korean",
        #     "0x0413": "Dutch",
        #     "0x0414": "Norwegian – Bokmal",
        #     "0x0810": "Swiss Italian",
        #     "0x0813": "Belgian Dutch",
        #     "0x0814": "Norwegian – Nynorsk",
        #     "0x0415": "Polish",
        #     "0x0416": "Portuguese (Brazil)",
        #     "0x0417": "Rhaeto-Romanic",
        #     "0x0418": "Romanian",
        #     "0x0419": "Russian",
        #     "0x041A": "Croato-Serbian (Latin)",
        #     "0x041B": "Slovak",
        #     "0x041C": "Albanian",
        #     "0x041D": "Swedish",
        #     "0x041E": "Thai",
        #     "0x041F": "Turkish",
        #     "0x0420": "Urdu",
        #     "0x0421": "Bahasa",
        #     "0x0804": "Simplified Chinese",
        #     "0x0807": "Swiss German",
        #     "0x0809": "U.K. English",
        #     "0x080A": "Spanish (Mexico)",
        #     "0x080C": "Belgian French",
        #     "0x0C0C": "Canadian French",
        #     "0x100C": "Swiss French",
        #     "0x0816": "Portuguese (Portugal)",
        #     "0x081A": "Serbo-Croatian (Cyrillic)"
        # }
        # self.CHAR_SETS = {
        #     0:"7-bit ASCII",
        #     932: "Japan (Shift – JIS X-0208)",
        #     949: "Korea (Shift – KSC 5601)",
        #     950: "Taiwan (Big5)",
        #     1200: "Unicode",
        #     1250: "Latin-2 (Eastern European)",
        #     1251: "Cyrillic",
        #     1252: "Multilingual",
        #     1253: "Greek",
        #     1254: "Turkish",
        #     1255: "Hebrew",
        #     1256: "Arabic",
        # }