import datetime
import collections
from itertools import combinations
import re
from tqdm import tqdm
from colorama import Fore, Style,init
import multiprocessing
from multiprocessing import Queue
import sys
import numpy
numpy.set_printoptions(threshold=sys.maxsize)
import math
from classes.PE_Offsets import PE_offsets

init()

# PE PARSER. DESIGNED AND DEVELOPED BY CHRIS TROY
# Resources Used: https://www.aldeid.com/wiki/PE-Portable-executable << OFFSET locations



# PE Extractor class. Instantiated/gives access to class methods for data collection access of the EXE.

class PE_Extractor(PE_offsets):

    def __init__(self, file, file_name_id):
        # Inherit the PE_Offsets from the PE_Offset class
        super().__init__()
        # open the file up. It is set to (RB) read/binary(bytes)
        self.entro_backup_path = file
        self.file = open(file, 'rb')
        self.file_name_id = file_name_id
        # if true, QWORD 8 bytes must be added for base of data inclusion
        self.magic_type_64bit = False



        self.PACKER_SECT_NAMES = [".aspack",".adata",".ASPack","ASPack",".boom",".ccg",".charmve","BitArts","DAStub",
                                  "!EPack",".ecode",".edata",".enigma1",".enigma2","FSG!",".imrsiv",".gentee",".kkrunchy",
                                  "kkrunchy",".mackt",".MaskPE","MEW",".mnbvcx1",".mnbvcx2",".MPRESS1",".MPRESS2",".neolite",".neolit",".nsp1",
                                  ".nsp0",".nsp2",".packed",".pebundle",".PEBundle",".PEC2TO",".PEC2",".pec",".pec1",".pec2",
                                  ".pec3",".pec4",".pec5",".pec6",".PEC2MO",".PELOCKnt",".perplex",".PESHiELD",".petite",
                                  ".pinclie",".ProCrypt",".RLPack",".rmnet",".RCryptor",".RPCrypt",".seau",".sforce3",
                                  ".shrink1",".shrink2",".shrink3",".spack",".svkp",".Themida",".taz",".tsuarch",".tsustub",
                                  ".packed",".PEPACK!!",".Upack",".ByDwing",".UPX0",".UPX1",".UPX2",".UPX3",".UPX!",".vmp0",
                                  ".vmp1",".vmp2",".VProtect",".winapi",".WinLicen","._winzip_",".WWPACK",".WWP32",".yP",".y0da",
                                  "nsp1","nsp0","nsp2", "pebundle", "PEBundle", "PEC2TO","PECompact2","PEC2","pec","pec1","pec2","pec3","pec4","pec5","pec6",
                                  "PEC2MO","PELOCKnt", "PESHiELD", "ProCrypt", "RCryptor", "Themida", "PEPACK!!", "UPX0", "UPX1", "UPX2", "UPX3", "UPX!",
                                  "VProtect","WinLicen","_winzip_"]

        self.COMMON_SECT_NAMES = [
            ".00cfg",
            ".AAWEBS",
            ".apiset",
            ".arch",
            ".autoload_text",
            ".bindat",
            ".bootdat",
            ".bss",
            ".BSS",
            ".buildid",
            ".CLR_UEF",
            ".code",
            ".cormeta",
            ".complua",
            ".CRT",
            ".cygwin_dll_common",
            ".data",
            ".DATA",
            ".data1",
            ".data2",
            ".data3",
            ".debug",
            ".debug$F",
            ".debug$P",
            ".debug$S",
            ".debug$T",
            ".drectve",
            ".didat",
            ".didata",
            ".edata",
            ".eh_fram",
            ".export",
            ".fasm",
            ".flat",
            ".gfids",
            ".giats",
            ".gljmp",
            ".glue_7t",
            ".glue_7",
            ".idata",
            ".idlsym",
            ".impdata",
            ".import",
            ".itext",
            ".ndata",
            ".orpc",
            ".pdata",
            ".rdata",
            ".reloc",
            ".rodata",
            ".rsrc",
            ".sbss",
            ".script",
            ".shared",
            ".sdata",
            ".srdata",
            ".stab",
            ".stabstr",
            ".sxdata",
            ".text",
            ".text0",
            ".text1",
            ".text2",
            ".text3",
            ".textbss",
            ".tls",
            ".tls$",
            ".udata",
            ".vsdata",
            ".xdata",
            ".wixburn",
            ".wpp_sf",
            "BSS",
            "CODE",
            "DATA",
            "DGROUP",
            "idata",
            "INIT",
            "minATL",
            "PAGE",
            "rdata",
            "sdata",
            "shared",
            "Shared",
            "testdata",
            "text"]

        # Once code executes, it gets PE offset and sets it for other methods to use at start position
        self.file.seek(self.MS_DOS_STUB['pe_header_loc'][0],1)
        # read 4 bytes. This value will give us the start location of PE offset
        self.PE_HEADER_LOC = self.file.readline(4)
        # little endian decimal value of pe header start location
        self.pe_loc_value = int.from_bytes(self.PE_HEADER_LOC, "little")
        # All variables below are empty initially and are set once private methods execute
        self.SECTION_TABLE_VALUES = []
        self.IMAGE_HEADER_VALUES = {}
        self.OPTIONAL_HEADER_VALUES = {}
        self.MS_DOS_STUB_VALUES = {}
        self.DATA_DIRECTORY_VALUES = {}
        self.SECTION_TABLE_DICT_VALUES = {}
        self.SECTION_DATA = {}
        self.section_entropy = []


        # Execute methods for each executable
        q = Queue()
        multi_process = multiprocessing.Process(target=self.__ms_Stub(),args=(q,))
        multi_process2 = multiprocessing.Process(target=self.__image_file_header(),args=(q,))
        multi_process3 = multiprocessing.Process(target=self.__optional_header(),args=(q,))
        multi_process4 = multiprocessing.Process(target=self.__data_directory(),args=(q,))
        multi_process5 = multiprocessing.Process(target=self.__section_table(),args=(q,))
        multi_process6 = multiprocessing.Process(target=self.__section_data(),args=(q,))

        multi_process.start()
        multi_process2.start()
        multi_process3.start()
        multi_process4.start()
        multi_process5.start()
        multi_process6.start()

        multi_process.join()
        multi_process2.join()
        multi_process3.join()
        multi_process4.join()
        multi_process4.join()
        multi_process5.join()
        multi_process6.join()



        # will contain most features we want to use, with some derived features as well
        self.MASTER_FEATURES_DOCUMENT = {}

        # close file when finished parsing data
        self.file.close()

    """
    How data retrieval works (The run down): 
    
    1.  Run a for loop over pre-defined offsets where these values lie in our dictionaries. Use base 16 decimal
    2. seek to the beginning of the file to ensure we have reset
    3. seek the pre-defined offset from the current position
    4. From current position, read bytes using the pre-defined size, be it (byte, WORD, DWORD, QWORD) in the dictionary
    5. Store the returned bytes into a variable
    6. Convert bytes to little endian
    7. Insert into the empty dictionary the new key and new value, being the hex
    
    """
    # MS DOS Stub method. MS Stub is the first part of the EXE structure. It contains the location to PE_Header offset
    def __ms_Stub(self):
        for prop in tqdm(self.MS_DOS_STUB, desc=Fore.BLUE+"Acquiring MS_Dos_Stub"):
            self.file.seek(0,0)
            self.file.seek(self.MS_DOS_STUB[prop][0],1)
            data = self.file.readline(self.MS_DOS_STUB[prop][1])
            data = int.from_bytes(data, "little")
            self.MS_DOS_STUB_VALUES[prop] = hex(data)
        print(Fore.BLUE+"\t{}".format(self.MS_DOS_STUB_VALUES))
        print(Style.RESET_ALL)

    # Image file header contains data like signature, how many sections, and image characteristics etc.
    def __image_file_header(self):
        for prop in tqdm(self.IMAGE_HEADER_OFFSETS, desc=Fore.CYAN+"Acquiring Image File Header information"):
            self.file.seek(self.pe_loc_value,0)
            self.file.seek(self.IMAGE_HEADER_OFFSETS[prop][0],1)
            data = self.file.readline(self.IMAGE_HEADER_OFFSETS[prop][1])
            data = int.from_bytes(data, "little")
            self.IMAGE_HEADER_VALUES[prop] = hex(data)

        # call our private method to also include the image chars
        chars = self.__image_file_characteristics()
        for img in self.IMAGE_CHARACTERISTICS.values():
            self.IMAGE_HEADER_VALUES[img] = 0
            for char in chars:
                if char == img:
                    self.IMAGE_HEADER_VALUES[img] = 1
                else:
                    pass

        # Stores our machine type value for comparison
        machine_type = ""
        for data in self.IMAGE_HEADER_VALUES['Machine']:
            machine_type += data
        # for machine type. if it matches what we have stored, put 1, and put 0 for all the rest
        for mac in self.MACHINE_TYPES.keys():
            if mac == machine_type:
                self.IMAGE_HEADER_VALUES[self.MACHINE_TYPES[mac]] = 1
            else:
                self.IMAGE_HEADER_VALUES[self.MACHINE_TYPES[mac]] = 0

        # determine how new the exe is
        exe_timestamp = datetime.datetime.fromtimestamp(int(self.IMAGE_HEADER_VALUES['TimeDateStamp'], base=16))
        present_timestamp = datetime.datetime.now()
        if exe_timestamp.year == present_timestamp.year:
            self.IMAGE_HEADER_VALUES['Recently Compiled'] = 1
        else:
            self.IMAGE_HEADER_VALUES['Recently Compiled'] = 0

        # self.IMAGE_HEADER_VALUES['Characteristic_Flag'] = chars
        print(Fore.CYAN + "\t{}".format(self.IMAGE_HEADER_VALUES))
        print(Style.RESET_ALL)

    # Image file characteristics tell us more meta information about the EXE
    def __image_file_characteristics(self):

        # Get the hex value of the image chars
        characteristics_val = self.IMAGE_HEADER_VALUES['Characteristics']
        charachteristic_val = characteristics_val[2:]


        # subset sum problem. Code refactored from:
        # https://stackoverflow.com/questions/54965404/python-subset-sum-problem-for-given-length-of-elements
        # By  Alain T.
        # List contains numerical values associated to its hex counterpart corresponding to flag descriptions
        """
        Subset Sum problem:
        Our list below named as (set) contains all possible flag values. If we get a value of say = 34, we must add up
        into the list all the possibilities to get to 34. Ex: 20 + 10 + 4. 
        
        This means the flag on index position 2,4 and 5 contain our flags.
        This same process is used for defining other flags
        
        The list comprehension used to solve to this problem was found on stack overflow discussed above.
        
        """
        set = [1, 2, 4, 8, 10, 20, 40, 80, 100, 200, 400, 800, 1000, 2000, 4000, 8000]
        total = int(characteristics_val, base=16)
        length = 0
        flags = ""
        # 15 POSSIBLE FLAGS TO APPLY, including 0.
        for i in range(17):
            result = [c for c in combinations(set, length) if sum(c) == total]  # This line By  Alain T.
            length += 1
            if result:
                flags = result[0]
                print(result)
                break
        # will contain the string flags
        img_chars_list = []
        # Runs loop and puts string flags into list above

        for characteristic in flags:
            img_chars_list.append(self.IMAGE_CHARACTERISTICS[characteristic])
        print(img_chars_list)
        return img_chars_list

    # Optional header is where a lot of data is extracted. Some being imagebase, size of image, number of RVA's etc.
    def __optional_header(self):

        MAGIC_SIGNATURE_VALUES = {
            "0x10b": "PE32 (Normal Executable File)",
            "0x107": "ROM image",
            "0x20b": "PE64"
        }
        for prop in tqdm(self.OPTIONAL_HEADER_OFFSETS, desc=Fore.MAGENTA+"Acquiring optional header information"):
            self.file.seek(self.pe_loc_value, 0)
            self.file.seek(self.OPTIONAL_HEADER_OFFSETS[prop][0], 1)
            data = self.file.readline(self.OPTIONAL_HEADER_OFFSETS[prop][1])
            data = int.from_bytes(data, "little")
            hex_value = hex(data)
            # Try to establish the PE type, if PE32 +, imagebase will actually be baseofdata (shift)
            try:
                for key in MAGIC_SIGNATURE_VALUES.keys():
                    if hex_value == key:
                        if MAGIC_SIGNATURE_VALUES[hex_value] == "PE64":
                            # We get a hit. It's 64, so it requires 8 byte inclusion shift for (base of data) insert
                            # THIS TO TURN TRUE ONCE DISCOVERED
                            self.magic_type_64bit = True
                            self.OPTIONAL_HEADER_OFFSETS['ImageBase'][0] = self.OPTIONAL_HEADER_OFFSETS['BaseOfData'][0]
                            self.OPTIONAL_HEADER_OFFSETS['ImageBase'][1] = 8

            except KeyError:

                print("Something went wrong with the keys")

            self.OPTIONAL_HEADER_VALUES[prop] = hex_value

        # Get subsytem type. Only 1 subsystem can be applied. A simple loop and match will suffice.
        for sys in self.SUBSYSTEMS:
            if sys == self.OPTIONAL_HEADER_VALUES['Subsystem']:
                self.OPTIONAL_HEADER_VALUES[self.SUBSYSTEMS[sys]] = 1
            else:
                self.OPTIONAL_HEADER_VALUES[self.SUBSYSTEMS[sys]] = 0

        # returns the DLL strings
        dlls = self.__dll_characteristics()
        # running multiple loops to do comparisons on strings which then sets the binary choice
        for dll in self.DLL_CHARACTERISTIC_FLAGS:
            for key in dlls:
                if key == self.DLL_CHARACTERISTIC_FLAGS[dll]:
                    self.OPTIONAL_HEADER_VALUES[self.DLL_CHARACTERISTIC_FLAGS[dll]] = 1
                else:
                    self.OPTIONAL_HEADER_VALUES[self.DLL_CHARACTERISTIC_FLAGS[dll]] = 0

        print(Fore.MAGENTA + "\t{}".format(self.OPTIONAL_HEADER_VALUES))
        print(Style.RESET_ALL)

    # Gives us more meta information regarding the DLL's used
    def __dll_characteristics(self):

        # same problem as described above regarding sum subset problem. Same solution is applied for these flags
        dll_hex_count = re.findall(r'\d+', self.OPTIONAL_HEADER_VALUES['DllCharacteristics'])
        set = [40, 80, 100, 200, 400, 800, 2000, 8000]
        total = int(dll_hex_count[1])
        length = 0
        dllflags = ""

        for i in range(8):
            result = [c for c in combinations(set, length) if sum(c) == total]  # By  Alain T.
            length += 1
            if result:
                dllflags = result[0]
                break

        dll_chars_list = []

        for dllcharacteristic in dllflags:

            dll_chars_list.append(self.DLL_CHARACTERISTIC_FLAGS[dllcharacteristic])
            # If no flags are found, rather than returning an empty list, return a list with one value (Not Found)

        if len(dll_chars_list) <= 0:
            return ["No Flags"]
        else:
            return dll_chars_list

    # Contains information regarding different directory locations, their RVA (Relative virtual address) and sizes
    def __data_directory(self):

        for prop in tqdm(self.DATA_DIRECTORIES_OFFSETS, desc=Fore.GREEN+"Acquiring Data Directory information"):
            if self.magic_type_64bit:
                self.file.seek(self.pe_loc_value, 0)
                self.file.seek(self.DATA_DIRECTORIES_OFFSETS[prop][0] + 16, 1)
                data = self.file.readline(self.DATA_DIRECTORIES_OFFSETS[prop][1])
                data = int.from_bytes(data, "little")
                hex_value = hex(data)
                self.DATA_DIRECTORY_VALUES[str(prop)] = hex_value
            else:
                self.file.seek(self.pe_loc_value, 0)
                self.file.seek(self.DATA_DIRECTORIES_OFFSETS[prop][0], 1)
                data = self.file.readline(self.DATA_DIRECTORIES_OFFSETS[prop][1])
                data = int.from_bytes(data, "little")
                hex_value = hex(data)
                self.DATA_DIRECTORY_VALUES[str(prop)] = hex_value

        print(Fore.GREEN + "\t{}".format(self.DATA_DIRECTORY_VALUES))
        print(Style.RESET_ALL)

    # section table contains the headers for each section, be it .text or .data pointing to raw address and virtual.
    def __section_table(self):
        # Count the amount of sections this exe has. Returns hex value
        section_count = self.IMAGE_HEADER_VALUES['NumberOfSections']
        # Convert the hex value to its decimal equivalent
        section_count = int(section_count, base=16)
        # Get the start of section by first adding 24 to PE_Header beginning position, plus our optional header size
        # This puts us directly at the start of the section table
        section_start = self.pe_loc_value + 24 + int(self.IMAGE_HEADER_VALUES['SizeOfOptionalHeader'], base=16)

        for i in tqdm(range(section_count), desc=Fore.LIGHTBLUE_EX+"Acquiring Section Table header information"):

            counter = 0
            record = []

            for prop in self.SECTION_TABLE_OFFSETS:
                self.file.seek(section_start, 0)
                self.file.seek(int(self.SECTION_TABLE_OFFSETS[prop][0], base=16), 1)
                data = self.file.readline(self.SECTION_TABLE_OFFSETS[prop][1])
                data = int.from_bytes(data, "little")
                record.append({prop: hex(data)})
                # if 9 it means we have moved onto next section. 9 being the amount of headers per section
                if counter == 9:
                    # Add the new section record to our list
                    self.SECTION_TABLE_VALUES.append(record)
                    print(record)
                    # Wipe the list for the next section header record
                    record = []
                    # Reset counter for next section header record
                    counter = 0
                else:
                    counter += 1

            # skip ahead 40 bytes to the next section table header information
            section_start += 40


        print(Fore.LIGHTBLUE_EX + "\t{}".format(self.SECTION_TABLE_VALUES))
        print(Style.RESET_ALL)

    # gets the data for each section header belonging to the exe
    def __section_data(self):
        # contains the section (data) for each section header. Ex: .text, .idata etc.
        section = []

        for sec in self.SECTION_TABLE_VALUES:
            size_raw = int(sec[3]['SizeOfRawData'], base=16)
            pointer_to_raw = int(sec[4]['PointerToRawData'], base=16)
            self.file.seek(pointer_to_raw, 0)
            data = self.file.read(size_raw)
            # section entropy tester
            entropy = self.__entropy_calculation(data)
            self.section_entropy.append(entropy)
            section.append(data)

        # Counter helps iterate through section data list. This helps get the correct data for each header
        counter = 0
        # comm_name_count = 0
        for sec in self.SECTION_TABLE_VALUES:
            sect_name = sec[0]['Name']
            print(sect_name)
            odd_check = len(sect_name[2:]) % 2
            if odd_check == 1:
                sect_name = "0" + sect_name[2:]
            else:
                continue

            # Contains string version of section header name. Rather than using hex value.
            string_sec_name = bytearray.fromhex(sect_name[2:]).decode('latin1')

            # Because of endianness of data, strings  need to be reversed from: .txet -> .text  This[::-1] reverses
            self.SECTION_DATA[string_sec_name[::-1]] = section[counter]
            counter += 1

        print(self.SECTION_TABLE_VALUES)


    # Just a basic hex_to_demical method.
    def hex_to_decimal(self,hex):

        return int(hex, base=16)

    # Gets ms_Stub info and converts to decimal before returning it.
    def get_ms_stub(self):

        for key in self.MS_DOS_STUB_VALUES:

            self.MS_DOS_STUB_VALUES[key] = self.hex_to_decimal(self.MS_DOS_STUB_VALUES[key])

        return self.MS_DOS_STUB_VALUES

    # Gets image file header data and converts to decimal before returning it.
    def get_image_file_header(self):
        # to decimal keys, while others are in binary format, either 0 or 1 for image characteristics
        dec_keys = ['Signature','Machine','NumberOfSections','TimeDateStamp','PointerToSymbolTable','NumberOfSymbols',
                    'SizeOfOptionalHeader','Characteristics']

        for key in self.IMAGE_HEADER_VALUES:
            # This key contains strings which we cannot run the hex_to_demical method on.
            for i in range(len(dec_keys)):

                if key == dec_keys[i]:

                    self.IMAGE_HEADER_VALUES[key] = self.hex_to_decimal(self.IMAGE_HEADER_VALUES[key])

        return self.IMAGE_HEADER_VALUES

    def get_optional_header(self):
        # contains all columns we want to apply hex to decimal conversion
        dec_keys = ['Magic','MajorLinkerVersion','MinorLinkerVersion','SizeOfInitializedData','SizeOfUninitializedData',
                    'AddressOfEntryPoint','BaseOfCode','BaseOfData','ImageBase','SectionAlignment',
                    'FileAlignment','MajorOperatingSystemVersion','MajorImageVersion','MinorImageVersion',
                    'MajorSubsystemVersion','MinorSubsystemVersion','Win32VersionValue','SizeOfImage','SizeOfHeaders',
                    'CheckSum','Subsystem','DllCharacteristics','SizeOfStackReserve','SizeOfStackCommit',
                    'SizeOfHeapReserve','SizeOfHeapCommit','LoaderFlags','NumberOfRvaAndSizes']

        for key in self.OPTIONAL_HEADER_VALUES:
            # These keys contain strings which we cannot run the hex_to_demical method on.
            for i in range(len(dec_keys)):

                if key == dec_keys[i]:

                    self.OPTIONAL_HEADER_VALUES[key] = self.hex_to_decimal(self.OPTIONAL_HEADER_VALUES[key])

        return self.OPTIONAL_HEADER_VALUES

    def get_data_directory(self):

        return self.DATA_DIRECTORY_VALUES

    def get_section_table(self):
        # Because we will be compiling many records of exes, we will have key name conflicts overwriting the prev
        # To get around this, each key will contain a list.
        """
        Example: "Name":['.text','.data','.idata','.rdata']
        If we didn't add a list, the record would keep overwriting so that the last one (rdata) and its value would be
        stored. This is applied for the rest of the keys inside self.SECTION_TABLE_ORGANIZED
        """
        self.SECTION_TABLE_ORGANIZED = {
            "Name": [],
            "VirtualSize": [],
            "VirtualAddress": [],
            "SizeOfRawData": [],
            "PointerToRawData": [],
            "PointerToRelocations": [],
            "PointerToLinenumbers": [],
            "NumberOfRelocations": [],
            "NumberOfLineNumbers": [],
            "Characteristics": []
        }

        # implementing the subset sum problem solution again for section characteristics
        SECTION_CHARS_LIST = [8, 32, 64, 128, 256, 512, 2048, 4096, 32768, 16777216, 33554432, 67108864, 134217728, 268435456,
                              536870912, 1073741824, 2147483648]

        # Get all values inside section table dict. We wil manually append then to ensure all values are part of key
        for val in self.SECTION_TABLE_VALUES:
            name = val[0]
            virtualsize = val[1]
            virtual_add = val[2]
            size_of_raw_Data = val[3]
            pointer_to_raw_data = val[4]
            pointer_to_relocations = val[5]
            pointer_to_line_numbers = val[6]
            number_of_relocations = val[7]
            number_of_line_nums = val[8]
            characteristics = val[9]

            # will contain the sect flags
            sect_chars_list = []
            for char in characteristics.values():

                total = int(char, base=16)
                length = 0
                flags = ""

                # 15 POSSIBLE FLAGS TO APPLY, including 0.
                for i in range(17):

                    result = [c for c in combinations(SECTION_CHARS_LIST, length) if sum(c) == total]  # This line By  Alain T.
                    length += 1

                    if result:

                        flags = result[0]
                        break

                # Runs loop and puts string flags into list above
                for characteristic in flags:

                    # img_chars_list.append(self.IMAGE_CHARACTERISTICS[characteristic])
                    sect_chars_list.append(self.SECTION_TABLE_CHARS[characteristic])
            
            # checking if sec name is odd. If it is append a 0 to correct parsing error
            odd_check = len(name['Name'][2:]) % 2
            if odd_check == 1:
                name['Name'] = "0" + name['Name'][2:]
            # converts hex to string.
            string_sec_name = bytearray.fromhex(name['Name'][2:]).decode('latin1')
            # reversing string so it is readable
            string_sec_name = string_sec_name[::-1]
            # Applying the appends to the new self.SECTION_TABLE_ORGANIZED dictionary
            self.SECTION_TABLE_ORGANIZED['Filename'] = self.file_name_id
            self.SECTION_TABLE_ORGANIZED['Name'].append(string_sec_name)
            self.SECTION_TABLE_ORGANIZED['VirtualSize'].append(int(virtualsize['VirtualSize'], base=16))
            self.SECTION_TABLE_ORGANIZED['VirtualAddress'].append(int(virtual_add['VirtualAddress'], base=16))
            self.SECTION_TABLE_ORGANIZED['SizeOfRawData'].append(int(size_of_raw_Data['SizeOfRawData'], base=16))
            self.SECTION_TABLE_ORGANIZED['PointerToRawData'].append(int(pointer_to_raw_data['PointerToRawData'], base=16))
            self.SECTION_TABLE_ORGANIZED['PointerToRelocations'].append(int(pointer_to_relocations['PointerToRelocations'], base=16))
            self.SECTION_TABLE_ORGANIZED['PointerToLinenumbers'].append(int(pointer_to_line_numbers['PointerToLinenumbers'], base=16))
            self.SECTION_TABLE_ORGANIZED['NumberOfRelocations'].append(int(number_of_relocations['NumberOfRelocations'], base=16))
            self.SECTION_TABLE_ORGANIZED['NumberOfLineNumbers'].append(int(number_of_line_nums['NumberOfLineNumbers'], base=16))
            self.SECTION_TABLE_ORGANIZED['Characteristics'].append({string_sec_name:  sect_chars_list})
            self.SECTION_TABLE_ORGANIZED['Entropy'] = self.section_entropy
            # self.SECTION_TABLE_ORGANIZED['Characteristics'].append(int(characteristics['Characteristics'], base=16))

        return self.SECTION_TABLE_ORGANIZED


    # Found online: https://blog.cugu.eu/post/fast-python-file-entropy/
    def __entropy_calculation(self,raw_data_section):
        file_entropy = 0
        counter = collections.Counter(raw_data_section)
        section_length = len(raw_data_section)
        for count in counter.values():
            p_x = count / section_length
            file_entropy += - p_x * math.log2(p_x)

        return file_entropy

    # looks for common packed section names
    def __packer_checker(self):
        packed_sections_count = 0
        for sect in self.SECTION_TABLE_VALUES:
            sect_name = sect[0]['Name']
            string_sec_name = bytearray.fromhex(sect_name[2:]).decode('latin1')
            string_sec_name = string_sec_name[::-1]
            
            if string_sec_name in self.PACKER_SECT_NAMES:
                packed_sections_count += 1
            else:
                pass


        return packed_sections_count

    # looks for uncommon section names
    def __section_name_checker(self):
        count = 0
        for sect in self.SECTION_TABLE_VALUES:
            sect_name = sect[0]['Name']
            string_sec_name = bytearray.fromhex(sect_name[2:]).decode('latin1')
            string_sec_name = string_sec_name[::-1]
            if string_sec_name in self.COMMON_SECT_NAMES:
                pass
            else:
                count += 1

        return count

    # main method which will get relevent features which will go towards creating a dataset
    def all_relevent_features(self):

        entropy_file = open(self.entro_backup_path, 'rb')
        self.FILE_ENTROPY = self.__entropy_calculation(entropy_file.read())
        entropy_file.close()
        # full file entropy check
        self.MASTER_FEATURES_DOCUMENT.update(self.MS_DOS_STUB_VALUES)
        self.MASTER_FEATURES_DOCUMENT.update(self.IMAGE_HEADER_VALUES)
        self.MASTER_FEATURES_DOCUMENT.update(self.OPTIONAL_HEADER_VALUES)
        self.MASTER_FEATURES_DOCUMENT.update(self.DATA_DIRECTORY_VALUES)
        self.MASTER_FEATURES_DOCUMENT.update(self.get_section_table())
        if self.MS_DOS_STUB_VALUES['e_magic'] != '0x5a4d' and self.FILE_ENTROPY > 6.7:
            self.MASTER_FEATURES_DOCUMENT['Suspicious File'] = 1
        elif self.FILE_ENTROPY > 6.7:
            self.MASTER_FEATURES_DOCUMENT['Suspicious File'] = 1
        else:
            self.MASTER_FEATURES_DOCUMENT['Suspicious File'] = 0
        sus_sections_count = 0
        for key in self.MASTER_FEATURES_DOCUMENT:
            if key == "Entropy":
                for entr in self.MASTER_FEATURES_DOCUMENT['Entropy']:
                    if entr > 6.5:
                        sus_sections_count += 1
                    else:
                        continue
            else:
                break

        self.MASTER_FEATURES_DOCUMENT['Suspicious Sections'] = sus_sections_count
        # self.MASTER_FEATURES_DOCUMENT['DLL Strings'] = self.get_found_dlls()
        self.MASTER_FEATURES_DOCUMENT['File Entropy'] = self.FILE_ENTROPY
        self.MASTER_FEATURES_DOCUMENT['Uncommon Section Names Count'] = self.__section_name_checker()
        self.MASTER_FEATURES_DOCUMENT['Packed Sections Detected'] = self.__packer_checker()

        sus_wr_secs_count = 0
        # check characteristics for strange permissions
        for char in self.MASTER_FEATURES_DOCUMENT['Characteristics']:
            for sect in self.PACKER_SECT_NAMES:
                if sect in char:
                    if "IMAGE_SCN_CNT_UNINITIALIZED_DATA" in char[sect] and "IMAGE_SCN_MEM_READ" in char[sect] and "IMAGE_SCN_MEM_EXECUTE" in char[sect] and "IMAGE_SCN_MEM_WRITE" in char[sect]:
                       sus_wr_secs_count += 1
            for sect in self.COMMON_SECT_NAMES:
                if sect in char:
                    if "IMAGE_SCN_CNT_UNINITIALIZED_DATA" in char[sect] and "IMAGE_SCN_MEM_READ" in char[sect] and "IMAGE_SCN_MEM_EXECUTE" in char[sect] and "IMAGE_SCN_MEM_WRITE" in char[sect]:
                        sus_wr_secs_count += 1
        
        self.MASTER_FEATURES_DOCUMENT['Suspicious Writeable Sections'] = sus_wr_secs_count
        return self.MASTER_FEATURES_DOCUMENT


# left in below for debugging purposes directly from the class rather than running it through main
# pe_info = PE_Extractor('../HxD.exe', 'hd.exe')

# pe_info = PE_Extractor('../GeForceNOW-release.exe', 'gpu.exe')
# data = pe_info.get_ms_stub()

# print(data)












