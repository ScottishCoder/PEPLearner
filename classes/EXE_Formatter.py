import pandas as pd  # Gives access to Dataframe objects required for saving data and organising it

class EXE_Formatter:
    # When instantiated, object will expect the pe_data, the users chosen path and what format they want to use.
    def __init__(self, extracted_pe_data, output_path, format_type, dataset_type):
        # list containing all PE_Extractor Objects and associated methods
        self.extracted_pe_data_list = extracted_pe_data
        self.format_type = format_type
        self.output_path = output_path
        self.dataset_type = dataset_type

    def hex_to_decimal(self, hex):
        return int(hex, base=16)

    # Only one method is required for formatting purposes.
    def format_to_dataframe(self):
        # stores all executables and the parsed PE data which will be extracted and sorted
        executables = []
        # Get length of pe_data_list. This length will be how many exes were scanned and data extracted. It will vary
        for i in range(len(self.extracted_pe_data_list)):
            """
            Explanation: 
            i being 0, meaning the first exe in list at position 0. We apply all methods to it belonging to the 
            PE_Extractor class. 
            i is now 1, it gets the exe at index position 1 in the list and does the same.
            It follows this process until it has gotten all exes and appended the results to their corresponding list.
            """
            executables.append(self.extracted_pe_data_list[i].all_relevent_features())
        # Init an empty list for sorting
        self.EXECUTABLE_FEATURES = dict()
        # Dictionary with all exes and sorted/parsed data will go into dataframes list creating dataframe for each exe
        self.dataframes = []
        for data in executables:
            if not data.keys() == "Entropy":
                data['Entropy'] = ["File compressed or encrypted"]
            # YES, THIS COULD BE DONE WITH A LOOP. HOWEVER, TO ENSURE COLUMNS I WANTED, THIS WAS THE APPROACH
            # self.EXECUTABLE_FEATURES['Filename'] = data['Filename']
            self.EXECUTABLE_FEATURES['Number of sections'] = self.hex_to_decimal(data['NumberOfSections'])
            self.EXECUTABLE_FEATURES['Optional Header Size'] = self.hex_to_decimal(data['SizeOfOptionalHeader'])
            self.EXECUTABLE_FEATURES['IMAGE_FILE_RELOCS_STRIPPED'] = data['IMAGE_FILE_RELOCS_STRIPPED']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_EXECUTABLE_IMAGE'] = data['IMAGE_FILE_EXECUTABLE_IMAGE']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_LINE_NUMS_STRIPPED'] = data['IMAGE_FILE_LINE_NUMS_STRIPPED']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_LOCAL_SYMS_STRIPPED'] = data['IMAGE_FILE_LOCAL_SYMS_STRIPPED']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_RELOCS_STRIPPED'] = data['IMAGE_FILE_RELOCS_STRIPPED']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_AGGRESSIVE_WS_TRIM'] = data['IMAGE_FILE_AGGRESSIVE_WS_TRIM']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_BYTES_REVERSED_LO'] = data['IMAGE_FILE_BYTES_REVERSED_LO']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_32BIT_MACHINE'] = data['IMAGE_FILE_32BIT_MACHINE']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_DEBUG_STRIPPED'] = data['IMAGE_FILE_DEBUG_STRIPPED']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP'] = data['IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_SYSTEM'] = data['IMAGE_FILE_SYSTEM']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_DLL'] = data['IMAGE_FILE_DLL']
            self.EXECUTABLE_FEATURES['IMAGE_FILE_UP_SYSTEM_ONLY'] = data['IMAGE_FILE_UP_SYSTEM_ONLY']
            self.EXECUTABLE_FEATURES['Contents applicable to any machine type'] = \
                data['The contents of this field are assumed to be applicable to any machine type']
            self.EXECUTABLE_FEATURES['Matsushita AM33'] = data['Matsushita AM33']
            self.EXECUTABLE_FEATURES['AMD64(K8)'] = data['AMD64(K8)']
            self.EXECUTABLE_FEATURES['ARM little endian'] = data['ARM little endian']
            self.EXECUTABLE_FEATURES['ARMv7 (or higher) Thumb mode only'] = data['ARMv7 (or higher) Thumb mode only']
            self.EXECUTABLE_FEATURES['ARMv8 in 64-bit mode'] = data['ARMv8 in 64-bit mode']
            self.EXECUTABLE_FEATURES['EFI byte code'] = data['EFI byte code']
            self.EXECUTABLE_FEATURES['Intel 386 or later processors and compatible processors'] = \
                data['Intel 386 or later processors and compatible processors']
            self.EXECUTABLE_FEATURES['Intel Itanium processor family'] = data['Intel Itanium processor family']
            self.EXECUTABLE_FEATURES['Mitsubishi M32R little endian'] = data['Mitsubishi M32R little endian']
            self.EXECUTABLE_FEATURES['MIPS16'] = data['MIPS16']
            self.EXECUTABLE_FEATURES['MIPS with FPU'] = data['MIPS with FPU']
            self.EXECUTABLE_FEATURES['MIPS16 with FPU'] = data['MIPS16 with FPU']
            self.EXECUTABLE_FEATURES['Power PC little endian'] = data['Power PC little endian']
            self.EXECUTABLE_FEATURES['Power PC with floating point support'] = data['Power PC with floating point support']
            self.EXECUTABLE_FEATURES['MIPS little endian'] = data['MIPS little endian']
            self.EXECUTABLE_FEATURES['Hitachi SH3'] = data['Hitachi SH3']
            self.EXECUTABLE_FEATURES['Hitachi SH3 DSP'] = data['Hitachi SH3 DSP']
            self.EXECUTABLE_FEATURES['Hitachi SH4'] = data['Hitachi SH4']
            self.EXECUTABLE_FEATURES['Hitachi SH5'] = data['Hitachi SH5']
            self.EXECUTABLE_FEATURES['ARM or Thumb (“interworking”)'] = data['ARM or Thumb (“interworking”)']
            self.EXECUTABLE_FEATURES['MIPS little-endian WCE v2'] = data['MIPS little-endian WCE v2']
            self.EXECUTABLE_FEATURES['Recently Compiled'] = data['Recently Compiled']

            if data['Magic'] == "0x10b":
                self.EXECUTABLE_FEATURES['64 Bit PE Image'] = 1
                self.EXECUTABLE_FEATURES['ROM Image'] = 0
                self.EXECUTABLE_FEATURES['32 Bit PE Image'] = 0
            elif data['Magic'] == "0x107":
                self.EXECUTABLE_FEATURES['ROM Image'] = 1
                self.EXECUTABLE_FEATURES['64 Bit PE Image'] = 0
                self.EXECUTABLE_FEATURES['32 Bit PE Image'] = 0

            elif data['Magic'] == "0x20b":
                self.EXECUTABLE_FEATURES['32 Bit PE Image'] = 1
                self.EXECUTABLE_FEATURES['ROM Image'] = 0
                self.EXECUTABLE_FEATURES['64 Bit PE Image'] = 0

            self.EXECUTABLE_FEATURES['MajorLinkerVersion'] = self.hex_to_decimal(data['MajorLinkerVersion'])
            self.EXECUTABLE_FEATURES['MinorLinkerVersion'] = self.hex_to_decimal(data['MinorLinkerVersion'])
            self.EXECUTABLE_FEATURES['SizeOfCode'] = self.hex_to_decimal(data['SizeOfCode'])
            self.EXECUTABLE_FEATURES['SizeOfInitializedData'] = self.hex_to_decimal(data['SizeOfInitializedData'])
            self.EXECUTABLE_FEATURES['SizeOfUninitializedData'] = self.hex_to_decimal(data['SizeOfUninitializedData'])
            self.EXECUTABLE_FEATURES['MajorOperatingSystemVersion'] = \
                self.hex_to_decimal(data['MajorOperatingSystemVersion'])
            self.EXECUTABLE_FEATURES['MinorOperatingSystemVersion'] = self.hex_to_decimal(data['MinorOperatingSystemVersion'])
            self.EXECUTABLE_FEATURES['MajorImageVersion'] = self.hex_to_decimal(data['MajorImageVersion'])
            self.EXECUTABLE_FEATURES['MinorImageVersion'] = self.hex_to_decimal(data['MinorImageVersion'])
            self.EXECUTABLE_FEATURES['MajorSubsystemVersion'] = self.hex_to_decimal(data['MajorSubsystemVersion'])
            self.EXECUTABLE_FEATURES['MinorSubsystemVersion'] = self.hex_to_decimal(data['MinorSubsystemVersion'])
            self.EXECUTABLE_FEATURES['SizeOfImage'] = self.hex_to_decimal(data['SizeOfImage'])
            self.EXECUTABLE_FEATURES['SizeOfHeaders'] = self.hex_to_decimal(data['SizeOfHeaders'])
            self.EXECUTABLE_FEATURES['SizeOfStackReserve'] = self.hex_to_decimal(data['SizeOfStackReserve'])
            self.EXECUTABLE_FEATURES['SizeOfStackCommit'] = self.hex_to_decimal(data['SizeOfStackCommit'])
            self.EXECUTABLE_FEATURES['SizeOfHeapReserve'] = self.hex_to_decimal(data['SizeOfHeapReserve'])
            self.EXECUTABLE_FEATURES['SizeOfHeapCommit'] = self.hex_to_decimal(data['SizeOfHeapCommit'])
            self.EXECUTABLE_FEATURES['NumberOfRvaAndSizes'] = self.hex_to_decimal(data['NumberOfRvaAndSizes'])
            self.EXECUTABLE_FEATURES['IMAGE_SUBSYSTEM_UNKNOWN'] = data['IMAGE_SUBSYSTEM_UNKNOWN']
            self.EXECUTABLE_FEATURES['IMAGE_SUBSYSTEM_NATIVE'] = data['IMAGE_SUBSYSTEM_NATIVE']
            self.EXECUTABLE_FEATURES['IMAGE_SUBSYSTEM_WINDOWS_GUI'] = data['IMAGE_SUBSYSTEM_WINDOWS_GUI']
            self.EXECUTABLE_FEATURES['IMAGE_SUBSYSTEM_WINDOWS_CUI'] = data['IMAGE_SUBSYSTEM_WINDOWS_CUI']
            self.EXECUTABLE_FEATURES['IMAGE_SUBSYSTEM_POSIX_CUI'] = data['IMAGE_SUBSYSTEM_POSIX_CUI']
            self.EXECUTABLE_FEATURES['IMAGE_SUBSYSTEM_WINDOWS_CE_GUI'] = data['IMAGE_SUBSYSTEM_WINDOWS_CE_GUI']
            self.EXECUTABLE_FEATURES['IMAGE_SUBSYSTEM_EFI_APPLICATION'] = data['IMAGE_SUBSYSTEM_EFI_APPLICATION']
            self.EXECUTABLE_FEATURES['IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER'] =data['IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER']
            self.EXECUTABLE_FEATURES['IMAGE_SUBSYSTEM_EFI_ROM'] = data['IMAGE_SUBSYSTEM_EFI_ROM']
            self.EXECUTABLE_FEATURES['IMAGE_SUBSYSTEM_XBOX'] = data['IMAGE_SUBSYSTEM_XBOX']
            self.EXECUTABLE_FEATURES['IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE'] = data['IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE']
            self.EXECUTABLE_FEATURES['IMAGE_DLL_CHARACTERISTICS_NX_COMPAT'] = data['IMAGE_DLL_CHARACTERISTICS_NX_COMPAT']
            self.EXECUTABLE_FEATURES['IMAGE_DLLCHARACTERISTICS_NO_ISOLATION'] = data['IMAGE_DLLCHARACTERISTICS_NO_ISOLATION']
            self.EXECUTABLE_FEATURES['IMAGE_DLLCHARACTERISTICS_NO_SEH'] = data['IMAGE_DLLCHARACTERISTICS_NO_SEH']
            self.EXECUTABLE_FEATURES['IMAGE_DLLCHARACTERISTICS_NO_BIND'] = data['IMAGE_DLLCHARACTERISTICS_NO_BIND']
            self.EXECUTABLE_FEATURES['IMAGE_DLLCHARACTERISTICS_WDM_DRIVER'] = data['IMAGE_DLLCHARACTERISTICS_WDM_DRIVER']
            self.EXECUTABLE_FEATURES['IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE'] = data['IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE']
            self.EXECUTABLE_FEATURES['size of Export Directory'] = self.hex_to_decimal(data['size of Export Directory'])
            self.EXECUTABLE_FEATURES['size of Import Directory'] = self.hex_to_decimal(data['size of Import Directory'])
            self.EXECUTABLE_FEATURES['size of Resource Directory'] = self.hex_to_decimal(data['size of Resource Directory'])
            self.EXECUTABLE_FEATURES['size of Exception Directory'] = self.hex_to_decimal(data['size of Exception Directory'])
            self.EXECUTABLE_FEATURES['size of Security Directory'] = self.hex_to_decimal(data['size of Security Directory'])
            self.EXECUTABLE_FEATURES['size of Base Relocation Directory'] = self.hex_to_decimal(data['size of Base Relocation Directory'])
            self.EXECUTABLE_FEATURES['size of Debug Directory'] = self.hex_to_decimal(data['size of Debug Directory'])
            self.EXECUTABLE_FEATURES['size of Bound Import Directory'] = self.hex_to_decimal(data['size of Bound Import Directory'])
            self.EXECUTABLE_FEATURES['size of Load Configuration Directory'] = self.hex_to_decimal(data['size of Load Configuration Directory'])
            self.EXECUTABLE_FEATURES['size of Bound Import Directory'] = self.hex_to_decimal(data['size of Bound Import Directory'])
            self.EXECUTABLE_FEATURES['total size of all Import Address Tables'] = self.hex_to_decimal(data['total size of all Import Address Tables'])
            self.EXECUTABLE_FEATURES['Suspicious File'] = data['Suspicious File']
            self.EXECUTABLE_FEATURES['File Entropy'] = data['File Entropy']
            self.EXECUTABLE_FEATURES['Uncommon Sections'] = data['Uncommon Section Names Count']
            self.EXECUTABLE_FEATURES['Packed Sections'] = data['Packed Sections Detected']
            self.EXECUTABLE_FEATURES['Suspicious Writeable Sections'] = data["Suspicious Writeable Sections"]


            for en in data['Entropy']:
                if isinstance(en, str):
                    pass
                else:
                    if en > 6.7:
                        self.EXECUTABLE_FEATURES['Suspicious Section Detected'] = 1
                        break
                    else:
                        self.EXECUTABLE_FEATURES['Suspicious Section Detected'] = 0

            if self.dataset_type == "b":
                # dependent variable
                self.EXECUTABLE_FEATURES['Malware'] = 0
            elif self.dataset_type == "m":
                self.EXECUTABLE_FEATURES['Malware'] = 1
            else:
                print("How did you get to this error print?")

            self.dataframes.append(self.EXECUTABLE_FEATURES)

            # RESETS the dict to a new one, allowing the process to follow for the next executable

            self.EXECUTABLE_FEATURES = {}

        # Creation of master datadrame file with all exes in the one pandas dataframe object now
        self.df = pd.DataFrame(self.dataframes)

        # if user decides to choose csv, then apply a csv format and output the files to users desired output location
        if self.format_type == "csv" and self.dataset_type == "b":
            self.df.to_csv(self.output_path + r"/benign_executables_dataset.csv", index=True, header=True)
        elif self.format_type == "csv" and self.dataset_type == "m":
            self.df.to_csv(self.output_path + r"/malware_executables_dataset.csv", index=True, header=True)
        elif self.format_type == "excel" and self.dataset_type == "b":
            self.df.to_excel(self.output_path + r"/benign_executables_dataset.xlsx", index=True, header=True)
        elif self.format_type == "csv" and self.dataset_type == "m":
            self.df.to_excel(self.output_path + r"/malware_executables_dataset.xlsx", index=True, header=True)
        else:
            print("Something went wrong.")

