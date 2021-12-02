import pefile
def extractAllPeinfo(file_path):
    pe = pefile.PE(file_path)
    result = {}
    result['Machine'] = pe.FILE_HEADER.Machine
    result['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    result['Characteristics'] = pe.FILE_HEADER.Characteristics
    result['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    result['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    result['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    result['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    result['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    result['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    result['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        result['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        result['BaseOfData'] = 0
    result['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    result['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    result['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    result['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    result['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    result['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    result['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    result['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    result['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    result['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    result['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    result['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    result['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    result['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    result['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    result['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    result['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    result['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    result['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    result['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
    result['SectionsNb'] = len(pe.sections)
    '''
        The PE Sections have data whioch are known as entropy and Higher entropy can indicate packed data. 
        Usually, an entropy level of above 6.7 is considered a good 
    '''
    sectionEntropy = []
    sizeOfRawData = []
    virtualSize = []
    for sect in pe.sections:
        sectionEntropy.append(sect.get_entropy())
        sizeOfRawData.append(sect.SizeOfRawData)
        virtualSize.append(sect.Misc_VirtualSize)

    result['SectionsMeanEntropy'] = sum(sectionEntropy) / float(len(sectionEntropy))
    result['SectionsMinEntropy'] = min(sectionEntropy)
    result['SectionsMaxEntropy'] = max(sectionEntropy)
    result['SectionsMeanRawsize'] = sum(sizeOfRawData) / float(len(sizeOfRawData))
    result['SectionsMinRawsize'] = min(sizeOfRawData)
    result['SectionsMaxRawsize'] = max(sizeOfRawData)
    result['SectionsMeanVirtualsize'] = sum(virtualSize) / float(len(virtualSize))
    result['SectionsMinVirtualsize'] = min(virtualSize)
    result['SectionMaxVirtualsize'] = max(virtualSize)
    try:
        result['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        result['ImportsNb'] = len(imports)
        result['ImportsNbOrdinal'] = len(list(filter(lambda x: x.name is None, imports)))
    except AttributeError:
        result['ImportsNbDLL'] = 0
        result['ImportsNb'] = 0
        result['ImportsNbOrdinal'] = 0
    try:
        result['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        result['ExportNb'] = 0
    
    try:
        result['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        result['LoadConfigurationSize'] = 0
    
    

pe = pefile.PE('exe/NonMalicious/JRuler.exe')


