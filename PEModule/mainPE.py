import pefile
import array
import math

def getEntropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0] * 256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy


def getResources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                   resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = getEntropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources


def getVersionInfo(pe):
    #Return version infos
    result = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    result[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                result[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        result['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        result['os'] = pe.VS_FIXEDFILEINFO.FileOS
        result['type'] = pe.VS_FIXEDFILEINFO.FileType
        result['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        result['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        result['signature'] = pe.VS_FIXEDFILEINFO.Signature
        result['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return result




def extractAllPeinfo(file_path):
    try:
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

        resources = getResources(pe)
        result['ResourcesNb'] = len(resources)
        if len(resources) > 0:
            entropy = list(map(lambda x: x[0], resources))
            result['ResourcesMeanEntropy'] = sum(entropy) / float(len(entropy))
            result['ResourcesMinEntropy'] = min(entropy)
            result['ResourcesMaxEntropy'] = max(entropy)
            sizes = list(map(lambda x: x[1], resources))
            result['ResourcesMeanSize'] = sum(sizes) / float(len(sizes))
            result['ResourcesMinSize'] = min(sizes)
            result['ResourcesMaxSize'] = max(sizes)
        else:
            result['ResourcesNb'] = 0
            result['ResourcesMeanEntropy'] = 0
            result['ResourcesMinEntropy'] = 0
            result['ResourcesMaxEntropy'] = 0
            result['ResourcesMeanSize'] = 0
            result['ResourcesMinSize'] = 0
            result['ResourcesMaxSize'] = 0
        try:
            result['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        except AttributeError:
            result['LoadConfigurationSize'] = 0
        try:
            version_infos = getVersionInfo(pe)
            result['VersionInformationSize'] = len(version_infos.keys())
        except AttributeError:
            result['VersionInformationSize'] = 0
        
        return result
    except pefile.PEFormatError:
        return None
    



