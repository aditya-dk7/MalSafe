import hashlib
import os
import pefile
import struct
import subprocess
import sys
import time


FILE_GNUWIN32 = True
__VERSION__ = '1.4'
FIELD_SIZE = 16
FILE_SUFFIX = '.info.txt'
YARA_SIG_FOLDER = ''
SCRIPT_PATH = ''
EXIF_PATH = ''
def check_overlay(data):
    """
    Performs cursory checks against overlay data to determine if it's of a known type.
    Currently just digital signatures

    Arguments:
        data: overlay data
    """
    if not len(data):
        return ''
    try:
        if len(data) > 256:
            #Check for Authenticode structure
            test_size = struct.unpack('l', data[0:4])[0]
            if test_size == len(data) and test_size > 512:
                hdr1 = struct.unpack('l', data[4:8])[0]
                if hdr1 == 0x00020200:
                    return '(Authenticode Signature)'
    except:
        pass
    return ''
def CheckFile(fileName):
    """
    Main routine to scan a file

    Arguments:
        fileName: path to file name
    """
    results = ''
    data = open(fileName, 'rb').read()
    if not len(data):
        return None
    fname = fileName

    results += ('%-*s: %s\n' % (FIELD_SIZE, 'File Name', fname))
    results += ('%-*s: %s\n' % (FIELD_SIZE, 'File Size', '{:,}'.format(os.path.getsize(fileName))))
    
    results += ('%-*s: %s\n' % (FIELD_SIZE, 'MD5', hashlib.md5(data).hexdigest()))
    results += ('%-*s: %s\n' % (FIELD_SIZE, 'SHA1', hashlib.sha1(data).hexdigest()))
    results += ('%-*s: %s\n' % (FIELD_SIZE, 'SHA256', hashlib.sha256(data).hexdigest()))

    

    

    # Do executable scans
    try:
        pe = pefile.PE(fileName)#, fast_load=True)
    except pefile.PEFormatError:
        pe = None

    if pe:

        try:
            imphash = pe.get_imphash()
            results += ('%-*s: %s\n' % (FIELD_SIZE, 'Import Hash', imphash))
        except:
            imphash = ''

        

        try:
            time_output = '%s UTC' % time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp))
        except:
            time_output = 'Invalid Time'
        results += ('%-*s: %s\n' % (FIELD_SIZE, 'Compiled Time', time_output))


        section_hdr = 'PE Sections (%d)' % pe.FILE_HEADER.NumberOfSections
        section_hdr2 = '%-10s %-10s %s' % ('Name', 'Size', 'SHA256')
        results += ('%-*s: %s\n' % (FIELD_SIZE, section_hdr, section_hdr2))
        for section in pe.sections:
            section_name = section.Name.strip(b'\x00').decode('utf-8')
            results += ('%-*s %-10s %-10s %s\n' % (FIELD_SIZE + 1, ' ', section_name,
                                                     '{:,}'.format(section.SizeOfRawData),
                                                     section.get_hash_sha256()))

        EoD = pe.sections[-1]
        end_of_PE = (EoD.PointerToRawData + EoD.SizeOfRawData)
        overlay_len = len(data) - end_of_PE
        if overlay_len:
            overlay = data[end_of_PE:len(data)]
            overlay_type = check_overlay(overlay)
            results += ('%-*s+ %-10s %-10s %s %s\n' % (FIELD_SIZE, ' ',
                                                        hex(end_of_PE), '{:,}'.format((len(overlay))),
                                                        hashlib.md5(overlay).hexdigest(),
                                                        overlay_type))

        if pe.is_dll():
            #DLL, get original compiled name and export routines
            #Load in export directory
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])

            try:
                orig_name = pe.get_string_at_rva(pe.DIRECTORY_ENTRY_EXPORT.struct.Name)
                results += ('%-*s: %s\n' % (FIELD_SIZE, 'Original DLL', orig_name))

                section_hdr = 'DLL Exports (%d)' % len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
                section_hdr2 = '%-8s %s' % ('Ordinal', 'Name')
                results += ('%-*s: %s\n' % (FIELD_SIZE, section_hdr, section_hdr2))

                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                  results += ('%-*s %-8s %s\n' % (FIELD_SIZE + 1, ' ', exp.ordinal, exp.name))
            
            except AttributeError: # For some reason, some pefile libs don't have this? Mine doesn't anymore
                pass

#        if pe.is_driver():
#            #TODO
#            raise

    
    

    if os.path.isfile(EXIF_PATH):
        exifdata = subprocess.check_output([EXIF_PATH, fileName])
        results += ('%s' % exifdata)

    return results

print(CheckFile(sys.argv[1]))
