# IDAPython XEX Loader 0.6 for IDA 7.0+ by emoose
# Based on work by the Xenia project, XEX2.bt by Anthony, xextool 0.1 by xor37h, x360_imports.idc by xorloser, xkelib...
# (currently only works on uncompressed XEXs, use "xextool -cu xexfile.xex" beforehand!)
# --
# Requires PyCrypto to be installed first
# "pip install pycrypto" should take care of that
# --
# This loader should support:
# - encrypted & decrypted XEXs (as long as they're uncompressed)
# - XEX2 (>=1888), XEX1 (>=1838), XEX% (>=1746), XEX- (>=1640) & XEX? (>=1529) formats
# - loading imports & exports from XEX headers ("XEX?" format stores imports in PE headers, which this doesn't read atm)
# --
# TODO:
# - read imports from PE headers if they exist
# - mark imports in IDA imports window (might be impossible in python - no import_module binding ...)
# - compression support (important for XEX1 and lower, since there's no decompressors for those)
# - relocations?
# - print more info to console (compression info, etc... should maybe print all structs to aid with RE?)
# - name/comment XEX resources?
# - find why IDA sometimes isn't marking strings & such inside data sections
# - test against more XEXs (need to check 1640 & 1746)

import io
import idc 
import idaapi
import ida_segment
import ida_bytes
import ida_loader
import ida_typeinf
import struct
import ctypes
import os
import x360_imports
from Crypto.Cipher import AES

_MAGIC_XEX32 = "XEX2" # >=1888
_MAGIC_XEX31 = "XEX1" # >=1838
_MAGIC_XEX25 = "XEX%" # >=1746
_MAGIC_XEX2D = "XEX-" # >=1640
_MAGIC_XEX3F = "XEX?" # >=1529

_FORMAT_XEX32 = "Xbox360 XEX2 File"
_FORMAT_XEX31 = "Xbox360 XEX1 File (>=1838)"
_FORMAT_XEX25 = "Xbox360 XEX% File (>=1746)"
_FORMAT_XEX2D = "Xbox360 XEX- File (>=1640)"
_FORMAT_XEX3F = "Xbox360 XEX? File (>=1529)"

char_t = ctypes.c_char
uint8_t  = ctypes.c_byte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint

retail_key = b'\x20\xB1\x85\xA5\x9D\x28\xFD\xC3\x40\x58\x3F\xBB\x08\x96\xBF\x91'
devkit_key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
unused_key = b'\xA2\x6C\x10\xF7\x1F\xD9\x35\xE9\x8B\x99\x92\x2C\xE9\x32\x15\x72' # aka "XEX1 key", never seen it used, we'll try using it as last resort though

xex_keys = [retail_key, devkit_key, unused_key]
xex_key_names = ["retail", "devkit", "xex1"]

# Globals shared between load_file, pe_load, etc..
image_key = b''
session_key = b''
directory_entry_headers = {}
directory_entries = {}
export_table_va = 0
base_address = 0
entry_point = 0

# Debug helpers to let us print(structure)
def StructAsString(self):
  return "{}: {{{}}}".format(self.__class__.__name__,
                             ", ".join(["{}: {}".format(field[0],
                                                        getattr(self,
                                                                field[0]))
                                        for field in self._fields_]))

ctypes.BigEndianStructure.__str__ = StructAsString

class MyStructure(ctypes.Structure):
  pass

MyStructure.__str__ = StructAsString

# PE structs & enums
class ImageDOSHeader(MyStructure):
  _fields_ = [
    ("MZSignature", uint16_t),
    ("UsedBytesInTheLastPage", uint16_t),
    ("FileSizeInPages", uint16_t),
    ("NumberOfRelocationItems", uint16_t),
    ("HeaderSizeInParagraphs", uint16_t),
    ("MinimumExtraParagraphs", uint16_t),
    ("MaximumExtraParagraphs", uint16_t),
    ("InitialRelativeSS", uint16_t),
    ("InitialSP", uint16_t),
    ("Checksum", uint16_t),
    ("InitialIP", uint16_t),
    ("InitialRelativeCS", uint16_t),
    ("AddressOfRelocationTable", uint16_t),
    ("OverlayNumber", uint16_t),
    ("Reserved", uint16_t * 4),
    ("OEMid", uint16_t),
    ("OEMinfo", uint16_t),
    ("Reserved2", uint16_t * 10),
    ("AddressOfNewExeHeader", uint32_t),
  ]

class ImageFileHeader(MyStructure):
  _fields_ = [
    ("Machine", uint16_t),
    ("NumberOfSections", uint16_t),
    ("TimeDateStamp", uint32_t),
    ("PointerToSymbolTable", uint32_t),
    ("NumberOfSymbols", uint32_t),
    ("SizeOfOptionalHeader", uint16_t),
    ("Characteristics", uint16_t),
  ]

class ImageOptionalHeader32(MyStructure):
  _fields_ = [
    ("Magic", uint16_t),
    ("MajorLinkerVersion", uint8_t),
    ("MinorLinkerVersion", uint8_t),
    ("SizeOfCode", uint32_t),
    ("SizeOfInitializedData", uint32_t),
    ("SizeOfUninitializedData", uint32_t),
    ("AddressOfEntryPoint", uint32_t),
    ("BaseOfCode", uint32_t),
    ("BaseOfData", uint32_t),
    ("ImageBase", uint32_t),
    ("SectionAlignment", uint32_t),
    ("FileAlignment", uint32_t),
    ("MajorOperatingSystemVersion", uint16_t),
    ("MinorOperatingSystemVersion", uint16_t),
    ("MajorImageVersion", uint16_t),
    ("MinorImageVersion", uint16_t),
    ("MajorSubsystemVersion", uint16_t),
    ("MinorSubsystemVersion", uint16_t),
    ("Win32VersionValue", uint32_t),
    ("SizeOfImage", uint32_t),
    ("SizeOfHeaders", uint32_t),
    ("CheckSum", uint32_t),
    ("Subsystem", uint16_t),
    ("DllCharacteristics", uint16_t),
    ("SizeOfStackReserve", uint32_t),
    ("SizeOfStackCommit", uint32_t),
    ("SizeOfHeapReserve", uint32_t),
    ("SizeOfHeapCommit", uint32_t),
    ("LoaderFlags", uint32_t),
    ("NumberOfRvaAndSizes", uint32_t),
  ]

class ImageNTHeaders(MyStructure):
  _fields_ = [
    ("Signature", uint32_t),
    ("FileHeader", ImageFileHeader),
    ("OptionalHeader", ImageOptionalHeader32),
  ]

class ImageSectionHeader(MyStructure):
  _fields_ = [
    ("Name", char_t * 8),
    ("VirtualSize", uint32_t), # also PhysicalAddress
    ("VirtualAddress", uint32_t),
    ("SizeOfRawData", uint32_t),
    ("PointerToRawData", uint32_t),
    ("PointerToRelocations", uint32_t),
    ("PointerToLinenumbers", uint32_t),
    ("NumberOfRelocations", uint16_t),
    ("NumberOfLineNumbers", uint16_t),
    ("Characteristics", uint32_t),
  ]

# Characteristics flags
IMAGE_SCN_CNT_CODE = 0x20
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

def pe_add_section(section):
  global base_address

  # Segment permissions
  seg_perms = 0
  if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
    seg_perms |= ida_segment.SEGPERM_EXEC
  if section.Characteristics & IMAGE_SCN_MEM_READ:
    seg_perms |= ida_segment.SEGPERM_READ
  if section.Characteristics & IMAGE_SCN_MEM_WRITE:
    seg_perms |= ida_segment.SEGPERM_WRITE

  # Segment type
  seg_class = "DATA"
  if section.Characteristics & IMAGE_SCN_CNT_CODE:
    seg_class = "CODE"

  seg_addr = base_address + section.VirtualAddress
  idaapi.add_segm(0, seg_addr, seg_addr + section.VirtualSize, section.Name, seg_class)
  idc.set_segm_alignment(seg_addr, idc.saRelPara)
  idc.set_segm_attr(seg_addr, idc.SEGATTR_PERM, seg_perms)
  idc.set_default_sreg_value(seg_addr, "DS", 0) # how is DS meant to be set? prolly don't matter but still
  idc.set_default_sreg_value(seg_addr, "VLE", 0)

def pe_load(li):
  global directory_entry_headers
  global base_address
  global entry_point
  global xex_magic

  # Get size of the PE
  li.seek(0, 2) # seek to end
  pe_size = li.tell()

  # Read DOS & NT headers
  li.seek(0)
  dos_header = read_struct(li, ImageDOSHeader)
  if dos_header.MZSignature != 0x5A4D:
    return 0

  li.seek(dos_header.AddressOfNewExeHeader)
  nt_header = read_struct(li, ImageNTHeaders)

  # Skip past PE data directories (for now? will we ever need them?)
  li.seek(nt_header.OptionalHeader.NumberOfRvaAndSizes * 8, os.SEEK_CUR)

  # If no EP passed we'll use EP from the optionalheader
  if entry_point <= 0:
    entry_point = base_address + nt_header.OptionalHeader.AddressOfEntryPoint

  # Read in & map our section headers
  # (todo: fix loading more sections than needed, seems sections like .reloc shouldn't be loaded in?)
  section_headers = []
  for i in range(0, nt_header.FileHeader.NumberOfSections):
    section_headers.append(read_struct(li, ImageSectionHeader))

  for section in section_headers:
    sec_addr = section.VirtualAddress if xex_magic != _MAGIC_XEX3F else section.PointerToRawData
    sec_size = min(section.VirtualSize, section.SizeOfRawData)

    if sec_addr + sec_size > pe_size:
      sec_size = pe_size - sec_addr

    # Load em if you got em
    if sec_size <= 0:
      continue

    pe_add_section(section)

    # Load data into IDB
    li.seek(sec_addr)
    ida_loader.mem2base(li.read(sec_size), base_address + section.VirtualAddress)

  # Name the EP if we have one
  if entry_point > 0:
    idaapi.add_entry(entry_point, entry_point, "start", 1)

  # PE load complete :)
  return 1

# todo: define imports in IDA's imports window (how though?)
def xex_load_imports(li):
  global directory_entry_headers

  li.seek(directory_entry_headers[XEX_HEADER_IMPORTS])
  import_desc = read_struct(li, XEXImportDescriptor)

  # seperate the library names from the name table
  import_libnames = []
  cur_lib = ""
  for i in range(0, import_desc.NameTableSize):
    name_char = li.read(1)

    if name_char == '\0' or name_char == '\xCD':
      if cur_lib != "":
        import_libnames.append(cur_lib)
        cur_lib = ""
    else:
      cur_lib += name_char

  # read in each import library
  import_libs = []
  variables = {}
  for i in range(0, import_desc.ModuleCount):
    table_addr = li.tell()
    table_header = read_struct(li, XEXImportTable)
    libname = import_libnames[table_header.ModuleIndex]
    import_table = []
    for i in range(0, table_header.ImportCount):
      record_addr = read_dwordBE(li)

      record_value = ida_bytes.get_dword(record_addr)
      record_type = (record_value & 0xFF000000) >> 24;
      ordinal = record_value & 0xFFFF

      import_name = x360_imports.DoNameGen(libname, 0, ordinal)
      if record_type == 0:
        # variable
        idc.create_data(record_addr, idc.FF_WORD, 2, idc.BADADDR)
        idc.create_data(record_addr + 2, idc.FF_WORD, 2, idc.BADADDR)
        idc.make_array(record_addr, 2)
        idc.set_name(record_addr, "__imp__" + import_name)
        variables[ordinal] = record_addr

      elif record_type == 1:
        # thunk
        # have to rewrite code to set r3 & r4 like xorlosers loader does
        # r3 = module index afaik
        # r4 = ordinal
        # important to note that basefiles extracted via xextool have this rewrite done already, but raw basefile from XEX doesn't!
        # todo: find out how to add to imports window like xorloser loader...

        ida_bytes.put_dword(record_addr + 0, 0x38600000 | table_header.ModuleIndex)
        ida_bytes.put_dword(record_addr + 4, 0x38800000 | ordinal)
        idc.add_func(record_addr, record_addr + 0x10)
        idc.set_name(record_addr, import_name)

        # add comment to thunk like xorloser's loader
        idc.set_cmt(record_addr + 4, "%s :: %s" % (libname.rsplit('.', 1)[0], import_name), 1)

        # this should mark the func as a library function, but it doesn't do anything for some reason
        # tried a bunch of things like idaapi.autoWait() before running it, just crashes IDA with internal errors...
        idc.set_func_flags(record_addr, idc.get_func_flags(record_addr) | idc.FUNC_LIB)

        # thunk means it's not a variable, so remove from variables dict
        if ordinal in variables:
          variables.pop(ordinal)

      else:
        print("[+] %s import %d (%s) (@ 0x%X) unknown type %d!" % (libname, ordinal, import_name, record_addr, record_type))

    # remove "__imp__" part from variable import names
    for ordinal in variables:
      import_name = x360_imports.DoNameGen(libname, 0, ordinal)
      idc.set_name(variables[ordinal], import_name)

    # Seek to end of this import table
    li.seek(table_addr + table_header.TableSize)

  return

def xex_load_exports(li):
  global export_table_va

  export_table = HvImageExportTable()
  slen = ctypes.sizeof(export_table)
  bytes = ida_bytes.get_bytes(export_table_va, slen)
  fit = min(len(bytes), slen)
  ctypes.memmove(ctypes.addressof(export_table), bytes, fit)

  if export_table.Magic[0] != 0x48000000 or export_table.Magic[1] != 0x00485645 or export_table.Magic[2] != 0x48000000:
    print("[+] Export table magic is invalid! (0x%X 0x%X 0x%X)" % (export_table.Magic[0], export_table.Magic[1], export_table.Magic[2]))
    return 0

  print("[+] Loading module exports...")
  print(export_table)

  ordinal_addrs_va = export_table_va + slen
  for i in range(0, export_table.Count):
    func_ord = export_table.Base + i
    func_va = ida_bytes.get_dword(ordinal_addrs_va + (i * 4))
    if func_va == 0:
      continue

    func_va = func_va + (export_table.ImageBaseAddress << 16)
    func_name = x360_imports.DoNameGen(idc.get_root_filename(), 0, func_ord)

    # Add to exports list & mark as func if inside a code section
    func_segmclass = ida_segment.get_segm_class(ida_segment.getseg(func_va))
    idc.add_entry(func_ord, func_va, func_name, 1 if func_segmclass == "CODE" else 0)

    if func_segmclass == "CODE":
      idc.add_func(func_va)

  return 1

# XEX structs & enums
XEX_EXPORT_MAGIC_0 = 0x48000000
XEX_EXPORT_MAGIC_1 = 0x00485645
XEX_EXPORT_MAGIC_2 = 0x48000000

class HvImageExportTable(ctypes.BigEndianStructure):
  _fields_ = [
    ("Magic", uint32_t * 3),
    ("ModuleNumber", uint32_t * 2),
    ("Version", uint32_t * 3),
    ("ImageBaseAddress", uint32_t),
    ("Count", uint32_t),
    ("Base", uint32_t),
  ]

class XEXImportDescriptor(ctypes.BigEndianStructure):
  _fields_ = [
    ("Size", uint32_t),
    ("NameTableSize", uint32_t),
    ("ModuleCount", uint32_t),
  ]

class XEXImportTable(ctypes.BigEndianStructure):
  _fields_ = [
    ("TableSize", uint32_t),
    ("NextImportDigest", uint8_t * 0x14),
    ("ModuleNumber", uint32_t),
    ("Version", uint32_t * 2),
    ("Unused", uint8_t),
    ("ModuleIndex", uint8_t),
    ("ImportCount", uint16_t),
  ]

class ImageXEXHeader(ctypes.BigEndianStructure):
  _fields_ = [
    ("Magic", uint32_t),
    ("ModuleFlags", uint32_t),
    ("SizeOfHeaders", uint32_t),
    ("SizeOfDiscardableHeaders", uint32_t),
    ("SecurityInfo", uint32_t),
    ("HeaderDirectoryEntryCount", uint32_t),
  ]

# ImageXEXHeader for "XEX?" format, which doesn't contain a SecurityInfo struct (>=1529)
class ImageXEXHeader_3F(ctypes.BigEndianStructure):
  _fields_ = [
    ("Magic", uint32_t),
    ("ModuleFlags", uint32_t),
    ("SizeOfHeaders", uint32_t),
    ("SizeOfDiscardableHeaders", uint32_t),
    ("LoadAddress", uint32_t),
    ("Unknown14", uint32_t),
    ("HeaderDirectoryEntryCount", uint32_t),
  ]

# ModuleFlags
XEX_MODULE_FLAG_TITLE_PROCESS = 0x0001
XEX_MODULE_FLAG_TITLE_IMPORTS = 0x0002
XEX_MODULE_FLAG_DEBUGGER = 0x0004
XEX_MODULE_FLAG_DLL = 0x0008
XEX_MODULE_FLAG_PATCH = 0x0010
XEX_MODULE_FLAG_PATCH_FULL = 0x0020
XEX_MODULE_FLAG_PATCH_DELTA = 0x0040
XEX_MODULE_FLAG_USER_MODE = 0x0080
XEX_MODULE_FLAG_BOUND_PATH = 0x40000000
XEX_MODULE_FLAG_SILENT_LOAD = 0x80000000

XEX_MODULE_TYPE_TITLE = (XEX_MODULE_FLAG_TITLE_PROCESS)
XEX_MODULE_TYPE_TITLE_DLL = (XEX_MODULE_FLAG_TITLE_PROCESS | XEX_MODULE_FLAG_DLL)
XEX_MODULE_TYPE_SYSTEM_APP = (XEX_MODULE_FLAG_DLL)
XEX_MODULE_TYPE_SYSTEM_DLL = (XEX_MODULE_FLAG_DLL | XEX_MODULE_FLAG_TITLE_IMPORTS)

class ImageXEXDirectoryEntry(ctypes.BigEndianStructure):
  _fields_ = [
    ("Key", uint32_t),
    ("Value", uint32_t),
  ]

def XEX_HEADER_FIXED_SIZE(key, size):
  return ((key) << 8) | ((size) >> 2)

def XEX_HEADER_ULONG(key):
  return ((key) << 8) | 1

def XEX_HEADER_FLAG(key):
  return (key) << 8

def XEX_HEADER_SIZEDSTRUCT(key):
  return ((key) << 8) | 0xFF

def XEX_HEADER_STRING_FIELD(key):
  return XEX_HEADER_SIZEDSTRUCT(key)

def XEX_HEADER_PRIVILEGE(priv):
  return XEX_HEADER_FLAG(0x0300) + ((priv&~0x1f)<<3)

XEX_NUMBER_GAME_RATING_SYSTEMS = 64
XEX_LAN_KEY_SIZE = 16

# ImageXEXDirectoryEntry Key values:
XEX_HEADER_SECTION_TABLE = XEX_HEADER_SIZEDSTRUCT(0x0002)
XEX_FILE_DATA_DESCRIPTOR_HEADER = XEX_HEADER_SIZEDSTRUCT(0x0003)
XEX_PATCH_FILE_BASE_REFERENCE = XEX_HEADER_FIXED_SIZE(0x0004, 0x14)
XEX_HEADER_DELTA_PATCH_DESCRIPTOR = XEX_HEADER_SIZEDSTRUCT(5)
XEX_HEADER_KEY_VAULT_PRIVS = 0x000040FF # XEX_HEADER_STRUCT(0x0040, XEX_KEY_VAULT_PRIVILEGES)
XEX_HEADER_TIME_RANGE = 0x000041FF # XEX_HEADER_STRUCT(0x0041, XEX_SYSTEM_TIME_RANGE)
XEX_HEADER_CONSOLE_ID_TABLE = XEX_HEADER_SIZEDSTRUCT(0x0042) # lists disallowed console IDs
XEX_HEADER_BOUND_PATH = XEX_HEADER_STRING_FIELD(0x0080)
XEX_HEADER_DEVICE_ID = XEX_HEADER_FIXED_SIZE(0x0081, 0x14)
XEX_HEADER_ORIGINAL_BASE_ADDRESS = XEX_HEADER_ULONG(0x0100)
XEX_HEADER_ENTRY_POINT = XEX_HEADER_FLAG(0x0101)
XEX_HEADER_PE_BASE = XEX_HEADER_ULONG(0x0102)
XEX_HEADER_IMPORTS = XEX_HEADER_SIZEDSTRUCT(0x0103)
XEX_HEADER_IMPORTS_PREXEX2 = 0x000102FF
XEX_HEADER_PE_EXPORTS = 0x00E10402 # XEX_HEADER_STRUCT(0xE104, IMAGE_DATA_DIRECTORY)
XEX_HEADER_PE_EXPORTS_PREXEX2 = 0x00008102 # used in some pre-XEX2 file
XEX_HEADER_VITAL_STATS = 0x00018002 # XEX_HEADER_STRUCT(0x0180, XEX_VITAL_STATS)
XEX_HEADER_CALLCAP_IMPORTS = 0x00018102 # XEX_HEADER_STRUCT(0x0181, XEX_CALLCAP_IMPORTS)
XEX_HEADER_FASTCAP_ENABLED = XEX_HEADER_FLAG(0x0182)
XEX_HEADER_PE_MODULE_NAME = XEX_HEADER_STRING_FIELD(0x0183)
XEX_HEADER_BUILD_VERSIONS = XEX_HEADER_SIZEDSTRUCT(0x0200)
XEX_HEADER_TLS_DATA = 0x00020104 # XEX_HEADER_STRUCT(0x201, XEX_TLS_DATA)
XEX_HEADER_STACK_SIZE = XEX_HEADER_FLAG(0x0202)
XEX_HEADER_FSCACHE_SIZE = XEX_HEADER_ULONG(0x203)
XEX_HEADER_XAPI_HEAP_SIZE = XEX_HEADER_ULONG(0x0204)
XEX_HEADER_PAGE_HEAP_SIZE_FLAGS = 0x00028002 # XEX_HEADER_STRUCT(0x0280, XEX_PAGE_HEAP_OPTIONS)
XEX_HEADER_EXECUTION_ID = 0x00040006 # XEX_HEADER_STRUCT(0x400, XEX_EXECUTION_ID)
XEX_HEADER_SERVICE_ID_LIST = XEX_HEADER_SIZEDSTRUCT(0x401)
XEX_HEADER_WORKSPACE_SIZE = XEX_HEADER_ULONG(0x0402)
XEX_HEADER_GAME_RATINGS = XEX_HEADER_FIXED_SIZE(0x403, XEX_NUMBER_GAME_RATING_SYSTEMS)
XEX_HEADER_LAN_KEY = XEX_HEADER_FIXED_SIZE(0x404, XEX_LAN_KEY_SIZE)
XEX_HEADER_MSLOGO = XEX_HEADER_SIZEDSTRUCT(0x0405)
XEX_HEADER_MULTIDISK_MEDIA_IDS = XEX_HEADER_SIZEDSTRUCT(0x0406)
XEX_HEADER_ALTERNATE_TITLE_IDS = XEX_HEADER_SIZEDSTRUCT(0x0407)
XEX_HEADER_ADDITIONAL_TITLE_MEM = XEX_HEADER_ULONG(0x0408)

class XEX2HVImageInfo(ctypes.BigEndianStructure):
  _fields_ = [
    ("Signature", uint8_t * 0x100),
    ("InfoSize", uint32_t),
    ("ImageFlags", uint32_t), # todo:ImageFlags
    ("LoadAddress", uint32_t),
    ("ImageHash", uint8_t * 0x14),
    ("ImportTableCount", uint32_t),
    ("ImportDigest", uint8_t * 0x14),
    ("MediaID", uint8_t * 0x10),
    ("ImageKey", uint8_t * 0x10),
    ("ExportTableAddress", uint32_t),
    ("HeaderHash", uint8_t * 0x14),
    ("GameRegion", uint32_t), # todo:GameRegions
  ]

class XEX2SecurityInfo(ctypes.BigEndianStructure):
  _fields_ = [
    ("Size", uint32_t),
    ("ImageSize", uint32_t),
    ("ImageInfo", XEX2HVImageInfo),
    ("AllowedMediaTypes", uint32_t), # todo:AllowedMediaTypes
    ("PageDescriptorCount", uint32_t),
  ]

class XEX1HVImageInfo(ctypes.BigEndianStructure):
  _fields_ = [
    ("Signature", uint8_t * 0x100),
    ("ImageHash", uint8_t * 0x14),
    ("ImportDigest", uint8_t * 0x14),
    ("LoadAddress", uint32_t),
    ("ImageKey", uint8_t * 0x10),
    ("MediaID", uint8_t * 0x10),
    ("GameRegion", uint32_t), # todo:GameRegions
    ("ImageFlags", uint32_t), # todo:ImageFlags
    ("ExportTableAddress", uint32_t),
  ]

class XEX1SecurityInfo(ctypes.BigEndianStructure):
  _fields_ = [
    ("Size", uint32_t),
    ("ImageSize", uint32_t),
    ("ImageInfo", XEX1HVImageInfo),
    ("AllowedMediaTypes", uint32_t), # todo:AllowedMediaTypes
    ("PageDescriptorCount", uint32_t),
  ]

class XEX25HVImageInfo(ctypes.BigEndianStructure):
  _fields_ = [
    ("Signature", uint8_t * 0x100),
    ("ImageHash", uint8_t * 0x14),
    ("ImportDigest", uint8_t * 0x14),
    ("LoadAddress", uint32_t),
    ("ImageKey", uint8_t * 0x10),
    ("ImageFlags", uint32_t), # todo:ImageFlags
    ("ExportTableAddress", uint32_t),
  ]

class XEX25SecurityInfo(ctypes.BigEndianStructure):
  _fields_ = [
    ("Size", uint32_t),
    ("ImageSize", uint32_t),
    ("ImageInfo", XEX25HVImageInfo),
    ("AllowedMediaTypes", uint32_t), # todo:AllowedMediaTypes
    ("PageDescriptorCount", uint32_t),
  ]

class XEX2DHVImageInfo(ctypes.BigEndianStructure):
  _fields_ = [
    ("Signature", uint8_t * 0x100),
    ("ImageHash", uint8_t * 0x14),
    ("ImportDigest", uint8_t * 0x14),
    ("LoadAddress", uint32_t),
    ("ImageFlags", uint32_t), # todo:ImageFlags
    ("ExportTableAddress", uint32_t),
    ("Unknown", uint32_t),
  ]

class XEX2DSecurityInfo(ctypes.BigEndianStructure):
  _fields_ = [
    ("Size", uint32_t),
    ("ImageInfo", XEX2DHVImageInfo),
    ("AllowedMediaTypes", uint32_t), # todo:AllowedMediaTypes
    ("PageDescriptorCount", uint32_t),
  ]

class HVPageInfo(ctypes.BigEndianStructure):
  _fields_ = [
    ("Info", uint32_t, 4),
    ("Size", uint32_t, 28),
    ("DataDigest", uint8_t * 0x14),
  ]

class XEXFileDataDescriptor(ctypes.BigEndianStructure):
  _fields_ = [
    ("Size", uint32_t), # (Size - 8) / sizeof(XEXRawBaseFileBlock or XEXDataDescriptor) = num blocks
    ("Flags", uint16_t), # enum: EncryptionType   (0: decrypted / 1: encrypted)
    ("Format", uint16_t), # enum: CompressionType (0: none / 1: raw / 2: compressed / 3: delta-compressed)
  ]

# After XEXFileDataDescriptor when Format == 1 (aka "uncompressed")
class XEXRawBaseFileBlock(ctypes.BigEndianStructure):
  _fields_ = [
    ("Size", uint32_t),
    ("ZeroSize", uint32_t), # num zeroes to insert after this block
  ]

# After XEXFileDataDescriptor when Format == 2 (aka compressed)
# (first block has WindowSize prepended to it!)
class XEXCompressedBaseFileBlock(ctypes.BigEndianStructure):
  _fields_ = [
    ("Size", uint32_t),
    ("DataDigest", uint8_t * 0x14),
  ]

# Optional XEX Headers
class Version(ctypes.BigEndianStructure):
  _pack_ = 1
  _fields_ = [
    ("Major", uint8_t, 4),
    ("Minor", uint8_t, 4),
    ("Build", uint16_t, 16),
    ("QFE", uint8_t, 8),
  ]

class XEX2ExecutionID(ctypes.BigEndianStructure):
  _fields_ = [
    ("MediaId", uint32_t),
    ("Version", Version),
    ("BaseVersion", Version),
    ("TitleId", uint32_t),
    ("Platform", uint8_t),
    ("ExecutableType", uint8_t),
    ("DiscNum", uint8_t),
    ("DiscsInSet", uint8_t),
    ("SaveGameId", uint32_t),
  ]

class XEX2ServiceIDList(ctypes.BigEndianStructure):
  _fields_ = [
    ("Size", uint32_t),
    ("CustomServiceIDs", uint32_t * 4),
  ]

class ImageDataDirectory(ctypes.BigEndianStructure):
  _fields_ = [
    ("VirtualAddress", uint32_t),
    ("Size", uint32_t),
  ]

class XEX2TLSData(ctypes.BigEndianStructure):
  _fields_ = [
    ("TlsSlotCount", uint32_t),
    ("AddressOfRawData", uint32_t),
    ("SizeOfRawData", uint32_t),
    ("SizeOfTlsData", uint32_t),
  ]

class XEX2VitalStats(ctypes.BigEndianStructure):
  _fields_ = [
    ("Checksum", uint32_t),
    ("Timestamp", uint32_t),
  ]

class XEX2CallcapImports(ctypes.BigEndianStructure):
  _fields_ = [
    ("BeginFunctionThunkAddress", uint32_t),
    ("EndFunctionThunkAddress", uint32_t),
  ]

class XEX2MSLogo(ctypes.BigEndianStructure):
  _fields_ = [
    ("SectionSize", uint32_t),
    ("LogoSize", uint32_t),
    ("Logo", uint8_t),
  ]

class XEX2GameRatings(ctypes.BigEndianStructure):
  _fields_ = [
    ("Ratings", uint8_t * XEX_NUMBER_GAME_RATING_SYSTEMS),
  ]

def read_struct(li, struct):
  s = struct()
  slen = ctypes.sizeof(s)
  bytes = li.read(slen)
  fit = min(len(bytes), slen)
  ctypes.memmove(ctypes.addressof(s), bytes, fit)
  return s

def read_dword(li):
  s = li.read(4)
  if len(s) < 4:
    return 0
  return struct.unpack('<I', s)[0]

def read_dwordBE(li):
  s = li.read(4)
  if len(s) < 4:
    return 0
  return struct.unpack('>I', s)[0]

def read_xexstring(li):
  size = read_dwordBE(li)
  string = li.read(size)
  return string

def xex_read_image(li, xex_key_index):
  global directory_entries
  global image_key
  global session_key

  comp_format = 0
  enc_flag = 0
  if XEX_FILE_DATA_DESCRIPTOR_HEADER in directory_entries:
    data_descriptor = directory_entries[XEX_FILE_DATA_DESCRIPTOR_HEADER]
    comp_format = data_descriptor.Format
    enc_flag = data_descriptor.Flags

  if comp_format > 1:
    idc.warning("Sorry, XEX loader can't load compressed XEX atm :(")
    return 0

  # Setup session key for decrypting basefile
  aes = AES.new(xex_keys[xex_key_index], AES.MODE_ECB)
  session_key = aes.decrypt(image_key)

  result = 0
  if comp_format == 0:
    result = xex_read_raw(li)
  elif comp_format == 1:
    result = xex_read_uncompressed(li)
  elif comp_format == 2:
    result = xex_read_compressed(li)
  else:
    idc.warning("xex_read_image failed: unknown compression format %d!" % comp_format)
    result = 0

  # Let user know which key was used if file is encrypted & we've loaded successfully
  if result and enc_flag == 1:
    print("[+] (decrypted using %s key)" % xex_key_names[xex_key_index])

  return result

def xex_read_compressed(li):
  #todo
  return 0

def xex_read_raw(li):
  global xex_header

  # Seek to end of file
  li.seek(0, 2)
  pe_size = li.tell() - xex_header.SizeOfHeaders
  li.seek(xex_header.SizeOfHeaders)

  pe_data = io.BytesIO()
  pe_data.write(li.read(pe_size))

  return pe_load(pe_data)

def xex_read_uncompressed(li):
  global directory_entry_headers
  global directory_entries
  global xex_header
  global session_key

  data_descriptor = directory_entries[XEX_FILE_DATA_DESCRIPTOR_HEADER]

  li.seek(directory_entry_headers[XEX_FILE_DATA_DESCRIPTOR_HEADER] + 8) # skip first 8 bytes of data descriptor
  num_blocks = (data_descriptor.Size - 8) / 8

  # Read block descriptor structs
  xex_blocks = []
  for i in range(0, num_blocks):
    block = read_struct(li, XEXRawBaseFileBlock)
    xex_blocks.append(block)

  # Read in basefile
  pe_data = io.BytesIO()
  aes = AES.new(session_key, AES.MODE_CBC, '\0' * 16)

  li.seek(xex_header.SizeOfHeaders)
  for block in xex_blocks:
    data_size = block.Size
    zero_size = block.ZeroSize

    if data_descriptor.Flags == 0:
      # decrypted
      pe_data.write(li.read(data_size))
    elif data_descriptor.Flags == 1:
      # encrypted
      data = li.read(data_size)
      pe_data.write(aes.decrypt(data))
    else:
      idc.warning("xex_read_uncompressed failed: unknown encryption flags %d" % data_descriptor.Flags)
      return 0

    pe_data.write('\0' * zero_size)

  return pe_load(pe_data)

def accept_file(li, n):
  li.seek(0)
  magic = li.read(4)
  if magic == _MAGIC_XEX32:
    return _FORMAT_XEX32
  if magic == _MAGIC_XEX31:
    return _FORMAT_XEX31
  if magic == _MAGIC_XEX25:
    return _FORMAT_XEX25
  if magic == _MAGIC_XEX2D:
    return _FORMAT_XEX2D
  if magic == _MAGIC_XEX3F:
    return _FORMAT_XEX3F

  return 0

def load_file(li, neflags, format):
  global xex_magic
  global xex_header
  global directory_entry_headers
  global directory_entries
  global export_table_va
  global base_address
  global entry_point
  global image_key

  if format != _FORMAT_XEX32 and format != _FORMAT_XEX31 and format != _FORMAT_XEX25 and format != _FORMAT_XEX2D and format != _FORMAT_XEX3F:
    Warning("Unknown format name: '%s'" % format)
    return 0

  idaapi.set_processor_type("ppc", idc.SETPROC_LOADER)
  ida_typeinf.set_compiler_id(idc.COMP_MS)

  print("[+] IDAPython XEX Loader 0.6 for IDA 7.0+ by emoose")

  # Read XEX header & directory entry headers
  li.seek(0)
  xex_magic = li.read(4)
  li.seek(0)
  if xex_magic == _MAGIC_XEX3F:
    xex_header = read_struct(li, ImageXEXHeader_3F)
  else:
    xex_header = read_struct(li, ImageXEXHeader)

  print(xex_header)

  directory_entry_headers = {}
  for i in range(0, xex_header.HeaderDirectoryEntryCount):
    dir_header = read_struct(li, ImageXEXDirectoryEntry)
    directory_entry_headers[dir_header.Key] = dir_header.Value

  # Read XEX SecurityInfo header
  if xex_magic != _MAGIC_XEX3F:
    li.seek(xex_header.SecurityInfo)

    if xex_magic == _MAGIC_XEX32:
      xex_security_info = read_struct(li, XEX2SecurityInfo)
    elif xex_magic == _MAGIC_XEX31:
      xex_security_info = read_struct(li, XEX1SecurityInfo)
    elif xex_magic == _MAGIC_XEX25:
      xex_security_info = read_struct(li, XEX25SecurityInfo)
    elif xex_magic == _MAGIC_XEX2D:
      xex_security_info = read_struct(li, XEX2DSecurityInfo)

    export_table_va = xex_security_info.ImageInfo.ExportTableAddress
    if xex_magic != _MAGIC_XEX2D:
      image_key = xex_security_info.ImageInfo.ImageKey

  # Try reading in XEX directory entry structures
  print("[+] Reading %d XEX directory entries / optional headers..." % xex_header.HeaderDirectoryEntryCount)

  directory_entries = {}  
  for key in directory_entry_headers:
    header_value = directory_entry_headers[key]
    entry_size = key & 0xFF;
    if entry_size <= 1:
      # value is stored in the header itself
      directory_entries[key] = header_value
      print("0x%X = 0x%X" % (key, header_value))
      continue

    li.seek(header_value)
    # value is pointer to a structure...
    if key == XEX_HEADER_SECTION_TABLE:
      print("0x%X = HeaderSectionTable (@ 0x%X)" % (key, header_value))
      directory_entries[key] = 0 # todo: read_struct(li, XEX2Resources)

    elif key == XEX_FILE_DATA_DESCRIPTOR_HEADER:
      print("0x%X = FileDataDescriptor (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_struct(li, XEXFileDataDescriptor)
      print(directory_entries[key])

    elif key == XEX_HEADER_DELTA_PATCH_DESCRIPTOR:
      print("0x%X = DeltaPatchDescriptor (@ 0x%X)" % (key, header_value))
      directory_entries[key] = 0 # todo: read_struct(li, XEX2DeltaPatchDescriptor)

    elif key == XEX_HEADER_BOUND_PATH:
      print("0x%X = BoundingPath (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_xexstring(li)
      print(directory_entries[key])

    elif key == XEX_HEADER_IMPORTS:
      print("0x%X = Imports (@ 0x%X)" % (key, header_value))
      directory_entries[key] = 0 # todo: read_struct(li, XEX2ImportDescriptor)

    elif key == XEX_HEADER_IMPORTS_PREXEX2:
      print("0x%X = Imports_OldKey (@ 0x%X)" % (key, header_value))
      directory_entries[key] = 0 # todo: read_struct(li, XEX2ImportDescriptor)

    elif key == XEX_HEADER_VITAL_STATS:
      print("0x%X = VitalStats (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_struct(li, XEX2VitalStats)
      print(directory_entries[key])

    elif key == XEX_HEADER_CALLCAP_IMPORTS:
      print("0x%X = CallcapImports (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_struct(li, XEX2CallcapImports)
      print(directory_entries[key])

    elif key == XEX_HEADER_PE_MODULE_NAME:
      print("0x%X = PEModuleName (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_xexstring(li)
      print(directory_entries[key])

    elif key == XEX_HEADER_BUILD_VERSIONS:
      print("0x%X = BuildVersions (@ 0x%X)" % (key, header_value))
      directory_entries[key] = 0 # todo: read_struct(li, XEXImageLibraryVersions)

    elif key == XEX_HEADER_TLS_DATA:
      print("0x%X = TLSData (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_struct(li, XEX2TLSData)
      print(directory_entries[key])

    elif key == XEX_HEADER_EXECUTION_ID:
      print("0x%X = ExecutionID (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_struct(li, XEX2ExecutionID)
      print(directory_entries[key])

    elif key == XEX_HEADER_SERVICE_ID_LIST:
      print("0x%X = ServiceIDList (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_struct(li, XEX2ServiceIDList)
      print(directory_entries[key])

    elif key == XEX_HEADER_GAME_RATINGS:
      print("0x%X = GameRatings (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_struct(li, XEX2GameRatings)
      print(directory_entries[key])

    elif key == XEX_HEADER_LAN_KEY:
      print("0x%X = LANKey (@ 0x%X)" % (key, header_value))
      directory_entries[key] = li.read(0x10)
      print(directory_entries[key].encode('hex'))

    elif key == XEX_HEADER_MSLOGO:
      print("0x%X = MicrosoftLogo (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_struct(li, XEX2MSLogo)
      print(directory_entries[key])

    elif key == XEX_HEADER_PE_EXPORTS:
      print("0x%X = PEExports (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_struct(li, ImageDataDirectory)
      print(directory_entries[key])

    elif key == XEX_HEADER_PE_EXPORTS_PREXEX2:
      print("0x%X = PEExports_OldKey (@ 0x%X)" % (key, header_value))
      directory_entries[key] = read_struct(li, ImageDataDirectory)
      print(directory_entries[key])

    else:
      if entry_size == 0xFF:
        print("0x%X = variable-size data (@ 0x%X)" % (key, header_value))
        directory_entries[key] = 0 # todo: read_struct(li, OptionalHeaderData)
      else:
        print("0x%X = unknown key (data @ 0x%X)" % (key, header_value))

  # Print some info about the XEX
  if XEX_HEADER_EXECUTION_ID in directory_entries:
    exec_id = directory_entries[XEX_HEADER_EXECUTION_ID]
    print
    print("[+] XEX info:")
    print(" TitleId: %08X" % exec_id.TitleId)
    print(" Version: %d.%d.%d.%d (base: %d.%d.%d.%d)" % (exec_id.Version.Major, exec_id.Version.Minor, exec_id.Version.Build, exec_id.Version.QFE, exec_id.BaseVersion.Major, exec_id.BaseVersion.Minor, exec_id.BaseVersion.Build, exec_id.BaseVersion.QFE))
    print(" MediaId: %08X" % exec_id.MediaId)
    print(" SaveGameId: %08X" % exec_id.SaveGameId)
    print

  # Exit out if this is a patch file
  if xex_header.ModuleFlags & (XEX_MODULE_FLAG_PATCH | XEX_MODULE_FLAG_PATCH_FULL | XEX_MODULE_FLAG_PATCH_DELTA):
    idc.warning("Sorry, XEX loader doesn't support loading XEX patches")
    return 0

  # Try getting EP from directory entries
  # If not found here load_pe will fall back to the EP inside PE headers (not what we want!)
  entry_point = 0
  if XEX_HEADER_ENTRY_POINT in directory_entries:
    entry_point = directory_entries[XEX_HEADER_ENTRY_POINT]

  # Try getting base address from directory entries
  # If not found we'll use the one from SecurityInfo
  # (not sure which is preferred... guess the optional header should override the always-present SecurityInfo one?)
  base_address = xex_security_info.ImageInfo.LoadAddress if xex_magic != _MAGIC_XEX3F else xex_header.LoadAddress
  if XEX_HEADER_PE_BASE in directory_entries:
    base_address = directory_entries[XEX_HEADER_PE_BASE]

  # Try reading in the basefile
  if xex_read_image(li, 0) == 0 and xex_read_image(li, 1) == 0 and xex_read_image(li, 2) == 0:
    print("[+] Failed to load PE image from XEX :(")
    return 0

  # basefile loaded!

  # Setup imports if we have them
  if XEX_HEADER_IMPORTS in directory_entry_headers:
    xex_load_imports(li)

  # Setup exports if we have them
  if export_table_va != 0:
    xex_load_exports(li)

  # Done :)
  print("[+] XEX loaded, voila!")
  return 1
