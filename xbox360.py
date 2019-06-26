# IDAPython XEX Loader 0.2 for IDA 7.0+ by emoose
# based on work by the Xenia project, XEX2.bt by Anthony, xextool 0.1 by xor37h, x360_imports.idc by xorloser, and xkelib
# (currently only works on decrypted & uncompressed XEXs, use "xextool -eu -cu xexfile.xex" beforehand!)
# --
# TODO:
# - exports
# - encryption & compression
# - relocations
# - support for XEX1 and lower (mapped the structs a while ago, will add support soon)
# - print more info to console (TitleID/Version, compression info, etc... should maybe print all structs to aid with RE?)
# - name/comment XEX resources?

import idc 
import idaapi
import ida_segment
import ida_bytes
import ida_auto
import struct
import ctypes
import os
import x360_imports

XEX2_MAGIC = "XEX2"
XEX2_FORMAT = "Xbox360 XEX File"

char_t = ctypes.c_char
uint8_t  = ctypes.c_byte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint

# Globals shared between load_file, pe_load, etc..
directory_entry_headers = {}
directory_entries = {}
base_address = 0
entry_point = 0
xex_blocks = []

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

  seg_addr = base_address + section.VirtualAddress
  idc.AddSeg(seg_addr, seg_addr + section.VirtualSize, 0, 1, idaapi.saRelPara, idaapi.scPub)
  idc.RenameSeg(seg_addr, section.Name)

  # Segment permissions
  seg_perms = 0
  if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
    seg_perms |= ida_segment.SEGPERM_EXEC
  if section.Characteristics & IMAGE_SCN_MEM_READ:
    seg_perms |= ida_segment.SEGPERM_READ
  if section.Characteristics & IMAGE_SCN_MEM_WRITE:
    seg_perms |= ida_segment.SEGPERM_WRITE

  # Segment type
  seg_type = idc.SEG_DATA
  if section.Characteristics & IMAGE_SCN_CNT_CODE:
    seg_type = idc.SEG_CODE

  idc.set_segm_attr(seg_addr, idc.SEGATTR_PERM, seg_perms);
  idc.SetSegmentType(seg_addr, seg_type)
 
# "Raw" basefile format has extraneous zeroes removed - loader is meant to re-add them based on contents of ImageKeys.FileDataDescriptor
# atm I'm not sure how to make IDA load from a modified in-memory copy of the PE though...
# So for now we do some funny hack on the sections VA to get the real file offset of it
# (hopefully IDAPython can load from in-memory data though, since I don't see how we could handle encryption/compression otherwise :)
# ^ mem2base(bytes, addr) should work?
def pe_adjust_addr(addr):
  global xex_blocks

  i = 0
  new_addr = addr
  for block in xex_blocks:
    i += block.Size
    if addr > i:
      new_addr -= block.ZeroSize
    i += block.ZeroSize

  return new_addr

def pe_load(li):
  global directory_entry_headers
  global base_address
  global entry_point

  # Get size of the PE
  pe_addr = li.tell()
  li.seek(0, 2) # seek to end
  pe_size = li.tell() - pe_addr
  li.seek(pe_addr)

  # Read DOS & NT headers
  dos_header = read_struct(li, ImageDOSHeader)

  li.seek(pe_addr + dos_header.AddressOfNewExeHeader)
  nt_header = read_struct(li, ImageNTHeaders)

  # Skip past PE data directories (for now? do we ever need them?)
  li.seek(nt_header.OptionalHeader.NumberOfRvaAndSizes * 8, os.SEEK_CUR)

  # If no EP passed we'll use EP from the optionalheader
  if entry_point <= 0:
    entry_point = nt_header.OptionalHeader.AddressOfEntryPoint

  # Read in & map our section headers
  # (todo: fix loading more sections than needed, seems sections like .reloc shouldn't be loaded in?)
  section_headers = []
  for i in range(0, nt_header.FileHeader.NumberOfSections):
    section_headers.append(read_struct(li, ImageSectionHeader))

  for section in section_headers:
    sec_addr = pe_adjust_addr(section.VirtualAddress)
    sec_size = min(section.VirtualSize, section.SizeOfRawData)

    if sec_addr + sec_size > pe_size:
      sec_size = pe_size - sec_addr

    # Load em if you got em
    if sec_size <= 0:
      continue

    pe_add_section(section)

    # Load from file into IDB
    li.file2base(sec_addr + pe_addr, base_address + section.VirtualAddress, base_address + section.VirtualAddress + sec_size, 0)

  # Name the EP if we have one
  if entry_point > 0:
    idaapi.add_entry(entry_point, entry_point, "start", 1)

  # Setup our imports (.......)
  if XEX_HEADER_IMPORTS in directory_entry_headers:
    xex_load_imports(li)

  # XEX load complete :)
  print("[+] XEX loaded, voila!")
  return 1

  
# todo: this messy stuff
# how to even define an import module in IDA? and then add imports to that module? can't find anything for it in IDAPython...
def xex_load_imports(li):
  global directory_entry_headers

  li.seek(directory_entry_headers[XEX_HEADER_IMPORTS])
  import_desc = read_struct(li, XEXImportDescriptor)

  import_libnames = []
  cur_lib = ""
  for i in range(0, import_desc.NameTableSize):
    name_char = li.read(1)

    if name_char == '\0':
      if cur_lib != "":
        import_libnames.append(cur_lib)
        cur_lib = ""
    else:
      cur_lib += name_char

  import_libs = []
  for i in range(0, import_desc.ModuleCount):
    table_header = read_struct(li, XEXImportTable)
    libname = import_libnames[table_header.ModuleIndex]
    print(table_header)
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

      elif record_type == 1:
        # thunk
        # have to rewrite code to set r3 & r4 like xorlosers loader does
        # r3 = module index afaik
        # r4 = ordinal
        # important to note that basefiles extracted via xextool have this rewrite done already, but raw basefile from XEX doesn't!
        # todo: find out how to add to imports window like xorloser loader...

        #idc.set_func_flags(record_addr, idc.FUNC_LIB)
        ida_bytes.put_dword(record_addr + 0, 0x38600000 | table_header.ModuleIndex)
        ida_bytes.put_dword(record_addr + 4, 0x38800000 | ordinal)
        idc.add_func(record_addr, record_addr + 4)
        idc.set_name(record_addr, import_name)

        # this should mark the func as a library function, but it doesn't do anything for some reason
        # tried a bunch of things like idaapi.autoWait() before running it, just crashes IDA with internal errors...
        idc.set_func_flags(record_addr, idc.get_func_flags(record_addr) | idc.FUNC_LIB)

      else:
        print("[+] %s import %d (@ 0x%X) unknown type %d!" % (libname, ordinal, record_addr, record_type))

  return

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


# XEX structs & enums
class ImageXEXHeader(ctypes.BigEndianStructure):
  _fields_ = [
    ("Magic", uint32_t),
    ("ModuleFlags", uint32_t),
    ("SizeOfHeaders", uint32_t),
    ("SizeOfDiscardableHeaders", uint32_t),
    ("SecurityInfo", uint32_t),
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

def accept_file(li, n):
  li.seek(0)
  magic = li.read(4)
  if magic == XEX2_MAGIC:
    return XEX2_FORMAT

  return 0

def load_file(li, neflags, format):
  global directory_entry_headers
  global directory_entries
  global base_address
  global entry_point
  global xex_blocks

  if format != XEX2_FORMAT:
    Warning("Unknown format name: '%s'" % format)
    return 0

  idaapi.set_processor_type("ppc", idc.SETPROC_LOADER)

  print("[+] IDAPython XEX Loader 0.1 for IDA 7.0+ by emoose")

  # Read XEX header & directory entry headers
  li.seek(0)
  xex_header = read_struct(li, ImageXEXHeader)
  print(xex_header)

  directory_entry_headers = {}
  for i in range(0, xex_header.HeaderDirectoryEntryCount):
    dir_header = read_struct(li, ImageXEXDirectoryEntry)
    directory_entry_headers[dir_header.Key] = dir_header.Value

  # Read XEX SecurityInfo header
  li.seek(xex_header.SecurityInfo)
  xex_security_info = read_struct(li, XEX2SecurityInfo)

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
  base_address = xex_security_info.ImageInfo.LoadAddress
  if XEX_HEADER_PE_BASE in directory_entries:
    base_address = directory_entries[XEX_HEADER_PE_BASE]

  # todo: add support for compression & encryption here!
  # For now only support reading in raw block descriptors (needed to align raw file properly, see pe_adjust_addr)
  xex_blocks = []
  if XEX_FILE_DATA_DESCRIPTOR_HEADER in directory_entries:
    data_descriptor = directory_entries[XEX_FILE_DATA_DESCRIPTOR_HEADER]
    if data_descriptor.Flags != 0 or data_descriptor.Format > 1:
      idc.warning("Sorry, XEX loader can't load compressed/encrypted XEX atm :(")
      return 0

    li.seek(directory_entry_headers[XEX_FILE_DATA_DESCRIPTOR_HEADER] + 8) # skip first 8 bytes of data descriptor
    num_blocks = (data_descriptor.Size - 8) / 8
    for i in range(0, num_blocks):
      xex_blocks.append(read_struct(li, XEXRawBaseFileBlock))

  # Now pass it to load_pe for basefile parsing!
  li.seek(xex_header.SizeOfHeaders)
  return pe_load(li)