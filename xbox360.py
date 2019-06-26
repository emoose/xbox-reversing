import idc 
import idaapi
import struct
import ctypes
import enum

XEX2_FORMAT = "Xbox360 executable"

XEX2_MAGIC = "XEX2"

uint8_t  = ctypes.c_byte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
     
def StructAsString(self):
  return "{}: {{{}}}".format(self.__class__.__name__,
                             ", ".join(["{}: {}".format(field[0],
                                                        getattr(self,
                                                                field[0]))
                                        for field in self._fields_]))
                                        
ctypes.BigEndianStructure.__str__ = StructAsString

# XEX structs & enums
class ModuleFlags(enum.IntEnum): 
  TitleProcess = 1
  TitleImports = 2
  Debugger = 4
  Dll = 8
  Patch = 16
  PatchFull = 32
  PatchDelta = 64
  UserMode = 128
  
class ImageKeys(enum.IntEnum):
  HeaderSectionTable          = 0x000002FF
  FileDataDescriptor          = 0x000003FF
  BaseReference               = 0x00000405
  DeltaPatchDescriptor        = 0x000005FF
  KeyVaultPrivs               = 0x000040FF
  TimeRange                   = 0x000041FF
  ConsoleIdTable              = 0x000042FF
  BoundingPath                = 0x000080FF
  PEExports_OldKey            = 0x00008102
  DeviceId                    = 0x00008105
  OriginalBaseAddress         = 0x00010001
  EntryPoint                  = 0x00010100
  PEBase                      = 0x00010201
  Imports_OldKey              = 0x000102FF
  Imports                     = 0x000103FF
  VitalStats                  = 0x00018002
  CallcapImports              = 0x00018102
  FastcapEnabled              = 0x00018200
  PEModuleName                = 0x000183FF
  BuildVersions               = 0x000200FF
  TLSData                     = 0x00020104
  StackSize                   = 0x00020200
  FSCacheSize                 = 0x00020301
  XapiHeapSize                = 0x00020401
  PageHeapSizeFlags           = 0x00028002
  SystemFlags                 = 0x00030000
  ExecutionID                 = 0x00040006
  ServiceIDList               = 0x000401FF
  WorkspaceSize               = 0x00040201
  GameRatings                 = 0x00040310
  LANKey                      = 0x00040404
  MicrosoftLogo               = 0x000405FF
  MultidiskMediaIDs           = 0x000406FF
  AlternateTitleIDs           = 0x000407FF
  AdditionalTitleMemory       = 0x00040801
  PEExports                   = 0x00E10402
     
class ImageXexHeader(ctypes.BigEndianStructure):
  _fields_ = [
      ("Magic", uint32_t),
      ("ModuleFlags", uint32_t), # enum:ModuleFlags
      ("SizeOfHeaders", uint32_t),
      ("SizeOfDiscardableHeaders", uint32_t),
      ("SecurityInfo", uint32_t),
      ("HeaderDirectoryEntryCount", uint32_t),
  ]
    
class ImageXexDirectoryEntry(ctypes.BigEndianStructure):
  _fields_ = [
      ("Key", uint32_t), # enum:ImageKeys
      ("Value", uint32_t),
  ]
    
class XEX2HVImageInfo(ctypes.BigEndianStructure):
  _fields_ = [
      ("Signature", uint8_t * 0x100),
      ("InfoSize", uint32_t),
      ("ImageFlags", uint32_t), # enum:ImageFlags
      ("LoadAddress", uint32_t),
      ("ImageHash", uint8_t * 0x14),
      ("ImportTableCount", uint32_t),
      ("ImportDigest", uint8_t * 0x14),
      ("MediaID", uint8_t * 0x10),
      ("ImageKey", uint8_t * 0x10),
      ("ExportTableAddress", uint32_t),
      ("HeaderHash", uint8_t * 0x14),
      ("GameRegion", uint32_t), # enum:GameRegions
  ]

class XEX2SecurityInfo(ctypes.BigEndianStructure):
  _fields_ = [
      ("Size", uint32_t),
      ("ImageSize", uint32_t),
      ("ImageInfo", XEX2HVImageInfo),
      ("AllowedMediaTypes", uint32_t), # enum:AllowedMediaTypes
      ("PageDescriptorCount", uint32_t),
  ]
    
class HVPageInfo(ctypes.BigEndianStructure):
  _fields_ = [
      ("InfoAndSize", uint32_t),
      ("DataDigest", uint8_t * 0x14),
  ]
  
# Optional Headers
class Version(ctypes.BigEndianStructure):
  _fields_ = [
      ("QFE", uint8_t),
      ("Build", uint16_t),
      ("MinorMajor", uint8_t),
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
      ("Ratings", uint8_t * 64),
  ]
    
def read_dword(li):
  s = li.read(4)
  if len(s) < 4: 
    return 0
  return struct.unpack('<I', s)[0]
  
def read_struct(li, struct):
  s = struct()
  slen = ctypes.sizeof(s)
  bytes = li.read(slen)
  fit = min(len(bytes), slen)
  ctypes.memmove(ctypes.addressof(s), bytes, fit)
  return s

def accept_file(li, n):
  li.seek(0)
  magic = li.read(4)
  if magic == XEX2_MAGIC:
    load_file(li, 0, XEX2_FORMAT) #debug
    return XEX2_FORMAT
    
  return 0
  
def load_pe(li):
  return 0
  
def load_file(li, neflags, format):
  if format != XEX2_FORMAT:
    Warning("Unknown format name: '%s'" % format)
    return 0

  xex_header = read_struct(li, ImageXexHeader)
  #print(xex_header)
  
  directory_entries_raw = []
  for i in range(0, xex_header.HeaderDirectoryEntryCount):
    directory_entries_raw.append(read_struct(li, ImageXexDirectoryEntry))
    
  #for p in directory_entries_raw: print p
  
  li.seek(xex_header.SecurityInfo)
  xex_security_info = read_struct(li, XEX2SecurityInfo)
  
  directory_entries = {}
  for entry in directory_entries_raw:
    entry_size = entry.Key & 0xFF;
    if entry_size <= 1:
      # value is stored in the directory entry itself!
      directory_entries[entry.Key] = entry.Value
      print("DirectoryEntry[%d] = %d" % (entry.Key, entry.Value))
      continue
    
    print("DirectoryEntry[%d] = struct" % entry.Key)
    li.seek(entry.Value)
    # value is pointer to a structure...
    if entry.Key == ImageKeys.HeaderSectionTable:
      directory_entries[entry.Key] = 0 # read_struct(li, XEX2Resources)
    elif entry.Key == ImageKeys.FileDataDescriptor:
      directory_entries[entry.Key] = 0 # read_struct(li, XEX2FileDataDescriptor)
    elif entry.Key == ImageKeys.DeltaPatchDescriptor:
      directory_entries[entry.Key] = 0 # read_struct(li, XEX2DeltaPatchDescriptor)
    elif entry.Key == ImageKeys.BoundingPath:
      directory_entries[entry.Key] = 0 ## todo: read XEXSTRING
    elif entry.Key == ImageKeys.Imports:
      directory_entries[entry.Key] = 0 # read_struct(li, XEX2ImportDescriptor)
    elif entry.Key == ImageKeys.Imports_OldKey:
      directory_entries[entry.Key] = 0 # read_struct(li, XEX2ImportDescriptor)
    elif entry.Key == ImageKeys.VitalStats:
      directory_entries[entry.Key] = read_struct(li, XEX2VitalStats)
    elif entry.Key == ImageKeys.CallcapImports:
      directory_entries[entry.Key] = read_struct(li, XEX2CallcapImports)
    elif entry.Key == ImageKeys.PEModuleName:
      directory_entries[entry.Key] = 0 ## todo: read XEXSTRING
    elif entry.Key == ImageKeys.BuildVersions:
      directory_entries[entry.Key] = 0 # read_struct(li, XEXImageLibraryVersions)
    elif entry.Key == ImageKeys.TLSData:
      directory_entries[entry.Key] = read_struct(li, XEX2TLSData)
    elif entry.Key == ImageKeys.ExecutionID:
      directory_entries[entry.Key] = read_struct(li, XEX2ExecutionID)
    elif entry.Key == ImageKeys.ServiceIDList:
      directory_entries[entry.Key] = read_struct(li, XEX2ServiceIDList)
    elif entry.Key == ImageKeys.GameRatings:
      directory_entries[entry.Key] = read_struct(li, XEX2GameRatings)
    elif entry.Key == ImageKeys.LANKey:
      directory_entries[entry.Key] = li.read(0x10)
    elif entry.Key == ImageKeys.MicrosoftLogo:
      directory_entries[entry.Key] = read_struct(li, XEX2MSLogo)
    elif entry.Key == ImageKeys.PEExports:
      directory_entries[entry.Key] = read_struct(li, ImageDataDirectory)
    elif entry.Key == ImageKeys.PEExports_OldKey:
      directory_entries[entry.Key] = read_struct(li, ImageDataDirectory)
    else:
      if entry_size == 0xFF:
        print("DirectoryEntry[%d]: variable data")
        directory_entries[entry.Key] = 0 # read_struct(li, OptionalHeaderData)
      else:
        print("DirectoryEntry[%d]: unknown key (data @ 0x%X)" % (entry.Key, entry.Value))

  li.seek(xex_header.SizeOfHeaders)
  
  return load_pe(li)