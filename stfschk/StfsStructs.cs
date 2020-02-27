using System;
using System.Text;
using System.Runtime.InteropServices;

namespace STFSChk
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct PEC_HEADER
    {
        public XE_CONSOLE_SIGNATURE ConsoleSignature;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x14)]
        public byte[] ContentId;
        public ulong Unknown;
        public STF_VOLUME_DESCRIPTOR StfsVolumeDescriptor;
        public uint Unknown2;
        public ulong Creator;
        public byte ConsoleIdsCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)]
        public XE_CONSOLE_ID[] ConsoleIds; // AKA AuditList ?

        public void EndianSwap()
        {
            ConsoleSignature.EndianSwap();
            Unknown = Unknown.EndianSwap();
            StfsVolumeDescriptor.EndianSwap();
            Unknown2 = Unknown2.EndianSwap();
            Creator = Creator.EndianSwap();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct SVOD_DEVICE_DESCRIPTOR
    {
        public byte DescriptorLength;
        public byte BlockCacheElementCount;
        public byte WorkerThreadProcessor;
        public byte WorkerThreadPriority;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] FirstFragmentHashEntry;
        public byte Features;
        public byte NumberOfDataBlocks2;
        public byte NumberOfDataBlocks1;
        public byte NumberOfDataBlocks0;
        public byte StartingDataBlock0;
        public byte StartingDataBlock1;
        public byte StartingDataBlock2;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
        public byte[] Reserved;

        public bool ShouldBeZeroForDownlevelClients
        {
            get
            {
                return (Features & 1) == 1;
            }
        }

        public bool HasEnhancedGDFLayout
        {
            get
            {
                return (Features & 2) == 2;
            }
        }

        public int NumberOfDataBlocks
        {
            get
            {
                return NumberOfDataBlocks0 | (NumberOfDataBlocks1 << 8) | (NumberOfDataBlocks2 << 16);
            }
        }

        public int StartingDataBlock
        {
            get
            {
                return StartingDataBlock0 | (StartingDataBlock1 << 8) | (StartingDataBlock2 << 16);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct STF_VOLUME_DESCRIPTOR
    {
        public byte DescriptorLength;
        public byte Version;
        public byte Flags;
        public ushort DirectoryAllocationBlocks;
        public byte DirectoryFirstBlockNumber0;
        public byte DirectoryFirstBlockNumber1;
        public byte DirectoryFirstBlockNumber2;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x14)]
        public byte[] RootHash;
        public uint NumberOfTotalBlocks;
        public uint NumberOfFreeBlocks;

        public static STF_VOLUME_DESCRIPTOR Default()
        {
            var descriptor = new STF_VOLUME_DESCRIPTOR();
            descriptor.DescriptorLength = 0x24;
            descriptor.Version = 0;
            descriptor.Flags = 0;
            descriptor.DirectoryAllocationBlocks = 1;
            descriptor.DirectoryFirstBlockNumber0 =
                descriptor.DirectoryFirstBlockNumber1 =
                descriptor.DirectoryFirstBlockNumber2 = 0;
            descriptor.RootHash = new byte[0x14];
            descriptor.NumberOfTotalBlocks = 1;
            descriptor.NumberOfFreeBlocks = 0;
            return descriptor;
        }

        public bool ReadOnlyFormat
        {
            get
            {
                return (Flags & 1) == 1;
            }
        }

        public bool RootActiveIndex
        {
            get
            {
                return (Flags & 2) == 2;
            }
        }

        public int DirectoryFirstBlockNumber
        {
            get
            {
                return DirectoryFirstBlockNumber0 | (DirectoryFirstBlockNumber1 << 8) | (DirectoryFirstBlockNumber2 << 16);
            }
        }

        public void EndianSwap()
        {
            // DirectoryAllocationBlocks = DirectoryAllocationBlocks.EndianSwap();
            NumberOfTotalBlocks = NumberOfTotalBlocks.EndianSwap();
            NumberOfFreeBlocks = NumberOfFreeBlocks.EndianSwap();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct STF_HASH_ENTRY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x14)]
        public byte[] Hash;

        public byte Flags;
        public byte Level0NextBlock2;
        public byte Level0NextBlock1;
        public byte Level0NextBlock0;

        public bool LevelNActiveIndex
        {
            get
            {
                return (Flags & 0x40) == 0x40;
            }
        }

        public int Level0NextBlock
        {
            get
            {
                return Level0NextBlock0 | (Level0NextBlock1 << 8) | (Level0NextBlock2 << 16);
            }
            set
            {
                Level0NextBlock0 = (byte)(value & 0xFF);
                Level0NextBlock1 = (byte)((value >> 8) & 0xFF);
                Level0NextBlock2 = (byte)((value >> 16) & 0xFF);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct STF_HASH_BLOCK
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 170)]
        public STF_HASH_ENTRY[] Entries;
        public uint NumberOfCommittedBlocks;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
        public byte[] Padding;

        public void EndianSwap()
        {
            NumberOfCommittedBlocks = NumberOfCommittedBlocks.EndianSwap();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct XCONTENT_LICENSEE
    {
        public const ulong kTypeWindowsId = 3u << 48;
        public const ulong kTypeXuid = 9u << 48;
        public const ulong kTypeSerPrivileges = 0xB000u << 48;
        public const ulong kTypeHvFlags = 0xC000u << 48;
        public const ulong kTypeKeyVaultPrivileges = 0xD000u << 48;
        public const ulong kTypeMediaFlags = 0xE000u << 48;
        public const ulong kTypeConsoleId = 0xF000u << 48;
        public const ulong kTypeUnrestricted = 0xFFFFu << 48;

        public ulong LicenseeId;
        public uint LicenseBits;
        public uint LicenseFlags;

        public bool IsWindowsIdLicense
        {
            get
            {
                return (LicenseeId & kTypeWindowsId) == kTypeWindowsId;
            }
        }

        public bool IsXuidLicense
        {
            get
            {
                return (LicenseeId & kTypeXuid) == kTypeXuid;
            }
        }

        public bool IsSerPrivilegesLicense
        {
            get
            {
                return (LicenseeId & kTypeSerPrivileges) == kTypeSerPrivileges;
            }
        }

        public bool IsHvFlagsLicense
        {
            get
            {
                return (LicenseeId & kTypeHvFlags) == kTypeHvFlags;
            }
        }

        public bool IsKeyVaultPrivilegesLicense
        {
            get
            {
                return (LicenseeId & kTypeKeyVaultPrivileges) == kTypeKeyVaultPrivileges;
            }
        }

        public bool IsMediaFlagsLicense
        {
            get
            {
                return (LicenseeId & kTypeMediaFlags) == kTypeMediaFlags;
            }
        }

        public bool IsConsoleIdLicense
        {
            get
            {
                return (LicenseeId & kTypeConsoleId) == kTypeConsoleId;
            }
        }

        public bool IsUnrestrictedLicense
        {
            get
            {
                return (LicenseeId & kTypeUnrestricted) == kTypeUnrestricted;
            }
        }

        public string LicenseType
        {
            get
            {
                if (IsUnrestrictedLicense)
                    return "Unrestricted";
                if (IsWindowsIdLicense)
                    return "WindowsId";
                if (IsXuidLicense)
                    return "Xuid";
                if (IsSerPrivilegesLicense)
                    return "SerPrivileges";
                if (IsHvFlagsLicense)
                    return "HvFlags";
                if (IsKeyVaultPrivilegesLicense)
                    return "KeyVaultPrivileges";
                if (IsMediaFlagsLicense)
                    return "MediaFlags";
                if (IsConsoleIdLicense)
                    return "ConsoleId";
                return "Unknown";
            }
        }

        public bool IsValid
        {
            get
            {
                return LicenseeId != 0 || LicenseBits != 0 || LicenseFlags != 0;
            }
        }

        public void EndianSwap()
        {
            LicenseeId = LicenseeId.EndianSwap();
            LicenseBits = LicenseBits.EndianSwap();
            LicenseFlags = LicenseFlags.EndianSwap();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct XCONTENT_HEADER
    {
        public const uint kSignatureTypeConBE = 0x434F4E20;
        public const uint kSignatureTypeLiveBE = 0x4C495645;
        public const uint kSignatureTypePirsBE = 0x50495253;

        public uint SignatureType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x228)]
        public byte[] Signature;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        public XCONTENT_LICENSEE[] LicenseDescriptors;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x14)]
        public byte[] ContentId;
        public uint SizeOfHeaders;

        public XE_CONSOLE_SIGNATURE ConsoleSignature
        {
            get
            {
                var sig = Utility.BytesToStruct<XE_CONSOLE_SIGNATURE>(Signature);
                sig.EndianSwap();
                return sig;
            }
        }

        public string SignatureTypeString
        {
            get
            {
                switch (SignatureType)
                {
                    case kSignatureTypeConBE:
                        return "CON";
                    case kSignatureTypeLiveBE:
                        return "LIVE";
                    case kSignatureTypePirsBE:
                        return "PIRS";
                }
                return SignatureType.ToString("X8");
            }
        }
        public void EndianSwap()
        {
            SignatureType = SignatureType.EndianSwap();

            for (int i = 0; i < 0x10; i++)
                LicenseDescriptors[i].EndianSwap();

            SizeOfHeaders = SizeOfHeaders.EndianSwap();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    public struct UCHAR_80
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x100)]
        public byte[] Bytes;

        public string String
        {
            get
            {
                return Encoding.Unicode.GetString(Bytes).Trim(new char[] { '\0' });
            }
        }

        public void EndianSwap()
        {
            for (int i = 0; i < Bytes.Length; i += 2)
                Array.Reverse(Bytes, i, 2);
        }

        public override string ToString()
        {
            return String;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    public struct UCHAR_40
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x80)]
        public byte[] Bytes;

        public string String
        {
            get
            {
                return Encoding.Unicode.GetString(Bytes).Trim(new char[] { '\0' });
            }
        }

        public void EndianSwap()
        {
            for (int i = 0; i < Bytes.Length; i += 2)
                Array.Reverse(Bytes, i, 2);
        }

        public override string ToString()
        {
            return String;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct VERSION
    {
        public byte MajorMinor;
        public ushort Build;
        public byte QFE;

        public bool IsValid
        {
            get
            {
                return MajorMinor != 0 || Build != 0 || QFE != 0;
            }
        }

        public override string ToString()
        {
            return $"{(MajorMinor >> 4) & 0xF}.{MajorMinor & 0xF}.{Build}.{QFE}";
        }

        public void EndianSwap()
        {
            Build = Build.EndianSwap();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct XEX2_EXECUTION_ID
    {
        public uint MediaId;
        public VERSION Version;
        public VERSION BaseVersion;
        public uint TitleId;
        public byte Platform;
        public byte ExecutableType;
        public byte DiscNum;
        public byte DiscsInSet;
        public uint SaveGameId;

        public void EndianSwap()
        {
            MediaId = MediaId.EndianSwap();
            Version.EndianSwap();
            BaseVersion.EndianSwap();
            TitleId = TitleId.EndianSwap();
            SaveGameId = SaveGameId.EndianSwap();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    public struct XCONTENT_METADATA
    {
        public void EndianSwap()
        {
            ContentType = ContentType.EndianSwap();
            ContentMetadataVersion = ContentMetadataVersion.EndianSwap();
            ContentSize = ContentSize.EndianSwap();
            ExecutionId.EndianSwap();
            Creator = Creator.EndianSwap();
            DataFiles = DataFiles.EndianSwap();
            DataFilesSize = DataFilesSize.EndianSwap();
            VolumeType = VolumeType.EndianSwap();
            OnlineCreator = OnlineCreator.EndianSwap();
            Category = Category.EndianSwap();

            foreach (var str in DisplayName)
                str.EndianSwap();
            foreach (var str in Description)
                str.EndianSwap();
            Publisher.EndianSwap();
            TitleName.EndianSwap();

            ThumbnailSize = ThumbnailSize.EndianSwap();
            foreach (var str in DisplayNameEx)
                str.EndianSwap();

            TitleThumbnailSize = TitleThumbnailSize.EndianSwap();
            foreach (var str in DescriptionEx)
                str.EndianSwap();
        }
        public uint ContentType;
        public uint ContentMetadataVersion;
        public ulong ContentSize;

        public XEX2_EXECUTION_ID ExecutionId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
        public byte[] ConsoleId;
        public ulong Creator;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x24)]
        public byte[] VolumeDescriptor;

        public uint DataFiles;
        public ulong DataFilesSize;
        public uint VolumeType;

        public ulong OnlineCreator;
        public uint Category;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
        public byte[] Reserved2;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x24)]
        public byte[] TypeSpecificData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x14)]
        public byte[] DeviceId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 9)]
        public UCHAR_80[] DisplayName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 9)]
        public UCHAR_80[] Description;
        public UCHAR_40 Publisher;
        public UCHAR_40 TitleName;

        public byte FlagsAsBYTE;

        public uint ThumbnailSize;
        public uint TitleThumbnailSize;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x3D00)]
        public byte[] Thumbnail;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public UCHAR_80[] DisplayNameEx;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x3D00)]
        public byte[] TitleThumbnail;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public UCHAR_80[] DescriptionEx;

        public STF_VOLUME_DESCRIPTOR StfsVolumeDescriptor
        {
            get
            {
                var desc = Utility.BytesToStruct<STF_VOLUME_DESCRIPTOR>(VolumeDescriptor);
                desc.EndianSwap();
                return desc;
            }
        }

        public SVOD_DEVICE_DESCRIPTOR SvodVolumeDescriptor
        {
            get
            {
                var desc = Utility.BytesToStruct<SVOD_DEVICE_DESCRIPTOR>(VolumeDescriptor);
                return desc;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    public struct XCONTENT_METADATA_INSTALLER
    {
        public const uint kTypeSystemUpdate = 0x53555044; // SUPD
        public const uint kTypeTitleUpdate = 0x54555044; // TUPD

        public uint MetaDataType;
        public VERSION CurrentVersion;
        public VERSION NewVersion;

        public bool IsSystemUpdate
        {
            get
            {
                return MetaDataType == kTypeSystemUpdate;
            }
        }

        public bool IsTitleUpdate
        {
            get
            {
                return MetaDataType == kTypeTitleUpdate;
            }
        }

        public bool IsValid
        {
            get
            {
                return MetaDataType == kTypeSystemUpdate || MetaDataType == kTypeTitleUpdate;
            }
        }

        public void EndianSwap()
        {
            MetaDataType = MetaDataType.EndianSwap();
            CurrentVersion.EndianSwap();
            NewVersion.EndianSwap();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct STF_DIRECTORY_ENTRY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]
        public byte[] FileNameBytes;
        public byte Flags;
        public byte ValidDataBlocks0;
        public byte ValidDataBlocks1;
        public byte ValidDataBlocks2;
        public byte AllocationBlocks0;
        public byte AllocationBlocks1;
        public byte AllocationBlocks2;
        public byte FirstBlockNumber0;
        public byte FirstBlockNumber1;
        public byte FirstBlockNumber2;
        public short DirectoryIndex;
        public uint FileSize;
        public int CreationTimeRaw;
        public int LastWriteTimeRaw;

        public DateTime CreationTime
        {
            get
            {
                return Utility.DecodeMSTime(CreationTimeRaw);
            }
            set
            {
                CreationTimeRaw = Utility.EncodeMSTime(value);
            }
        }

        public DateTime LastWriteTime
        {
            get
            {
                return Utility.DecodeMSTime(LastWriteTimeRaw);
            }
            set
            {
                LastWriteTimeRaw = Utility.EncodeMSTime(value);
            }
        }

        public byte FileNameLength
        {
            get
            {
                return (byte)(Flags & 0x3F);
            }
            set
            {
                Flags = (byte)(value & 0x3F);
            }
        }

        public bool IsDirectory
        {
            get
            {
                return (Flags & 0x80) == 0x80;
            }
        }

        public bool IsContiguous
        {
            get
            {
                return (Flags & 0x40) == 0x40;
            }
        }

        public string FileName
        {
            get
            {
                return Encoding.ASCII.GetString(FileNameBytes, 0, FileNameLength).Trim(new char[] { '\0' });
            }
            set
            {
                FileNameLength = (byte)value.Length;
                FileNameBytes = Encoding.ASCII.GetBytes(value);
                if (FileNameBytes.Length > FileNameLength)
                    Array.Resize(ref FileNameBytes, FileNameLength);
            }
        }
        public int ValidDataBlocks
        {
            get
            {
                return ValidDataBlocks0 | (ValidDataBlocks1 << 8) | (ValidDataBlocks2 << 16);
            }
        }

        public int AllocationBlocks
        {
            get
            {
                return AllocationBlocks0 | (AllocationBlocks1 << 8) | (AllocationBlocks2 << 16);
            }
        }

        public int FirstBlockNumber
        {
            get
            {
                return FirstBlockNumber0 | (FirstBlockNumber1 << 8) | (FirstBlockNumber2 << 16);
            }
        }

        public bool IsValid
        {
            get
            {
                return Flags != 0 && FileNameLength > 0 && FileNameLength < 41 && FileName.IndexOfAny(StfsFileSystem.kInvalidFilenameChars) < 0;
            }
        }

        public void EndianSwap()
        {
            DirectoryIndex = DirectoryIndex.EndianSwap();
            FileSize = FileSize.EndianSwap();
            CreationTimeRaw = CreationTimeRaw.EndianSwap();
            LastWriteTimeRaw = LastWriteTimeRaw.EndianSwap();
        }

        public override string ToString()
        {
            return FileName;
        }
    }

    // AKA "Josh" sector, at sector 4 / 0x800 of HDD
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct CACHE_PARTITION_DATA
    {
        public const uint kMagicJosh = 0x4A6F7368; // "Josh"

        public uint CacheSignature;
        public XE_CONSOLE_SIGNATURE Signature;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public STF_VOLUME_DESCRIPTOR[] VolumeDescriptor; // both are console-signed into the signature above
        public uint Version;
        public uint LastUsedIndex;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public uint[] TitleID;

        public bool IsValid
        {
            get
            {
                return CacheSignature == kMagicJosh;
            }
        }

        public void EndianSwap()
        {
            CacheSignature = CacheSignature.EndianSwap();
            Signature.EndianSwap();
            for (int i = 0; i < 2; i++)
                VolumeDescriptor[i].EndianSwap();
            Version = Version.EndianSwap();
            LastUsedIndex = LastUsedIndex.EndianSwap();
            for (int i = 0; i < 2; i++)
                TitleID[i] = TitleID[i].EndianSwap();
        }
    }
}
