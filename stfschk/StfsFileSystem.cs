using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

// TODO:
// - add invalid tables to metadata.ini
namespace STFSChk
{
    public class StfsFileSystem
    {
        public const int kSectorSize = 0x1000;
        public static readonly char[] kInvalidFilenameChars = new[] { '>', '<', '=', '?', ':', ';', '"', '*', '+', ',', '/', '\\', '|' };
        static readonly int[] kDataBlocksPerHashLevel = new int[] { 0xAA, 0x70E4, 0x4AF768 };

        public bool SkipHashChecks = false;

        bool contentIdValid = false;
        public bool ContentIdValid
        {
            get
            {
                return contentIdValid;
            }
        }

        public string MetadataString = string.Empty;

        Stream Stream;
        Object StreamLock = new object();

        public STF_VOLUME_DESCRIPTOR StfsVolumeDescriptor;

        // Position of start of this FS
        long Position = 0;

        public XCONTENT_HEADER Header;
        public XCONTENT_METADATA Metadata;
        public XCONTENT_METADATA_INSTALLER InstallerMetadata;

        PEC_HEADER PecHeader;
        bool IsXContent = false;

        XE_CONSOLE_SIGNATURE ConsoleSignature;
        bool IsConsoleSigned = false;

        // All files in the package
        public FileEntry[] Children;
        long BytesInUse = 0;

        // The earliest CreationTime in all the file entries
        DateTime CreationTime = DateTime.Now;

        // Values used in some block calculations, inited by StfsInit();
        long SizeOfHeaders = 0;
        int BlocksPerHashTable = 1;
        ulong[] StfsBlockStep = new[] { 0xABul, 0x718Ful };

        // Cached hash blocks
        public List<long> InvalidTables = new List<long>();
        public Dictionary<long, STF_HASH_BLOCK> CachedTables = new Dictionary<long, STF_HASH_BLOCK>();

        // Misc
        SHA1 Sha1 = SHA1.Create();

        byte[] headerSha1;

        public uint NumberOfBackingBlocks
        {
            get
            {
                ulong blockHashRemainder = (ulong)(StfsVolumeDescriptor.NumberOfTotalBlocks % kDataBlocksPerHashLevel[0]);

                ulong hashBlockBackingBlock = (ulong)StfsComputeLevelNBackingHashBlockNumber((int)StfsVolumeDescriptor.NumberOfTotalBlocks, 0);

                return (uint)(hashBlockBackingBlock + blockHashRemainder + 1);
            }
        }

        public StfsFileSystem(Stream stream, string inputPath, long partitionOffset = 0)
        {
            Stream = stream;
            Position = partitionOffset;
        }

        public static bool IsPackage(Stream stream)
        {
            stream.Position = 0;
            byte[] magic = new byte[4];
            stream.Read(magic, 0, 4);

            uint magic32 = BitConverter.ToUInt32(magic, 0).EndianSwap();
            return magic32 == XCONTENT_HEADER.kSignatureTypeConBE || magic32 == XCONTENT_HEADER.kSignatureTypeLiveBE || magic32 == XCONTENT_HEADER.kSignatureTypePirsBE;
        }

        public void StfsInit()
        {
            if (Position == 0)
                Position = Stream.Position;

            // Read in XContent/PEC header if the volume descriptor isn't already set:
            if (StfsVolumeDescriptor.DescriptorLength != 0x24)
            {
                Stream.Position = Position;
                PecHeader = Stream.ReadStruct<PEC_HEADER>();
                PecHeader.EndianSwap();
                if (PecHeader.ConsoleSignature.IsStructureValid)
                {
                    IsXContent = false;
                    IsConsoleSigned = true;
                    ConsoleSignature = PecHeader.ConsoleSignature;
                    StfsVolumeDescriptor = PecHeader.StfsVolumeDescriptor;
                }
                else
                {
                    IsXContent = true;
                    Stream.Seek(0, SeekOrigin.Begin);

                    Header = Stream.ReadStruct<XCONTENT_HEADER>();
                    Header.EndianSwap();

                    if (Header.SignatureType != XCONTENT_HEADER.kSignatureTypeConBE &&
                        Header.SignatureType != XCONTENT_HEADER.kSignatureTypeLiveBE &&
                        Header.SignatureType != XCONTENT_HEADER.kSignatureTypePirsBE)
                        throw new FileSystemParseException("File has invalid header magic");

                    if (Header.SizeOfHeaders == 0)
                        throw new FileSystemParseException("Package doesn't contain STFS filesystem");

                    if (Header.SignatureType == XCONTENT_HEADER.kSignatureTypeConBE)
                    {
                        IsConsoleSigned = true;
                        ConsoleSignature = Header.ConsoleSignature;
                    }

                    byte[] headerRaw = new byte[0x118];
                    Stream.Position = 0x22C;
                    Stream.Read(headerRaw, 0, 0x118);
                    headerSha1 = Sha1.ComputeHash(headerRaw);
                    
                    // TODO: check headerSha1 against package signature

                    var metadataEnd = (int)(Utility.RoundToPages(Header.SizeOfHeaders, kSectorSize) * kSectorSize);

                    byte[] metadataRaw = new byte[metadataEnd - 0x344];
                    Stream.Position = 0x344;
                    Stream.Read(metadataRaw, 0, metadataEnd - 0x344);

                    contentIdValid = Sha1.ComputeHash(metadataRaw).BytesMatch(Header.ContentId);

                    Stream.Position = 0x344;
                    Metadata = Stream.ReadStruct<XCONTENT_METADATA>();
                    Metadata.EndianSwap();

                    if (Header.SizeOfHeaders > 0x971A)
                    {
                        Stream.Position = 0x971A;
                        InstallerMetadata = Stream.ReadStruct<XCONTENT_METADATA_INSTALLER>();
                        InstallerMetadata.EndianSwap();
                    }

                    if (Metadata.VolumeType != 0)
                        throw new FileSystemParseException("Package contains unsupported SVOD filesystem");

                    StfsVolumeDescriptor = Metadata.StfsVolumeDescriptor;
                }

                if (StfsVolumeDescriptor.DescriptorLength != 0x24)
                    throw new FileSystemParseException("File has invalid descriptor length");
            }
            StfsInitValues();

            // Read in our directory entries...

            int directoryBlock = StfsVolumeDescriptor.DirectoryFirstBlockNumber;
            var entries = new List<FileEntry>();
            for (int i = 0; i < StfsVolumeDescriptor.DirectoryAllocationBlocks; i++)
            {
                if (directoryBlock == 0xFFFFFF)
                {
                    Console.WriteLine("Premature directory exit 1!!!");
                    break;
                }

                var directoryOffset = StfsDataBlockToOffset(directoryBlock);

                Stream.Position = directoryOffset;

                bool noMoreEntries = false;
                for (int ent = 0; ent < (0x1000 / 0x40); ent++)
                {
                    var entry = new FileEntry(this);
                    if (!entry.Read(Stream))
                    {
                        noMoreEntries = true;
                        break;
                    }

                    entry.DirectoryOffset = directoryOffset;

                    if (entry.CreationTime < CreationTime)
                        CreationTime = entry.CreationTime;

                    if (!entry.IsDirectory)
                        BytesInUse += entry.DirEntry.FileSize;

                    entries.Add(entry);
                }


                // Find next directory block...
                var blockHashEntry = StfsGetLevel0HashEntry(directoryBlock);
                directoryBlock = blockHashEntry.Level0NextBlock;

                if (noMoreEntries)
                {
                    if (i + 1 < StfsVolumeDescriptor.DirectoryAllocationBlocks)
                        Console.WriteLine("Premature directory exit 2!!!");
                    break;
                }
            }

            // Create metadata.ini/metadata_thumbnail/etc..
            MetadataString = InitMetadataFiles();

            // Connect entries up with their parents/children
            var rootEntries = new List<FileEntry>();
            for (int i = 0; i < entries.Count; i++)
            {
                var ent = entries[i];
                if (ent.DirEntry.DirectoryIndex == -1)
                    rootEntries.Add(ent);

                if (!ent.IsDirectory)
                    continue;

                var children = new List<FileEntry>();
                foreach (var ent2 in entries)
                    if (ent2.DirEntry.DirectoryIndex == i)
                    {
                        children.Add(ent2);
                        ent2.Parent = ent;
                    }

                children.Sort((x, y) => x.Name.CompareTo(y.Name));
                ent.Children = children;
            }

            // Make sure to sort so that ReadDirectoryEntry doesn't make windows loop forever...
            rootEntries.Sort((x, y) => x.Name.CompareTo(y.Name));

            Children = entries.ToArray();
        }

        // Creates some fake metadata entries at root of FS
        string InitMetadataFiles()
        {
            var curTime = DateTime.Now;

            var writer = new StringBuilder();
            if (IsConsoleSigned)
            {
                writer.AppendLine("[ConsoleSignature]");
                writer.AppendLine($"ConsoleId = {BitConverter.ToString(ConsoleSignature.Cert.ConsoleId)}");
                writer.AppendLine($"ConsolePartNumber = {ConsoleSignature.Cert.ConsolePartNumber}");
                writer.AppendLine($"Privileges = 0x{ConsoleSignature.Cert.Privileges:X}");
                writer.AppendLine($"ConsoleType = 0x{ConsoleSignature.Cert.ConsoleType:X8} ({ConsoleSignature.Cert.ConsoleTypeString})");
                writer.AppendLine($"ManufacturingDate = {ConsoleSignature.Cert.ManufacturingDate}");

                writer.AppendLine();
            }
            if (IsXContent)
            {
                writer.AppendLine("[ExecutionId]");

                if (Metadata.ExecutionId.MediaId != 0)
                    writer.AppendLine($"MediaId = 0x{Metadata.ExecutionId.MediaId:X8}");
                if (Metadata.ExecutionId.Version.IsValid)
                    writer.AppendLine($"Version = v{Metadata.ExecutionId.Version}");
                if (Metadata.ExecutionId.BaseVersion.IsValid)
                    writer.AppendLine($"BaseVersion = v{Metadata.ExecutionId.BaseVersion}");
                if (Metadata.ExecutionId.TitleId != 0)
                    writer.AppendLine($"TitleId = 0x{Metadata.ExecutionId.TitleId:X8}");
                writer.AppendLine($"Platform = {Metadata.ExecutionId.Platform}");
                writer.AppendLine($"ExecutableType = {Metadata.ExecutionId.ExecutableType}");
                writer.AppendLine($"DiscNum = {Metadata.ExecutionId.DiscNum}");
                writer.AppendLine($"DiscsInSet = {Metadata.ExecutionId.DiscsInSet}");
                if (Metadata.ExecutionId.SaveGameId != 0)
                    writer.AppendLine($"SaveGameId = 0x{Metadata.ExecutionId.SaveGameId:X8}");

                writer.AppendLine();
                writer.AppendLine("[XContentHeader]");
                writer.AppendLine($"SignatureType = {Header.SignatureTypeString}");
                writer.AppendLine($"ContentId = {BitConverter.ToString(Header.ContentId)}");
                writer.AppendLine($"SizeOfHeaders = 0x{Header.SizeOfHeaders:X}");

                for (int i = 0; i < Header.LicenseDescriptors.Length; i++)
                {
                    var license = Header.LicenseDescriptors[i];
                    if (!license.IsValid)
                        continue;

                    writer.AppendLine();
                    writer.AppendLine($"[XContentLicensee{i}]");
                    writer.AppendLine($"LicenseeId = 0x{license.LicenseeId:X16} ({license.LicenseType})");
                    writer.AppendLine($"LicenseBits = 0x{license.LicenseBits:X8}");
                    writer.AppendLine($"LicenseFlags = 0x{license.LicenseFlags:X8}");
                }

                writer.AppendLine();
                writer.AppendLine("[XContentMetadata]");
                writer.AppendLine($"ContentType = 0x{Metadata.ContentType:X8}");
                writer.AppendLine($"ContentMetadataVersion = {Metadata.ContentMetadataVersion}");
                writer.AppendLine($"ContentSize = 0x{Metadata.ContentSize:X}");
                if (!Metadata.ConsoleId.IsNull())
                    writer.AppendLine($"ConsoleId = {BitConverter.ToString(Metadata.ConsoleId)}");
                if (Metadata.Creator != 0)
                    writer.AppendLine($"Creator = 0x{Metadata.Creator:X16}");
                if (Metadata.OnlineCreator != 0)
                    writer.AppendLine($"OnlineCreator = 0x{Metadata.OnlineCreator:X16}");
                if (Metadata.Category != 0)
                    writer.AppendLine($"Category = {Metadata.Category}");
                if (!Metadata.DeviceId.IsNull())
                    writer.AppendLine($"DeviceId = {BitConverter.ToString(Metadata.DeviceId)}");

                for (int i = 0; i < 9; i++)
                    if (!string.IsNullOrEmpty(Metadata.DisplayName[i].String))
                        writer.AppendLine($"DisplayName[{Utility.XboxLanguages[i]}] = {Metadata.DisplayName[i].String}");
                if (Metadata.ContentMetadataVersion >= 2)
                    for (int i = 0; i < 3; i++)
                        if (!string.IsNullOrEmpty(Metadata.DisplayNameEx[i].String))
                            writer.AppendLine($"DisplayNameEx[{Utility.XboxLanguages[i + 9]}] = {Metadata.DisplayNameEx[i].String}");
                for (int i = 0; i < 9; i++)
                    if (!string.IsNullOrEmpty(Metadata.Description[i].String))
                        writer.AppendLine($"Description[{Utility.XboxLanguages[i]}] = {Metadata.Description[i].String}");
                if (Metadata.ContentMetadataVersion >= 2)
                    for (int i = 0; i < 3; i++)
                        if (!string.IsNullOrEmpty(Metadata.DescriptionEx[i].String))
                            writer.AppendLine($"DescriptionEx[{Utility.XboxLanguages[i + 9]}] = {Metadata.DescriptionEx[i].String}");

                if (!string.IsNullOrEmpty(Metadata.Publisher.String))
                    writer.AppendLine($"Publisher = {Metadata.Publisher.String}");
                if (!string.IsNullOrEmpty(Metadata.TitleName.String))
                    writer.AppendLine($"TitleName = {Metadata.TitleName.String}");

                if (Metadata.FlagsAsBYTE != 0)
                    writer.AppendLine($"Flags = 0x{Metadata.FlagsAsBYTE:X2}");

                writer.AppendLine($"ThumbnailSize = 0x{Metadata.ThumbnailSize:X}");
                writer.AppendLine($"TitleThumbnailSize = 0x{Metadata.TitleThumbnailSize:X}");

                if (InstallerMetadata.IsValid)
                {
                    writer.AppendLine();
                    writer.AppendLine("[XContentMetadataInstaller]");

                    string type = "";
                    if (InstallerMetadata.IsSystemUpdate)
                        type = " (SystemUpdate)";
                    else if (InstallerMetadata.IsTitleUpdate)
                        type = " (TitleUpdate)";
                    writer.AppendLine($"MetaDataType = 0x{InstallerMetadata.MetaDataType:X8}{type}");

                    if (InstallerMetadata.CurrentVersion.IsValid)
                        writer.AppendLine($"CurrentVersion = v{InstallerMetadata.CurrentVersion}");
                    if (InstallerMetadata.NewVersion.IsValid)
                        writer.AppendLine($"NewVersion = v{InstallerMetadata.NewVersion}");
                }
            }
            else
            {
                if (PecHeader.ContentId != null)
                {
                    writer.AppendLine("[PECHeader]");
                    writer.AppendLine($"ContentId = {BitConverter.ToString(PecHeader.ContentId)}");
                    if (PecHeader.Unknown != 0)
                        writer.AppendLine($"Unknown = 0x{PecHeader.Unknown:X16}");
                    if (PecHeader.Unknown2 != 0)
                        writer.AppendLine($"Unknown2 = 0x{PecHeader.Unknown2:X8}");
                    if (PecHeader.Creator != 0)
                        writer.AppendLine($"Creator = 0x{PecHeader.Creator:X16}");
                    if (PecHeader.ConsoleIdsCount != 0)
                        writer.AppendLine($"ConsoleIdsCount = {PecHeader.ConsoleIdsCount}");
                    for (int i = 0; i < 100; i++)
                        if (!PecHeader.ConsoleIds[i].Bytes.IsNull())
                            writer.AppendLine($"ConsoleId[{i}] = {BitConverter.ToString(PecHeader.ConsoleIds[i].Bytes)}");
                }
            }

            writer.AppendLine();
            writer.AppendLine("[VolumeDescriptor]");
            string volumeType = (!IsXContent || Metadata.VolumeType == 0) ? "STFS" : "SVOD";
            if (IsXContent)
            {
                writer.AppendLine($"VolumeType = {Metadata.VolumeType} ({volumeType})");
                if (Metadata.DataFiles != 0)
                    writer.AppendLine($"DataFiles = {Metadata.DataFiles}");
                if (Metadata.DataFilesSize != 0)
                    writer.AppendLine($"DataFilesSize = 0x{Metadata.DataFilesSize:X}");
            }
            if (!IsXContent || Metadata.VolumeType == 0)
            {
                string flags = "";
                if (StfsVolumeDescriptor.ReadOnlyFormat)
                    flags += "(ReadOnlyFormat) ";
                if (StfsVolumeDescriptor.RootActiveIndex)
                    flags += "(RootActiveIndex) ";
                writer.AppendLine($"Stfs.DescriptorLength = 0x{StfsVolumeDescriptor.DescriptorLength:X}");
                writer.AppendLine($"Stfs.Version = {StfsVolumeDescriptor.Version}");
                writer.AppendLine($"Stfs.Flags = {StfsVolumeDescriptor.Flags} {flags}");
                writer.AppendLine($"Stfs.DirectoryAllocationBlocks = 0x{StfsVolumeDescriptor.DirectoryAllocationBlocks:X}");
                writer.AppendLine($"Stfs.DirectoryFirstBlockNumber = 0x{StfsVolumeDescriptor.DirectoryFirstBlockNumber:X}");
                writer.AppendLine($"Stfs.RootHash = {BitConverter.ToString(StfsVolumeDescriptor.RootHash)}");
                writer.AppendLine($"Stfs.NumberOfTotalBlocks = 0x{StfsVolumeDescriptor.NumberOfTotalBlocks:X}");
                writer.AppendLine($"Stfs.NumberOfFreeBlocks = 0x{StfsVolumeDescriptor.NumberOfFreeBlocks:X}");
            }

            return writer.ToString();
        }

        // Precalculates some things
        void StfsInitValues()
        {
            if (IsXContent)
                SizeOfHeaders = ((Header.SizeOfHeaders + kSectorSize - 1) / kSectorSize) * kSectorSize;
            else
                SizeOfHeaders = 0x1000; // PEC

            BlocksPerHashTable = 1;
            StfsBlockStep[0] = 0xAB;
            StfsBlockStep[1] = 0x718F;
            if (!StfsVolumeDescriptor.ReadOnlyFormat)
            {
                BlocksPerHashTable = 2;
                StfsBlockStep[0] = 0xAC;
                StfsBlockStep[1] = 0x723A;
            }
        }

        int StfsComputeBackingDataBlockNumber(int BlockNumber)
        {
            int blockBase = 0xAA;
            int block = BlockNumber;

            for (int i = 0; i < 3; i++)
            {
                block += BlocksPerHashTable * ((BlockNumber + blockBase) / blockBase);
                if (BlockNumber < blockBase)
                    break;

                blockBase *= 0xAA;
            }

            return block;
        }

        int StfsComputeLevelNBackingHashBlockNumber(int blockNum, int level)
        {
            ulong blockNum64 = (ulong)blockNum;
            ulong num = 0;
            if (level == 0)
            {
                num = (blockNum64 / 0xAA) * StfsBlockStep[0];
                if (blockNum / 0xAA == 0)
                    return (int)num;

                num = num + ((blockNum64 / 0x70E4) + 1) * (ulong)BlocksPerHashTable;
                if (blockNum / 0x70E4 == 0)
                    return (int)num;
            }
            else if (level == 1)
            {
                num = (blockNum64 / 0x70E4) * StfsBlockStep[1];
                if (blockNum64 / 0x70E4 == 0)
                    return (int)num + (int)StfsBlockStep[0];
            }
            else
            {
                return (int)StfsBlockStep[1];
            }
            return (int)num + BlocksPerHashTable;
        }

        public long StfsBackingBlockToOffset(long BlockNumber)
        {
            ulong blockNum64 = (ulong)BlockNumber;
            return (long)((ulong)Position + (ulong)SizeOfHeaders + (blockNum64 * 0x1000ul));
        }

        public long StfsDataBlockToOffset(int BlockNumber)
        {
            return StfsBackingBlockToOffset(StfsComputeBackingDataBlockNumber(BlockNumber));
        }

        STF_HASH_ENTRY StfsGetLevelNHashEntry(int BlockNumber, int Level, ref byte[] ExpectedHash, bool UseSecondaryBlock)
        {
            int record = BlockNumber;
            if (Level > 0)
                record /= kDataBlocksPerHashLevel[Level - 1];

            record %= kDataBlocksPerHashLevel[0];

            if(BlockNumber == 0x0007f404 && Level == 0)
            {
                record = record;
            }

            var backingBlock = StfsComputeLevelNBackingHashBlockNumber(BlockNumber, Level);
            long hashOffset = StfsBackingBlockToOffset(backingBlock);

            if (UseSecondaryBlock && !StfsVolumeDescriptor.ReadOnlyFormat)
                hashOffset += kSectorSize;

            bool isInvalidTable = InvalidTables.Contains(hashOffset);
            if (!CachedTables.ContainsKey(hashOffset))
            {
                // Cache the table in memory, since it's likely to be needed again
                byte[] block = new byte[kSectorSize];
                if (Stream.Length > hashOffset)
                {
                    lock (StreamLock)
                    {
                        Stream.Seek(hashOffset, SeekOrigin.Begin);
                        Stream.Read(block, 0, (int)kSectorSize);
                    }
                }

                var hashBlock = Utility.BytesToStruct<STF_HASH_BLOCK>(block);
                hashBlock.EndianSwap();
                CachedTables.Add(hashOffset, hashBlock);

                if (!isInvalidTable)
                {
                    if (hashOffset >= Stream.Length)
                    {
                        // hash offset outside file...
                        isInvalidTable = true;
                        InvalidTables.Add(hashOffset);
                    }
                    else if (!SkipHashChecks)
                    {
                        // It's not cached and not in the invalid table array yet... lets check it
                        byte[] hash;
                        lock (Sha1)
                            hash = Sha1.ComputeHash(block);

                        if (!hash.BytesMatch(ExpectedHash))
                        {
                            isInvalidTable = true;
                            InvalidTables.Add(hashOffset);
                            //Console.WriteLine($"Invalid hash table at 0x{hashOffset:X}!");
                        }
                    }
                }
            }

            if (isInvalidTable)
            {
                // If table is corrupt there's no use reading invalid data
                // Lets try salvaging things by providing next block as block + 1
                // (Should work fine for LIVE/PIRS packages hopefully)
                var entry2 = new STF_HASH_ENTRY();
                entry2.Level0NextBlock = BlockNumber + 1;
                return entry2;
            }

            var table = CachedTables[hashOffset];
            var entry = table.Entries[record];
            // Copy hash from entry into hash parameter...
            Array.Copy(entry.Hash, 0, ExpectedHash, 0, 0x14);
            return table.Entries[record];
        }

        public STF_HASH_ENTRY StfsGetLevel0HashEntry(int BlockNumber)
        {
            bool useSecondaryBlock = false;
            // Use secondary block for root table if RootActiveIndex flag is set
            if (StfsVolumeDescriptor.RootActiveIndex)
                useSecondaryBlock = true;

            byte[] hash = new byte[0x14];
            Array.Copy(StfsVolumeDescriptor.RootHash, 0, hash, 0, 0x14);

            uint numBlocks = StfsVolumeDescriptor.NumberOfTotalBlocks;
            if (numBlocks > kDataBlocksPerHashLevel[1])
            {
                // Get the L2 entry for this block
                var l2_entry = StfsGetLevelNHashEntry(BlockNumber, 2, ref hash, useSecondaryBlock);
                useSecondaryBlock = l2_entry.LevelNActiveIndex;
            }

            if (numBlocks > kDataBlocksPerHashLevel[0])
            {
                // Get the L1 entry for this block
                var l1_entry = StfsGetLevelNHashEntry(BlockNumber, 1, ref hash, useSecondaryBlock);
                useSecondaryBlock = l1_entry.LevelNActiveIndex;
            }

            return StfsGetLevelNHashEntry(BlockNumber, 0, ref hash, useSecondaryBlock);
        }

        public int[] StfsGetDataBlockChain(int BlockNumber, int limit = -1)
        {
            var blockList = new List<int>();
            while (BlockNumber != 0xFFFFFF)
            {
                if (limit != -1 && blockList.Count > limit)
                    break;

                blockList.Add(BlockNumber);
                var hashEntry = StfsGetLevel0HashEntry(BlockNumber);
                BlockNumber = hashEntry.Level0NextBlock;
            }
            return blockList.ToArray();
        }

        // Info about a file stored inside the STFS image
        public class FileEntry
        {
            public long DirectoryOffset;

            StfsFileSystem FileSystem;
            public STF_DIRECTORY_ENTRY DirEntry;

            internal int[] BlockChain; // Chain gets read in once a FileDesc is created for the entry
            public Stream FakeData; // Allows us to inject custom data into the filesystem, eg. for a fake metadata.ini file.

            public string Name
            {
                get
                {
                    return DirEntry.FileName;
                }
                set { throw new NotImplementedException(); }
            }

            public ulong Size
            {
                get
                {
                    return DirEntry.FileSize;
                }
                set { throw new NotImplementedException(); }
            }

            public bool IsDirectory
            {
                get
                {
                    return DirEntry.IsDirectory;
                }
                set { throw new NotImplementedException(); }
            }

            public DateTime CreationTime
            {
                get
                {
                    return DirEntry.CreationTime;
                }
                set
                {
                    DirEntry.CreationTime = value;
                }
            }

            public DateTime LastWriteTime
            {
                get
                {
                    return DirEntry.LastWriteTime;
                }
                set
                {
                    DirEntry.LastWriteTime = value;
                }
            }

            public DateTime LastAccessTime
            {
                get
                {
                    return LastWriteTime;
                }
                set { throw new NotImplementedException(); }
            }

            public List<FileEntry> Children { get; set; }
            public FileEntry Parent { get; set; }

            public FileEntry(StfsFileSystem fileSystem)
            {
                FileSystem = fileSystem;
            }

            public bool Read(Stream stream)
            {
                DirEntry = stream.ReadStruct<STF_DIRECTORY_ENTRY>();
                DirEntry.EndianSwap();
                return DirEntry.IsValid;
            }

            public string FilePath
            {
                get
                {
                    if (Parent == null)
                        return DirEntry.FileName;
                    else
                        return Path.Combine(Parent.FilePath, DirEntry.FileName);
                }
            }

            public override string ToString()
            {
                return $"{DirEntry.FileName}" + (Children != null ? $" ({Children.Count} children)" : "");
            }

            public uint ReadBytes(IntPtr buffer, ulong fileOffset, uint length)
            {
                if (fileOffset >= Size)
                    return 0;

                if (fileOffset + length >= Size)
                    length = (uint)(Size - fileOffset);

                if (FakeData != null)
                {
                    byte[] bytes2 = new byte[length];
                    int read = 0;
                    lock (FakeData)
                    {
                        FakeData.Seek((long)fileOffset, SeekOrigin.Begin);
                        read = FakeData.Read(bytes2, 0, bytes2.Length);
                    }
                    Marshal.Copy(bytes2, 0, buffer, read);
                    return (uint)read;
                }

                // Lock so that two threads can't try updating chain at once...
                lock (this)
                    if (BlockChain == null)
                        BlockChain = FileSystem.StfsGetDataBlockChain(DirEntry.FirstBlockNumber);

                uint chainNum = (uint)(fileOffset / kSectorSize);
                uint blockOffset = (uint)(fileOffset % kSectorSize);

                uint blockRemaining = kSectorSize - blockOffset;
                uint lengthRemaining = length;
                uint transferred = 0;

                byte[] bytes = new byte[kSectorSize];
                while (lengthRemaining > 0)
                {
                    var blockNum = BlockChain[chainNum];

                    uint toRead = blockRemaining;
                    if (toRead > lengthRemaining)
                        toRead = lengthRemaining;

                    int read = 0;
                    lock (FileSystem.StreamLock)
                    {
                        FileSystem.Stream.Seek((long)FileSystem.StfsDataBlockToOffset(blockNum) + blockOffset, SeekOrigin.Begin);
                        read = FileSystem.Stream.Read(bytes, 0, (int)toRead);
                    }

                    Marshal.Copy(bytes, 0, buffer, read);
                    transferred += (uint)read;

                    if (blockOffset + read >= kSectorSize)
                        chainNum++;

                    buffer += read;
                    blockRemaining = kSectorSize;
                    blockOffset = 0;
                    lengthRemaining -= (uint)read;
                }
                return transferred;
            }
        }
    }
}
