using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace STFSChk
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("STFS filesystem checker/verifier 0.3, by emoose");
            Console.WriteLine();
            if (args.Length <= 0)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("  stfschk.exe [-h] <path\\to\\package.file>");
                Console.WriteLine("-h flag will include STFS headers in summary");
                Console.WriteLine();
                Console.WriteLine("Batch mode:");
                Console.WriteLine("  stfschk.exe [-h] <path\\to\\folder>");
                Console.WriteLine();
                Console.WriteLine("Batch mode checks all packages in a folder, creating a <filename>.bad file for packages detected as bad");
                Console.WriteLine("The .bad file contains info about why the file was marked as bad");
                Console.WriteLine("Only files with valid XContent magic signature CON/LIVE/PIRS are checked when using batch mode");
                return;
            }

            bool printHeaders = false;
            string filePath = string.Empty;
            foreach (var arg in args)
            {
                if (arg == "-h")
                    printHeaders = true;
                else
                    filePath = arg;
            }

            if(!File.Exists(filePath) && !Directory.Exists(filePath))
            {
                Console.WriteLine($"Invalid path {filePath}!");
                return;
            }

            if (!Directory.Exists(filePath))
            {
                var consoleWriter = new StreamWriter(Console.OpenStandardOutput());
                consoleWriter.AutoFlush = true;

                var result = ProcessFile(filePath, printHeaders, consoleWriter);
                Console.WriteLine();

                if (result)
                    Console.WriteLine("No major errors detected.");
                else
                    Console.WriteLine("Errors found, file may be invalid!");

                Console.WriteLine();
                Console.WriteLine("Press any key to exit...");
                Console.ReadLine();
            }
            else
            {
                ProcessDir(filePath, printHeaders);
            }
        }

        static void ProcessDir(string dirPath, bool printHeaders)
        {
            foreach (var dir in Directory.GetDirectories(dirPath))
                ProcessDir(dir, printHeaders);

            foreach (var file in Directory.GetFiles(dirPath))
            {
                var mem = new MemoryStream();
                var sw = new StreamWriter(mem);

                bool result = ProcessFile(file, printHeaders, sw);
                if(!result)
                {
                    string info = System.Text.Encoding.UTF8.GetString(mem.ToArray());
                    if(!string.IsNullOrEmpty(info))
                        File.WriteAllText(file + ".bad", info);
                }
            }
        }

        static bool ProcessFile(string filePath, bool printHeaders, StreamWriter infoWriter = null)
        {
            var fileStream = File.OpenRead(filePath);
            if (!StfsFileSystem.IsPackage(fileStream))
                return false;

            Console.WriteLine("Checking file " + filePath);
            Console.WriteLine();

            fileStream.Position = 0;
            var file = new StfsFileSystem(fileStream, filePath);
            try
            {
                file.StfsInit();
            }
            catch (FileSystemParseException e)
            {
                if (infoWriter != null)
                    infoWriter.WriteLine("FileSystemParseException: " + e.Message);

                return false;
            }
            catch (IOException e)
            {
                if (infoWriter != null)
                    infoWriter.WriteLine("IOException: " + e.Message);

                return false;
            }

            bool isLivePirs = file.Header.SignatureType == XCONTENT_HEADER.kSignatureTypeLiveBE || file.Header.SignatureType == XCONTENT_HEADER.kSignatureTypePirsBE;
            long fileExpectedSize = file.StfsBackingBlockToOffset(file.NumberOfBackingBlocks);
            var signer = file.Signer;

            if (infoWriter != null)
            {
                if (printHeaders)
                {
                    infoWriter.Write(file.MetadataString);
                    infoWriter.WriteLine($"Stfs.NumberOfBackingBlocks = 0x{file.NumberOfBackingBlocks:X}");
                    infoWriter.WriteLine();
                }
                infoWriter.WriteLine($"File Count: {file.Children.Length}");
                infoWriter.WriteLine($"Block Count: {file.StfsVolumeDescriptor.NumberOfTotalBlocks}");
                infoWriter.WriteLine($"Verifying hash tables...");
            }

            // Go through all blocks and request the hash entry of it, this will in turn check the L2 hash against the RootHash, the L1 hash against the L2 hash-value, and the L0 hash against the L1 hash-value
            // After this we'll then check the data hash against the L0 hash-value
            var hashEntries = new List<STF_HASH_ENTRY>();
            for(int i = 0; i < file.StfsVolumeDescriptor.NumberOfTotalBlocks; i++)
            {
                var entry = file.StfsGetLevel0HashEntry(i);
                hashEntries.Add(entry);
            }

            if (infoWriter != null)
            {
                if (file.InvalidTables.Count > 0)
                {
                    infoWriter.WriteLine();
                    infoWriter.WriteLine($"Detected {file.InvalidTables.Count} invalid hash tables:");
                    foreach (var offset in file.InvalidTables)
                        infoWriter.WriteLine($"  0x{offset:X}");
                }

                infoWriter.WriteLine();
                infoWriter.WriteLine("Verifying data hashes...");
            }

            // Now check data hashes!
            var sha = System.Security.Cryptography.SHA1.Create();
            byte[] data = new byte[0x1000];
            var invalidHashes = new Dictionary<long, Tuple<int, STF_HASH_ENTRY, byte[]>>();
            var invalidBlocks = new List<int>();
            int freeBlockCount = 0;
            for (int i = 0; i < file.StfsVolumeDescriptor.NumberOfTotalBlocks; i++)
            {
                var offset = file.StfsDataBlockToOffset(i);
                var hashEntry = hashEntries[i];

                if (offset >= fileStream.Length || (offset + 0x1000) > fileStream.Length)
                {
                    invalidBlocks.Add(i);
                    continue;
                }
                if (hashEntry.Hash == null)
                    continue; // Bad hash block :(
                if (hashEntry.Flags == 0)
                {
                    // Free block, hash doesn't matter
                    freeBlockCount++;
                    continue;
                }

                fileStream.Position = offset;
                fileStream.Read(data, 0, 0x1000);
                byte[] hash = sha.ComputeHash(data);
                if (!hash.BytesMatch(hashEntry.Hash))
                    invalidHashes.Add(offset, new Tuple<int,STF_HASH_ENTRY,byte[]>(i, hashEntry, hash));
            }

            if (infoWriter != null)
            {
                if (invalidHashes.Count > 0)
                {
                    infoWriter.WriteLine();
                    infoWriter.WriteLine($"Detected {invalidHashes.Count} invalid data blocks:");
                    foreach (var offset in invalidHashes)
                    {
                        infoWriter.WriteLine($"  0x{offset.Key:X} (block 0x{offset.Value.Item1:X})");
                        infoWriter.WriteLine($"    Expected hash: {BitConverter.ToString(offset.Value.Item2.Hash).Replace("-", "")}");
                        infoWriter.WriteLine($"      Actual hash: {BitConverter.ToString(offset.Value.Item3).Replace("-", "")}");
                        infoWriter.WriteLine($"      Entry flags: {offset.Value.Item2.Flags:X}");
                    }
                }

                infoWriter.WriteLine();
                infoWriter.WriteLine("Verifying directory entries...");
            }

            int directoryBlock = file.StfsVolumeDescriptor.DirectoryFirstBlockNumber;
            var entries = new List<STFSChk.StfsFileSystem.FileEntry>();
            for (int i = 0; i < file.StfsVolumeDescriptor.DirectoryAllocationBlocks; i++)
            {
                if (directoryBlock == 0xFFFFFF)
                    break;

                var directoryOffset = file.StfsDataBlockToOffset(directoryBlock);

                string valid = "(valid)";
                if (invalidHashes.ContainsKey(directoryOffset))
                    valid = "(invalid)";

                if (infoWriter != null)
                    infoWriter.WriteLine($"  Directory #{i}\tblock 0x{directoryBlock}\t{valid}");

                var blockHashEntry = file.StfsGetLevel0HashEntry(directoryBlock);
                directoryBlock = blockHashEntry.Level0NextBlock;
            }

            // Verify block-chains of files
            // Block chain length should be equal to the files allocated block count, which should be equal to the FileSize in STFS blocks (/0x1000)
            var notifiedDirBlocks = new List<long>();
            int numInvalidEntries = 0;
            foreach (var entry in file.Children)
            {
                if (entry.IsDirectory)
                    continue;

                if (infoWriter != null)
                    infoWriter.WriteLine($"  {entry.FilePath}\t{entry.Size} bytes\tstart block 0x{entry.DirEntry.FirstBlockNumber:X}");

                bool thisIsValid = true;
                if (invalidHashes.ContainsKey(entry.DirectoryOffset))
                {
                    thisIsValid = false; // hash of directory block is invalid, so this entry is probably invalid too
                    if (infoWriter != null)
                    {
                        if(!notifiedDirBlocks.Contains(entry.DirectoryOffset))
                        {
                            infoWriter.WriteLine($"  ^ is inside invalid (bad hash) directory block! (0x{entry.DirectoryOffset:X})");
                            notifiedDirBlocks.Add(entry.DirectoryOffset);
                        }
                    }
                }

                var numBlocks = Utility.RoundToPages(entry.Size, StfsFileSystem.kSectorSize);
                if (numBlocks != (ulong)entry.DirEntry.AllocationBlocks)
                {
                    thisIsValid = false;
                    if (infoWriter != null)
                        infoWriter.WriteLine($"  ^ has invalid NumAllocationBlocks! (value 0x{entry.DirEntry.AllocationBlocks:X}, expected 0x{numBlocks:X}{Environment.NewLine})");
                }
                if (numBlocks != (ulong)entry.DirEntry.ValidDataBlocks)
                {
                    if (isLivePirs)
                        thisIsValid = false; // only count as invalid if this is LIVE/PIRS, since CON can use weird values here?

                    if (infoWriter != null)
                        infoWriter.WriteLine($"  ^ has invalid NumValidDataBlocks! (value 0x{entry.DirEntry.ValidDataBlocks:X}, expected 0x{numBlocks:X}{Environment.NewLine})");
                }

                if (entry.DirEntry.FirstBlockNumber >= file.StfsVolumeDescriptor.NumberOfTotalBlocks)
                {
                    thisIsValid = false;
                    if (infoWriter != null)
                        infoWriter.WriteLine($"  ^ FirstBlockNumber 0x{entry.DirEntry.FirstBlockNumber:X} out-of-range! (max block number: 0x{file.StfsVolumeDescriptor.NumberOfTotalBlocks:X})");
                }
                else
                {
                    int[] blockChain = null;
                    try
                    {
                        blockChain = file.StfsGetDataBlockChain(entry.DirEntry.FirstBlockNumber, (int)(numBlocks + 10));
                    }
                    catch (IOException)
                    {
                        thisIsValid = false;
                        if (infoWriter != null)
                            infoWriter.WriteLine($"  ^ failed to read complete block chain!");
                    }

                    if (blockChain != null)
                    {
                        if (numBlocks != (ulong)blockChain.Length)
                        {
                            thisIsValid = false;
                            if (infoWriter != null)
                                infoWriter.WriteLine($"  ^ has invalid block chain length! (length {blockChain.Length} blocks, expected {numBlocks})");
                        }

                        // Check blockChain values
                        for (int i = 0; i < blockChain.Length; i++)
                        {
                            var blockNum = blockChain[i];
                            if (blockNum >= file.StfsVolumeDescriptor.NumberOfTotalBlocks)
                            {
                                thisIsValid = false;
                                if (infoWriter != null)
                                    infoWriter.WriteLine($"  ^ block-chain contains out-of-range block 0x{blockNum:X}! (max block number: 0x{file.StfsVolumeDescriptor.NumberOfTotalBlocks:X})");
                                break;
                            }
                        }
                    }
                }

                if (!thisIsValid)
                    numInvalidEntries++;
            }

            int expectedFreeBlocks = freeBlockCount;
            bool expectedReadOnlyFormat = false;
            uint expectedHeaderSize = 0x971A; // CON SizeOfHeaders

            if (isLivePirs)
            {
                expectedReadOnlyFormat = true;
                expectedHeaderSize = 0xAD0E; // LIVE/PIRS SizeOfHeaders (larger size for the XCONTENT_METADATA_INSTALLER data?)
                expectedFreeBlocks = 0;
            }

            if (infoWriter != null)
            {
                infoWriter.WriteLine();
                infoWriter.WriteLine($"Summary (invalid/total):");

                // Header checks
                {
                    var addStr = "";
                    if (signer.Contains("invalid"))
                        addStr = $" (expected valid {file.Header.SignatureTypeString} signature)";
                    infoWriter.WriteLine($"  Header signature: {signer}" + addStr);
                }

                // Metadata checks
                {
                    infoWriter.WriteLine($"  Metadata hash: {(file.ContentIdValid ? "valid" : "invalid")}");

                    var contentSizeExpected = fileExpectedSize - 0xB000;
                    var contentSizeDifference = (long)file.Metadata.ContentSize - contentSizeExpected;
                    if (contentSizeDifference != 0)
                        infoWriter.WriteLine($"  Metadata.ContentSize: 0x{file.Metadata.ContentSize:X} (expected 0x{contentSizeExpected:X}, {contentSizeDifference} bytes difference)");

                    if (file.Metadata.ContentMetadataVersion > 2)
                        infoWriter.WriteLine($"  Metadata.ContentMetadataVersion: {file.Metadata.ContentMetadataVersion:X} (expected 0, 1 or 2)");
                }

                // Header & Volume Descriptor checks
                {
                    if (file.StfsVolumeDescriptor.ReadOnlyFormat != expectedReadOnlyFormat)
                        infoWriter.WriteLine($"  StfsVolumeDescriptor.ReadOnlyFormat: {file.StfsVolumeDescriptor.ReadOnlyFormat} (expected {expectedReadOnlyFormat} for {file.Header.SignatureTypeString} package!)");

                    if (file.StfsVolumeDescriptor.NumberOfFreeBlocks != expectedFreeBlocks)
                        infoWriter.WriteLine($"  StfsVolumeDescriptor.NumberOfFreeBlocks: {file.StfsVolumeDescriptor.NumberOfFreeBlocks} (expected {expectedFreeBlocks})");

                    if (file.Header.SizeOfHeaders != expectedHeaderSize)
                        infoWriter.WriteLine($"  Header.SizeOfHeaders: 0x{file.Header.SizeOfHeaders:X} (expected 0x{expectedHeaderSize:X} for {file.Header.SignatureTypeString} package!)");

                    // not checking file.StfsVolumeDescriptor.DescriptorLength here as that was already checked inside StfsInit
                }

                // Directory checks
                {
                    // TODO: check that the directory block count is sane (directory should contain at least ((blockCount - 1) * 64) children)
                    // uint minDirectoryEntries = (file.StfsVolumeDescriptor.DirectoryAllocationBlocks - 1u) * 64;
                    // if(minDirectoryEntries > file.Children.Length)

                    // Check that the chain-size of directory blocks == size inside volume descriptor
                    var directoryChain = file.StfsGetDataBlockChain(file.StfsVolumeDescriptor.DirectoryFirstBlockNumber, file.StfsVolumeDescriptor.DirectoryAllocationBlocks + 10);
                    if (directoryChain.Length != file.StfsVolumeDescriptor.DirectoryAllocationBlocks)
                        infoWriter.WriteLine($"  DirectoryChain.Length: {directoryChain.Length} (expected {file.StfsVolumeDescriptor.DirectoryAllocationBlocks})");
                }

                // Hash/block checks
                {
                    infoWriter.WriteLine($"  Hash tables: {file.InvalidTables.Count}/{file.CachedTables.Count}");

                    var addStr = "";
                    if (file.InvalidTables.Count > 0)
                        addStr = " (bad hash tables prevents checking data blocks, the invalid count may be higher!)";

                    infoWriter.WriteLine($"  Data blocks: {invalidHashes.Count}/{file.StfsVolumeDescriptor.NumberOfTotalBlocks}" + addStr);
                    infoWriter.WriteLine($"  Directory entries: {numInvalidEntries}/{file.Children.Length}");
                    infoWriter.WriteLine($"  Missing blocks: {invalidBlocks.Count}/{file.StfsVolumeDescriptor.NumberOfTotalBlocks}");
                }

                // Size checks
                {
                    var sizeDifference = fileStream.Length - fileExpectedSize;
                    if (sizeDifference != 0)
                        infoWriter.WriteLine($"  Package size: 0x{fileStream.Length:X} (expected 0x{fileExpectedSize:X})");
                    else
                        infoWriter.WriteLine($"  Package size: 0x{fileExpectedSize:X}");

                    if (fileStream.Length < fileExpectedSize)
                        infoWriter.WriteLine($"    (file truncated by {-(fileStream.Length - fileExpectedSize)} bytes, too small to hold {file.NumberOfBackingBlocks} backing blocks)");
                    else if (fileStream.Length > fileExpectedSize)
                        infoWriter.WriteLine($"    (file oversized, contains {fileStream.Length - fileExpectedSize} extra bytes)");
                }

                var path = $"Content\\{file.Metadata.Creator:X16}\\{file.Metadata.ExecutionId.TitleId:X8}\\{file.Metadata.ContentType:X8}\\{file.Header.ContentId.ToHexString()}";
                infoWriter.WriteLine($"  HDD path: {path}");
            }

            return !signer.Contains("invalid") && file.InvalidTables.Count <= 0 && invalidHashes.Count <= 0 && invalidBlocks.Count <= 0 && numInvalidEntries <= 0 && (fileStream.Length >= fileExpectedSize) && file.StfsVolumeDescriptor.NumberOfFreeBlocks == expectedFreeBlocks;
        }
    }
}
