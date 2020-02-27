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
            Console.WriteLine("STFS filesystem checker/verifier 0.1, by emoose");
            Console.WriteLine();
            if (args.Length <= 0)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("  stfschk.exe <path\\to\\package.file>");
                Console.WriteLine();
                Console.WriteLine("Batch mode:");
                Console.WriteLine("  stfschk.exe <path\\to\\folder>");
                Console.WriteLine();
                Console.WriteLine("Batch mode checks all packages in a folder, creating a <filename>.bad file for packages detected as bad");
                Console.WriteLine("The .bad file contains info about why the file was marked as bad");
                Console.WriteLine("Only files with valid XContent magic signature CON/LIVE/PIRS are checked when using batch mode");
                return;
            }

            var filePath = args[0];
            if(!File.Exists(filePath) && !Directory.Exists(filePath))
            {
                Console.WriteLine($"Invalid path {filePath}!");
                return;
            }

            if (!Directory.Exists(filePath))
            {
                var consoleWriter = new StreamWriter(Console.OpenStandardOutput());
                consoleWriter.AutoFlush = true;

                var result = ProcessFile(filePath, consoleWriter);
                Console.WriteLine();

                if (result)
                    Console.WriteLine("No errors detected.");
                else
                    Console.WriteLine("Errors found, file may be invalid!");

                Console.WriteLine();
                Console.WriteLine("Press any key to exit...");
                Console.ReadLine();
            }
            else
            {
                ProcessDir(filePath);
            }
        }

        static void ProcessDir(string dirPath)
        {
            foreach (var dir in Directory.GetDirectories(dirPath))
                ProcessDir(dir);

            foreach (var file in Directory.GetFiles(dirPath))
            {
                var mem = new MemoryStream();
                var sw = new StreamWriter(mem);

                bool result = ProcessFile(file, sw);
                if(!result)
                {
                    string info = System.Text.Encoding.UTF8.GetString(mem.ToArray());
                    if(!string.IsNullOrEmpty(info))
                        File.WriteAllText(file + ".bad", info);
                }
            }
        }

        static bool ProcessFile(string filePath, StreamWriter infoWriter = null)
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

            long fileExpectedSize = file.StfsBackingBlockToOffset(file.NumberOfBackingBlocks);

            if (infoWriter != null)
            {
                infoWriter.Write(file.MetadataString);
                infoWriter.WriteLine($"Stfs.NumberOfBackingBlocks = 0x{file.NumberOfBackingBlocks:X}");
                infoWriter.WriteLine();
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
            var invalidHashes = new List<long>();
            var invalidBlocks = new List<int>();
            for (int i = 0; i < file.StfsVolumeDescriptor.NumberOfTotalBlocks; i++)
            {
                var offset = file.StfsDataBlockToOffset(i);
                var hashEntry = hashEntries[i];

                if (offset >= fileExpectedSize || (offset + 0x1000) > fileExpectedSize)
                {
                    invalidBlocks.Add(i);
                    continue;
                }
                if (hashEntry.Hash == null)
                    continue; // Bad hash block :(

                fileStream.Position = offset;
                fileStream.Read(data, 0, 0x1000);
                byte[] hash = sha.ComputeHash(data);
                if (!hash.BytesMatch(hashEntry.Hash))
                    invalidHashes.Add(offset);
            }

            if (infoWriter != null)
            {
                if (invalidHashes.Count > 0)
                {
                    infoWriter.WriteLine();
                    infoWriter.WriteLine($"Detected {invalidHashes.Count} invalid data blocks:");
                    foreach (var offset in invalidHashes)
                        infoWriter.WriteLine($"  0x{offset:X}");
                }

                if (invalidBlocks.Count > 0)
                {
                    infoWriter.WriteLine();
                    infoWriter.WriteLine($"Detected {invalidBlocks.Count} out-of-bounds data blocks:");
                    foreach (var block in invalidBlocks)
                        infoWriter.WriteLine($"  0x{block:X} (at 0x{file.StfsDataBlockToOffset(block):X})");
                }

                infoWriter.WriteLine();
                infoWriter.WriteLine("Verifying directory entries...");
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
                    infoWriter.WriteLine($"{entry.FilePath}  {entry.Size} bytes  start block 0x{entry.DirEntry.FirstBlockNumber:X}");

                bool thisIsValid = true;
                if (invalidHashes.Contains(entry.DirectoryOffset))
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
                    thisIsValid = false;
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

            if (infoWriter != null)
            {
                infoWriter.WriteLine();
                infoWriter.WriteLine($"Summary (invalid/total):");

                // Header checks
                {
                   // infoWriter.WriteLine($"  Header signature: unknown (TBD in 0.2)");
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
                    bool expectedReadOnlyFormat = false;
                    uint expectedHeaderSize = 0x971A; // CON SizeOfHeaders

                    if (file.Header.SignatureType == XCONTENT_HEADER.kSignatureTypeLiveBE || file.Header.SignatureType == XCONTENT_HEADER.kSignatureTypePirsBE)
                    {
                        expectedReadOnlyFormat = true;
                        expectedHeaderSize = 0xAD0E; // LIVE/PIRS SizeOfHeaders (larger size for the XCONTENT_METADATA_INSTALLER data?)
                    }

                    if (file.StfsVolumeDescriptor.ReadOnlyFormat != expectedReadOnlyFormat)
                        infoWriter.WriteLine($"  StfsVolumeDescriptor.ReadOnlyFormat: {file.StfsVolumeDescriptor.ReadOnlyFormat} (expected {expectedReadOnlyFormat} for {file.Header.SignatureTypeString} package!)");

                    if (file.Header.SizeOfHeaders != expectedHeaderSize)
                        infoWriter.WriteLine($"  Header.SizeOfHeaders: 0x{file.Header.SizeOfHeaders:X} (expected 0x{expectedHeaderSize:X} for {file.Header.SignatureTypeString} package!)");

                    // not checking file.StfsVolumeDescriptor.DescriptorLength here as that was already checked inside StfsInit
                }

                // Hash checks
                {
                    infoWriter.WriteLine($"  Hash tables: {file.InvalidTables.Count}/{file.CachedTables.Count}");

                    var addStr = "";
                    if (file.InvalidTables.Count > 0)
                        addStr = " (bad hash tables prevents checking data blocks, the invalid count may be higher!)";

                    infoWriter.WriteLine($"  Data blocks: {invalidHashes.Count}/{file.StfsVolumeDescriptor.NumberOfTotalBlocks}" + addStr);
                    infoWriter.WriteLine($"  Directory entries: {numInvalidEntries}/{file.Children.Length}");
                    infoWriter.WriteLine($"  Block indices: {invalidBlocks.Count}/{file.StfsVolumeDescriptor.NumberOfTotalBlocks}");
                }

                // Size checks
                {
                    var sizeDifference = fileStream.Length - fileExpectedSize;
                    if (sizeDifference != 0)
                        infoWriter.WriteLine($"  Package size: 0x{fileStream.Length:X} (expected 0x{fileExpectedSize:X}, {sizeDifference} bytes difference)");
                    else
                        infoWriter.WriteLine($"  Package size: 0x{fileExpectedSize:X}");

                    if (fileStream.Length < fileExpectedSize)
                        infoWriter.WriteLine($"  (file truncated, too small to hold {file.NumberOfBackingBlocks} backing blocks)");
                    else if (fileStream.Length > fileExpectedSize)
                        infoWriter.WriteLine($"  (file oversized, contains 0x{(fileStream.Length - fileExpectedSize):X} extra bytes)");
                }

                var path = $"{file.Metadata.Creator:X16}\\{file.Metadata.ExecutionId.TitleId:X8}\\{file.Metadata.ContentType:X8}\\{file.Header.ContentId.ToHexString()}";
                infoWriter.WriteLine($"  Expected path: {path}");
            }

            return file.InvalidTables.Count <= 0 && invalidHashes.Count <= 0 && invalidBlocks.Count <= 0 && numInvalidEntries <= 0 && (fileStream.Length >= fileExpectedSize);
        }
    }
}
