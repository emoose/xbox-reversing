using System;
using System.IO;
using System.Collections.Generic;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace STFSChk
{
    public class FileSystemParseException : Exception
    {
        public FileSystemParseException(String Message = null) : base(Message)
        {
            HasMessage = Message != null;
        }

        public bool HasMessage;
    }

    [Flags]
    public enum EFileAccess : uint
    {
        //
        // Standart Section
        //

        AccessSystemSecurity = 0x1000000,   // AccessSystemAcl access type
        MaximumAllowed = 0x2000000,     // MaximumAllowed access type

        Delete = 0x10000,
        ReadControl = 0x20000,
        WriteDAC = 0x40000,
        WriteOwner = 0x80000,
        Synchronize = 0x100000,

        StandardRightsRequired = 0xF0000,
        StandardRightsRead = ReadControl,
        StandardRightsWrite = ReadControl,
        StandardRightsExecute = ReadControl,
        StandardRightsAll = 0x1F0000,
        SpecificRightsAll = 0xFFFF,

        FILE_READ_DATA = 0x0001,        // file & pipe
        FILE_LIST_DIRECTORY = 0x0001,       // directory
        FILE_WRITE_DATA = 0x0002,       // file & pipe
        FILE_ADD_FILE = 0x0002,         // directory
        FILE_APPEND_DATA = 0x0004,      // file
        FILE_ADD_SUBDIRECTORY = 0x0004,     // directory
        FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
        FILE_READ_EA = 0x0008,          // file & directory
        FILE_WRITE_EA = 0x0010,         // file & directory
        FILE_EXECUTE = 0x0020,          // file
        FILE_TRAVERSE = 0x0020,         // directory
        FILE_DELETE_CHILD = 0x0040,     // directory
        FILE_READ_ATTRIBUTES = 0x0080,      // all
        FILE_WRITE_ATTRIBUTES = 0x0100,     // all

        //
        // Generic Section
        //

        GenericRead = 0x80000000,
        GenericWrite = 0x40000000,
        GenericExecute = 0x20000000,
        GenericAll = 0x10000000,

        SPECIFIC_RIGHTS_ALL = 0x00FFFF,
        FILE_ALL_ACCESS =
        StandardRightsRequired |
        Synchronize |
        0x1FF,

        FILE_GENERIC_READ =
        StandardRightsRead |
        FILE_READ_DATA |
        FILE_READ_ATTRIBUTES |
        FILE_READ_EA |
        Synchronize,

        FILE_GENERIC_WRITE =
        StandardRightsWrite |
        FILE_WRITE_DATA |
        FILE_WRITE_ATTRIBUTES |
        FILE_WRITE_EA |
        FILE_APPEND_DATA |
        Synchronize,

        FILE_GENERIC_EXECUTE =
        StandardRightsExecute |
            FILE_READ_ATTRIBUTES |
            FILE_EXECUTE |
            Synchronize
    }

    [Flags]
    public enum EFileShare : uint
    {
        /// <summary>
        ///
        /// </summary>
        None = 0x00000000,
        /// <summary>
        /// Enables subsequent open operations on an object to request read access.
        /// Otherwise, other processes cannot open the object if they request read access.
        /// If this flag is not specified, but the object has been opened for read access, the function fails.
        /// </summary>
        Read = 0x00000001,
        /// <summary>
        /// Enables subsequent open operations on an object to request write access.
        /// Otherwise, other processes cannot open the object if they request write access.
        /// If this flag is not specified, but the object has been opened for write access, the function fails.
        /// </summary>
        Write = 0x00000002,
        /// <summary>
        /// Enables subsequent open operations on an object to request delete access.
        /// Otherwise, other processes cannot open the object if they request delete access.
        /// If this flag is not specified, but the object has been opened for delete access, the function fails.
        /// </summary>
        Delete = 0x00000004
    }

    public enum ECreationDisposition : uint
    {
        /// <summary>
        /// Creates a new file. The function fails if a specified file exists.
        /// </summary>
        New = 1,
        /// <summary>
        /// Creates a new file, always.
        /// If a file exists, the function overwrites the file, clears the existing attributes, combines the specified file attributes,
        /// and flags with FILE_ATTRIBUTE_ARCHIVE, but does not set the security descriptor that the SECURITY_ATTRIBUTES structure specifies.
        /// </summary>
        CreateAlways = 2,
        /// <summary>
        /// Opens a file. The function fails if the file does not exist.
        /// </summary>
        OpenExisting = 3,
        /// <summary>
        /// Opens a file, always.
        /// If a file does not exist, the function creates a file as if dwCreationDisposition is CREATE_NEW.
        /// </summary>
        OpenAlways = 4,
        /// <summary>
        /// Opens a file and truncates it so that its size is 0 (zero) bytes. The function fails if the file does not exist.
        /// The calling process must open the file with the GENERIC_WRITE access right.
        /// </summary>
        TruncateExisting = 5
    }

    [Flags]
    public enum EFileAttributes : uint
    {
        Readonly = 0x00000001,
        Hidden = 0x00000002,
        System = 0x00000004,
        Directory = 0x00000010,
        Archive = 0x00000020,
        Device = 0x00000040,
        Normal = 0x00000080,
        Temporary = 0x00000100,
        SparseFile = 0x00000200,
        ReparsePoint = 0x00000400,
        Compressed = 0x00000800,
        Offline = 0x00001000,
        NotContentIndexed = 0x00002000,
        Encrypted = 0x00004000,
        Write_Through = 0x80000000,
        Overlapped = 0x40000000,
        NoBuffering = 0x20000000,
        RandomAccess = 0x10000000,
        SequentialScan = 0x08000000,
        DeleteOnClose = 0x04000000,
        BackupSemantics = 0x02000000,
        PosixSemantics = 0x01000000,
        OpenReparsePoint = 0x00200000,
        OpenNoRecall = 0x00100000,
        FirstPipeInstance = 0x00080000
    }

    public class Natives
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern SafeFileHandle CreateFile(
            [MarshalAs(UnmanagedType.LPTStr)] string lpFileName,
            [MarshalAs(UnmanagedType.U4)] EFileAccess dwDesiredAccess,
            [MarshalAs(UnmanagedType.U4)] EFileShare dwShareMode,
            IntPtr lpSecurityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
            [MarshalAs(UnmanagedType.U4)] ECreationDisposition dwCreationDisposition,
            [MarshalAs(UnmanagedType.U4)] EFileAttributes dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(SafeHandle hObject);

        [DllImport("kernel32.dll")]
        public static extern uint GetFileSize(SafeHandle hFile, ref uint lpFileSizeHigh);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(SafeHandle hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize, ref DiskGeometry lpOutBuffer,
            uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);

        [StructLayout(LayoutKind.Sequential)]
        private struct DiskGeometry
        {
            private long cylinders;
            private uint mediaType;
            private uint tracksPerCylinder;
            private uint sectorsPerTrack;
            private uint bytesPerSector;

            public long DiskSize
            {
                get
                {
                    return cylinders * tracksPerCylinder *
                        sectorsPerTrack * bytesPerSector;
                }
            }
        }

        public static long GetDriveSize(SafeHandle sfh)
        {
            DiskGeometry geo = new DiskGeometry();
            uint returnedBytes;
            DeviceIoControl(sfh, 0x70000, IntPtr.Zero, 0, ref geo,
                (uint)Marshal.SizeOf(typeof(DiskGeometry)),
                out returnedBytes, IntPtr.Zero);
            return geo.DiskSize;
        }
    }

    public class TupleList<T1, T2, T3> : List<Tuple<T1, T2, T3>>
    {
        public void Add(T1 item, T2 item2, T3 item3)
        {
            Add(new Tuple<T1, T2, T3>(item, item2, item3));
        }
    }

    static class Utility
    {
        public static readonly string[] XboxLanguages =
        {
            "English",
            "Japanese",
            "German",
            "French",
            "Spanish",
            "Italian",
            "Korean",
            "Trad.Chinese",
            "Portuguese",
            "Unused10", // formerly SimpChinese?
            "Polish",
            "Russian",
            "Swedish",
            "Turkish",
            "Norwegian",
            "Dutch",
            "Simp.Chinese"
        };

        public static ulong RoundToPages(ulong number, ulong pageSize)
        {
            return (number + pageSize - 1) / pageSize;
        }

        public static DateTime DecodeMSTime(int dateTime)
        {
            if (dateTime == 0)
                return DateTime.MinValue;

            int second = (dateTime & 0x1F) * 2;
            int minute = (dateTime >> 5) & 0x3F;
            int hour = (dateTime >> 11) & 0x1F;
            int day = (dateTime >> 16) & 0x1F;
            int month = (dateTime >> 21) & 0x0F;
            int year = ((dateTime >> 25) & 0x7F) + 1980;

            try
            {
                return new DateTime(year, month, day, hour, minute, second).ToLocalTime();
            }
            catch { return DateTime.MinValue; }
        }

        public static int EncodeMSTime(DateTime dateTime)
        {
            dateTime = dateTime.ToUniversalTime();

            int second = dateTime.Second;
            int minute = dateTime.Minute;
            int hour = dateTime.Hour;
            int day = dateTime.Day;
            int month = dateTime.Month;
            int year = dateTime.Year;

            year -= 1980;
            second /= 2;

            return (year << 25) | (month << 21) | (day << 16) | (hour << 11) | (minute << 5) | second;
        }

        public static T ReadStruct<T>(this Stream stream)
        {
            var size = Marshal.SizeOf(typeof(T));

            // Read in a byte array
            byte[] bytes = new byte[size];
            stream.Read(bytes, 0, size);
            //stream.ReadAsync(bytes, 0, size).Wait();

            return BytesToStruct<T>(bytes);
        }

        public static T ReadStruct<T>(this BinaryReader reader)
        {
            var size = Marshal.SizeOf(typeof(T));

            // Read in a byte array
            byte[] bytes = reader.ReadBytes(size);

            return BytesToStruct<T>(bytes);
        }

        public static T BytesToStruct<T>(byte[] bytes)
        {
            // Pin the managed memory while, copy it out the data, then unpin it
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            var theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        public static short EndianSwap(this short num)
        {
            byte[] data = BitConverter.GetBytes(num);
            Array.Reverse(data);
            return BitConverter.ToInt16(data, 0);
        }

        public static ushort EndianSwap(this ushort num)
        {
            byte[] data = BitConverter.GetBytes(num);
            Array.Reverse(data);
            return BitConverter.ToUInt16(data, 0);
        }

        public static int EndianSwap(this int num)
        {
            byte[] data = BitConverter.GetBytes(num);
            Array.Reverse(data);
            return BitConverter.ToInt32(data, 0);
        }

        public static uint EndianSwap(this uint num)
        {
            byte[] data = BitConverter.GetBytes(num);
            Array.Reverse(data);
            return BitConverter.ToUInt32(data, 0);
        }

        public static ulong EndianSwap(this ulong num)
        {
            byte[] data = BitConverter.GetBytes(num);
            Array.Reverse(data);
            return BitConverter.ToUInt64(data, 0);
        }

        public static string ToHexString(this byte[] data)
        {
            var ret = "";
            foreach (var byt in data)
                ret += byt.ToString("X2");
            return ret;
        }

        public static bool BytesMatch(this byte[] b1, byte[] b2)
        {
            if (b1.Length != b2.Length)
                return false;
            for (int i = 0; i < b1.Length; i++)
            {
                if (b1[i] != b2[i])
                    return false;
            }
            return true;
        }

        public static bool IsNull(this byte[] b1)
        {
            foreach (var byt in b1)
                if (byt != 0)
                    return false;
            return true;
        }

        public static byte[] Substring(this byte[] data, int offset, int length)
        {
            var buffer = new byte[length];
            for (int i = offset, y = 0; i < offset + length; i++, y++)
                buffer[y] = data[i];

            return buffer;
        }
    }
}
