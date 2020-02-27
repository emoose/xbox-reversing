using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace STFSChk
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct CONSOLE_PUBLIC_KEY
    {
        public uint PublicExponent;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] Modulus;

        public void EndianSwap()
        {
            PublicExponent = PublicExponent.EndianSwap();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct XE_CONSOLE_CERTIFICATE
    {
        public ushort CertSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
        public byte[] ConsoleId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 11)]
        public byte[] ConsolePartNumberBytes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Reserved;
        public ushort Privileges;
        public uint ConsoleType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] ManufacturingDateBytes;
        public CONSOLE_PUBLIC_KEY ConsolePublicKey;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] Signature;

        public string ConsolePartNumber
        {
            get
            {
                return Encoding.ASCII.GetString(ConsolePartNumberBytes);
            }
        }

        public string ManufacturingDate
        {
            get
            {
                return Encoding.ASCII.GetString(ManufacturingDateBytes);
            }
        }

        public string ConsoleTypeString
        {
            get
            {
                switch (ConsoleType)
                {
                    case 1:
                        return "DevKit";
                    case 2:
                        return "Retail";
                    case 0x80000001:
                        return "DevKit (recovered/generated)";
                    case 0x80000002:
                        return "BetaKit";
                }
                return ConsoleType.ToString("X8");
            }
        }

        public bool IsStructureValid
        {
            get
            {
                return CertSize == 0x1A8;
            }
        }

        public void EndianSwap()
        {
            CertSize = CertSize.EndianSwap();
            Privileges = Privileges.EndianSwap();
            ConsoleType = ConsoleType.EndianSwap();
            ConsolePublicKey.EndianSwap();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct XE_CONSOLE_ID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
        public byte[] Bytes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct XE_CONSOLE_SIGNATURE
    {
        public XE_CONSOLE_CERTIFICATE Cert;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] Signature;

        public bool IsStructureValid
        {
            get
            {
                return Cert.IsStructureValid;
            }
        }

        public void EndianSwap()
        {
            Cert.EndianSwap();
        }
    }
}
