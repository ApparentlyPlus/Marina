using Marina;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class Binary
{
    public byte[] Data { get; private set; }
    public IMAGE_DOS_HEADER DosHeader { get; private set; }
    public IMAGE_FILE_HEADER FileHeader { get; private set; }

    // One of these will be valid depending on the file
    public IMAGE_OPTIONAL_HEADER32? OptionalHeader32 { get; private set; }
    public IMAGE_OPTIONAL_HEADER64? OptionalHeader64 { get; private set; }
    public List<IMAGE_SECTION_HEADER> SectionHeaders { get; private set; } = new List<IMAGE_SECTION_HEADER>();

    public Binary(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("File not found", filePath);

        try
        {
            Data = File.ReadAllBytes(filePath);
        }
        catch
        {
            throw new Exception("The file exceeds the maximum size allowed by File.ReadAllBytes(). Please choose a smaller file.");
        }
        
        TryParse();
    }

    private void TryParse()
    {

        // First, parse the DOS header
        DosHeader = Helpers.FromBytes<IMAGE_DOS_HEADER>(Data, 0);
        if (DosHeader.e_magic != 0x5A4D) // Ensure valid
            throw new Exception("Not a valid PE file (missing MZ header).");

        // Second, parse NT headers
        int NTHeadersOffset = DosHeader.e_lfanew;
        uint ntSignature = BitConverter.ToUInt32(Data, NTHeadersOffset);
        if (ntSignature != 0x00004550) // PE Signature check
            throw new Exception("Invalid NT Header signature.");

        // Read through the file header
        int FileHeaderOffset = NTHeadersOffset + 4;
        FileHeader = Helpers.FromBytes<IMAGE_FILE_HEADER>(Data, fileHeaderOffset);

        // Determine the Optional Header type (PE32 or PE64)

        int optHeaderOffset = FileHeaderOffset + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));
        ushort magic = BitConverter.ToUInt16(Data, optHeaderOffset);
        if (magic == 0x10b)
            OptionalHeader32 = Helpers.FromBytes<IMAGE_OPTIONAL_HEADER32>(Data, optHeaderOffset);
        else if (magic == 0x20b)
            OptionalHeader64 = Helpers.FromBytes<IMAGE_OPTIONAL_HEADER64>(Data, optHeaderOffset);
        else
            throw new Exception("Unknown Optional Header Magic.");

        // Section headers immediately follow the optional header.
        int OptHeaderSize = (magic == 0x10b) ? Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER32)) : Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER64));

        int SectionOffset = optHeaderOffset + OptHeaderSize;
        for (int i = 0; i < FileHeader.NumberOfSections; i++)
        {
            IMAGE_SECTION_HEADER section = Helpers.FromBytes<IMAGE_SECTION_HEADER>(Data, SectionOffset + i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
            SectionHeaders.Add(section);
        }

    }



    #region Structures


    /// <summary>
    /// Everything below is according to the Windows PE format. All structs are copied from the internet.
    /// </summary>
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;

        public string SectionName => Encoding.UTF8.GetString(Name).TrimEnd('\0');
    }

    #endregion
}
