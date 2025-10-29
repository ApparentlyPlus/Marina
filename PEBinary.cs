using Marina;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class PEBinary
{
    public byte[] Data { get; private set; }
    public IMAGE_DOS_HEADER DosHeader { get; private set; }
    public IMAGE_FILE_HEADER FileHeader { get; private set; }

    // One of these will be valid depending on the file
    public IMAGE_OPTIONAL_HEADER32? OptionalHeader32 { get; private set; }
    public IMAGE_OPTIONAL_HEADER64? OptionalHeader64 { get; private set; }
    public List<IMAGE_SECTION_HEADER> SectionHeaders { get; private set; } = new List<IMAGE_SECTION_HEADER>();

    public PEBinary(string filePath)
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
        FileHeader = Helpers.FromBytes<IMAGE_FILE_HEADER>(Data, FileHeaderOffset);

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

        ParseDataDirectoriesAndTables();
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_IMPORT_DESCRIPTOR
    {
        public uint OriginalFirstThunk; // RVA to IMAGE_THUNK_DATA (name/ordinal)
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name; // RVA to DLL name (ASCII)
        public uint FirstThunk; // RVA to IAT (after load)
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_THUNK_DATA32
    {
        public uint ForwarderString; // union
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_THUNK_DATA64
    {
        public ulong ForwarderString; // union
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;              // RVA
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;     // RVA -> uint[]
        public uint AddressOfNames;         // RVA -> uint[]
        public uint AddressOfNameOrdinals;  // RVA -> ushort[]
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAddress;
        public uint SizeOfBlock;
    }

    // Parsed results you may want to inspect:
    public List<ImportDescriptor> Imports { get; private set; } = new List<ImportDescriptor>();
    public List<ExportEntry> Exports { get; private set; } = new List<ExportEntry>();
    public List<BaseRelocBlock> BaseRelocations { get; private set; } = new List<BaseRelocBlock>();

    public class ImportDescriptor
    {
        public string DLLName { get; set; }
        public List<ImportEntry> Entries { get; } = new List<ImportEntry>();
    }

    public class ImportEntry
    {
        public bool ByOrdinal { get; set; }
        public ushort Ordinal { get; set; }     // if by ordinal
        public string Name { get; set; }        // if by name
        public uint Hint { get; set; }          // hint (for name imports)
        public uint IATRVA { get; set; }        // the FirstThunk/IAT RVA where loader writes pointer
        public uint OriginalThunkRVA { get; set; } // original thunk table RVA (optional)
    }

    public class ExportEntry
    {
        public string Name { get; set; }
        public ushort Ordinal { get; set; } // ordinal = Base + index
        public uint AddressRva { get; set; } // RVA
    }

    public class BaseRelocBlock
    {
        public uint VirtualAddress { get; set; }
        public uint SizeOfBlock { get; set; }
        public List<ushort> TypeOffsetList { get; } = new List<ushort>(); // raw 16-bit entries
    }

    // Helper: whether this PE is 64-bit
    public bool Is64Bit => OptionalHeader64.HasValue;

    // Expose some common loader fields
    public ulong ImageBase => OptionalHeader64?.ImageBase ?? OptionalHeader32?.ImageBase ?? 0UL;
    public uint SizeOfImage => OptionalHeader64?.SizeOfImage ?? OptionalHeader32?.SizeOfImage ?? 0U;
    public uint AddressOfEntryPoint => OptionalHeader64?.AddressOfEntryPoint ?? OptionalHeader32?.AddressOfEntryPoint ?? 0U;

    // --- Call these from TryParse() after reading SectionHeaders ---
    private void ParseDataDirectoriesAndTables()
    {
        // parse data directories from optional header
        IMAGE_DATA_DIRECTORY[] dirs;
        if (OptionalHeader32.HasValue)
            dirs = OptionalHeader32.Value.DataDirectory;
        else
            dirs = OptionalHeader64.Value.DataDirectory;

        // indexes in the data directory (standard)
        const int EXPORT_TABLE = 0;
        const int IMPORT_TABLE = 1;
        const int BASE_RELOCATION_TABLE = 5;

        // Parse Export Table
        if (dirs.Length > EXPORT_TABLE && dirs[EXPORT_TABLE].VirtualAddress != 0)
        {
            ParseExportTable(dirs[EXPORT_TABLE].VirtualAddress, dirs[EXPORT_TABLE].Size);
        }

        // Parse Import Table
        if (dirs.Length > IMPORT_TABLE && dirs[IMPORT_TABLE].VirtualAddress != 0)
        {
            ParseImportTable(dirs[IMPORT_TABLE].VirtualAddress, dirs[IMPORT_TABLE].Size);
        }

        // Parse Base Relocations
        if (dirs.Length > BASE_RELOCATION_TABLE && dirs[BASE_RELOCATION_TABLE].VirtualAddress != 0)
        {
            ParseBaseRelocations(dirs[BASE_RELOCATION_TABLE].VirtualAddress, dirs[BASE_RELOCATION_TABLE].Size);
        }
    }

    // Convert an RVA to file offset. Returns -1 if cannot map
    public int RvaToOffset(uint rva)
    {
        // If RVA points into headers (<= SizeOfHeaders) map to file start
        uint sizeOfHeaders = OptionalHeader32?.SizeOfHeaders ?? OptionalHeader64?.SizeOfHeaders ?? 0U;
        if (rva < sizeOfHeaders)
            return (int)rva;

        // find section containing RVA
        foreach (var s in SectionHeaders)
        {
            uint va = s.VirtualAddress;
            uint vsz = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= va && rva < va + vsz)
            {
                uint delta = rva - va;
                return (int)(s.PointerToRawData + delta);
            }
        }

        return -1; // not found
    }

    private IMAGE_SECTION_HEADER? GetSectionForRva(uint rva)
    {
        foreach (var s in SectionHeaders)
        {
            uint va = s.VirtualAddress;
            uint vsz = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= va && rva < va + vsz)
                return s;
        }
        return null;
    }

    private string ReadAsciiStringAtRva(uint rva)
    {
        int off = RvaToOffset(rva);
        if (off < 0 || off >= Data.Length) return null;
        int pos = off;
        var sb = new StringBuilder();
        while (pos < Data.Length && Data[pos] != 0)
        {
            sb.Append((char)Data[pos]);
            pos++;
        }
        return sb.ToString();
    }

    private void ParseImportTable(uint importTableRva, uint importTableSize)
    {
        int descSize = Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
        int offset = RvaToOffset(importTableRva);
        if (offset < 0) return;

        Imports.Clear();
        int cursor = offset;

        while (cursor + descSize <= Data.Length)
        {
            IMAGE_IMPORT_DESCRIPTOR desc = Helpers.FromBytes<IMAGE_IMPORT_DESCRIPTOR>(Data, cursor);
            // a descriptor of zeros indicates end
            if (desc.OriginalFirstThunk == 0 && desc.Name == 0 && desc.FirstThunk == 0 && desc.TimeDateStamp == 0 && desc.ForwarderChain == 0)
                break;

            var id = new ImportDescriptor();
            id.DLLName = ReadAsciiStringAtRva(desc.Name) ?? string.Empty;
            uint oft = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk; // sometimes OriginalFirstThunk == 0
            int thunkOffset = RvaToOffset(oft);
            int iatOffset = RvaToOffset(desc.FirstThunk);

            // Walk thunk list
            if (thunkOffset >= 0)
            {
                if (Is64Bit)
                {
                    int thunkSize = Marshal.SizeOf(typeof(IMAGE_THUNK_DATA64));
                    int tcur = thunkOffset;
                    while (tcur + thunkSize <= Data.Length)
                    {
                        ulong entry = BitConverter.ToUInt64(Data, tcur);
                        if (entry == 0) break;
                        var ie = new ImportEntry { IATRVA = desc.FirstThunk + (uint)(tcur - thunkOffset), OriginalThunkRVA = oft + (uint)(tcur - thunkOffset) };

                        // highest bit set => ordinal if IMAGE_ORDINAL_FLAG64 (0x8000000000000000)
                        const ulong IMAGE_ORDINAL_FLAG64 = 0x8000000000000000UL;
                        if ((entry & IMAGE_ORDINAL_FLAG64) != 0)
                        {
                            ie.ByOrdinal = true;
                            ie.Ordinal = (ushort)(entry & 0xffff);
                        }
                        else
                        {
                            ie.ByOrdinal = false;
                            int nameOffset = RvaToOffset((uint)entry + 2); // skip hint (2 bytes) to name
                            if (nameOffset >= 0)
                            {
                                ie.Hint = BitConverter.ToUInt16(Data, RvaToOffset((uint)entry));
                                ie.Name = Encoding.ASCII.GetString(Data, nameOffset, Array.IndexOf<byte>(Data, 0, nameOffset) - nameOffset);
                            }
                        }

                        id.Entries.Add(ie);
                        tcur += thunkSize;
                    }
                }
                else
                {
                    int thunkSize = Marshal.SizeOf(typeof(IMAGE_THUNK_DATA32));
                    int tcur = thunkOffset;
                    while (tcur + thunkSize <= Data.Length)
                    {
                        uint entry = BitConverter.ToUInt32(Data, tcur);
                        if (entry == 0) break;
                        var ie = new ImportEntry { IATRVA = desc.FirstThunk + (uint)(tcur - thunkOffset), OriginalThunkRVA = oft + (uint)(tcur - thunkOffset) };

                        const uint IMAGE_ORDINAL_FLAG32 = 0x80000000U;
                        if ((entry & IMAGE_ORDINAL_FLAG32) != 0)
                        {
                            ie.ByOrdinal = true;
                            ie.Ordinal = (ushort)(entry & 0xffff);
                        }
                        else
                        {
                            ie.ByOrdinal = false;
                            int nameOffset = RvaToOffset(entry + 2);
                            if (nameOffset >= 0)
                            {
                                ie.Hint = BitConverter.ToUInt16(Data, RvaToOffset(entry));
                                ie.Name = Encoding.ASCII.GetString(Data, nameOffset, Array.IndexOf<byte>(Data, 0, nameOffset) - nameOffset);
                            }
                        }

                        id.Entries.Add(ie);
                        tcur += thunkSize;
                    }
                }
            }

            Imports.Add(id);
            cursor += descSize;
        }
    }

    private void ParseExportTable(uint exportTableRva, uint exportTableSize)
    {
        int off = RvaToOffset(exportTableRva);
        if (off < 0) return;
        if (off + Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY)) > Data.Length) return;

        IMAGE_EXPORT_DIRECTORY ed = Helpers.FromBytes<IMAGE_EXPORT_DIRECTORY>(Data, off);
        string dllName = ReadAsciiStringAtRva(ed.Name);

        // Read arrays
        uint funcsRva = ed.AddressOfFunctions;
        uint namesRva = ed.AddressOfNames;
        uint ordinalsRva = ed.AddressOfNameOrdinals;

        int funcsOff = RvaToOffset(funcsRva);
        int namesOff = RvaToOffset(namesRva);
        int ordOff = RvaToOffset(ordinalsRva);

        if (funcsOff < 0) return;

        Exports.Clear();
        // NumberOfFunctions indicates size of function table (index = ordinal - Base)
        // We'll read names and ordinals if present to build the list of exported named functions
        for (uint i = 0; i < ed.NumberOfNames; i++)
        {
            // each name entry is a 32-bit RVA to ASCII name
            uint nameRva = BitConverter.ToUInt32(Data, namesOff + (int)(i * 4));
            int nameOff = RvaToOffset(nameRva);
            if (nameOff < 0) continue;
            string name = ReadAsciiStringAtRva(nameRva);

            ushort ordinalIndex = BitConverter.ToUInt16(Data, ordOff + (int)(i * 2));
            // lookup function RVA by index
            uint funcRva = BitConverter.ToUInt32(Data, funcsOff + (int)(ordinalIndex * 4));

            var e = new ExportEntry
            {
                Name = name,
                Ordinal = (ushort)(ed.Base + ordinalIndex),
                AddressRva = funcRva
            };
            Exports.Add(e);
        }

        // Optionally, add unnamed exports by scanning function table for entries whose RVA is not within export thunk range.
        // (omitted for brevity; named exports are usually the important ones)
    }

    private void ParseBaseRelocations(uint baseRelocRva, uint baseRelocSize)
    {
        int curOff = RvaToOffset(baseRelocRva);
        if (curOff < 0) return;

        BaseRelocations.Clear();
        int end = curOff + (int)baseRelocSize;
        while (curOff + Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION)) <= Data.Length && curOff < end)
        {
            IMAGE_BASE_RELOCATION hdr = Helpers.FromBytes<IMAGE_BASE_RELOCATION>(Data, curOff);
            if (hdr.SizeOfBlock == 0) break;
            var block = new BaseRelocBlock { VirtualAddress = hdr.VirtualAddress, SizeOfBlock = hdr.SizeOfBlock };

            int entriesOffset = curOff + Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION));
            int entriesCount = ((int)hdr.SizeOfBlock - Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION))) / 2;
            for (int i = 0; i < entriesCount; i++)
            {
                ushort entry = BitConverter.ToUInt16(Data, entriesOffset + i * 2);
                block.TypeOffsetList.Add(entry);
            }

            BaseRelocations.Add(block);
            curOff += (int)hdr.SizeOfBlock;
        }
    }

    // Build an in-memory image buffer mapped like the loader would (headers + sections at their VirtualAddress)
    public byte[] BuildImageBuffer()
    {
        uint imageSize = SizeOfImage;
        if (imageSize == 0)
            throw new Exception("SizeOfImage is zero; cannot build image.");

        byte[] image = new byte[imageSize];

        // Copy headers
        uint sizeOfHeaders = OptionalHeader32?.SizeOfHeaders ?? OptionalHeader64?.SizeOfHeaders ?? 0U;
        int headersCopySize = (int)Math.Min(sizeOfHeaders == 0 ? Data.Length : sizeOfHeaders, (uint)Data.Length);
        Array.Copy(Data, 0, image, 0, headersCopySize);

        // Map sections: copy each section raw data into image at VirtualAddress
        foreach (var s in SectionHeaders)
        {
            if (s.SizeOfRawData == 0) continue; // nothing to copy
            int srcOff = (int)s.PointerToRawData;
            if (srcOff < 0 || srcOff >= Data.Length) continue;
            uint destRva = s.VirtualAddress;
            int destOff = (int)destRva;
            uint copySize = Math.Min(s.SizeOfRawData, s.VirtualSize);
            if (srcOff + copySize > Data.Length) copySize = (uint)Math.Max(0, Data.Length - srcOff);
            if (destOff + copySize > image.Length) copySize = (uint)Math.Max(0, image.Length - destOff);

            if (copySize > 0)
                Array.Copy(Data, srcOff, image, destOff, (int)copySize);
        }

        return image;
    }




    #region Structures


    /// <summary>
    /// Everything below is according to the Windows PE format. All structs are copied from the internet.
    /// For an in depth look of th PE file format, please visit https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
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
