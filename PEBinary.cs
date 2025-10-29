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

    // Exactly one will be set
    public IMAGE_OPTIONAL_HEADER32? OptionalHeader32 { get; private set; }
    public IMAGE_OPTIONAL_HEADER64? OptionalHeader64 { get; private set; }

    public List<IMAGE_SECTION_HEADER> SectionHeaders { get; private set; } = new List<IMAGE_SECTION_HEADER>();

    // Parsed tables
    public List<ImportDescriptor> Imports { get; private set; } = new List<ImportDescriptor>();
    public List<ExportEntry> Exports { get; private set; } = new List<ExportEntry>();
    public List<BaseRelocBlock> BaseRelocations { get; private set; } = new List<BaseRelocBlock>();
    public List<DelayImportDescriptor> DelayImports { get; private set; } = new List<DelayImportDescriptor>();
    public TLSDirectory TLS { get; private set; } = null;
    public ResourceDirectory Resources { get; private set; } = null;

    // Built (mapped) image
    public byte[] Image { get; private set; } = null;

    // Public summary props
    public bool Is64Bit => OptionalHeader64.HasValue;
    public ulong ImageBase => OptionalHeader64?.ImageBase ?? OptionalHeader32?.ImageBase ?? 0UL;
    public uint SizeOfImage => OptionalHeader64?.SizeOfImage ?? OptionalHeader32?.SizeOfImage ?? 0U;
    public uint AddressOfEntryPoint => OptionalHeader64?.AddressOfEntryPoint ?? OptionalHeader32?.AddressOfEntryPoint ?? 0U;

    private const ushort IMAGE_FILE_DLL = 0x2000;
    public bool IsDll => (FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;



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
        // DOS
        DosHeader = Helpers.FromBytes<IMAGE_DOS_HEADER>(Data, 0);
        if (DosHeader.e_magic != 0x5A4D) // 'MZ'
            throw new Exception("Not a valid PE file (missing MZ header).");

        // NT
        int ntOffset = DosHeader.e_lfanew;
        if (ntOffset <= 0 || ntOffset + 4 > Data.Length) throw new Exception("Invalid e_lfanew.");
        uint ntSig = BitConverter.ToUInt32(Data, ntOffset);
        if (ntSig != 0x00004550) // 'PE\0\0'
            throw new Exception("Invalid NT Header signature.");

        // File header
        int fileHdrOff = ntOffset + 4;
        FileHeader = Helpers.FromBytes<IMAGE_FILE_HEADER>(Data, fileHdrOff);

        // Optional header
        int optOff = fileHdrOff + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));
        ushort magic = BitConverter.ToUInt16(Data, optOff);
        if (magic == 0x10b)
        {
            OptionalHeader32 = Helpers.FromBytes<IMAGE_OPTIONAL_HEADER32>(Data, optOff);
        }
        else if (magic == 0x20b)
        {
            OptionalHeader64 = Helpers.FromBytes<IMAGE_OPTIONAL_HEADER64>(Data, optOff);
        }
        else
        {
            throw new Exception("Unknown Optional Header Magic.");
        }

        // Sections
        int optSize = FileHeader.SizeOfOptionalHeader;
        int sectOff = optOff + optSize;
        int sectSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
        SectionHeaders.Clear();
        for (int i = 0; i < FileHeader.NumberOfSections; i++)
        {
            int off = sectOff + i * sectSize;
            if (off + sectSize > Data.Length) break;
            var sh = Helpers.FromBytes<IMAGE_SECTION_HEADER>(Data, off);
            SectionHeaders.Add(sh);
        }

        // Tables
        ParseDataDirectoriesAndTables();
    }

    // ---------------------------
    // Data directory indices
    // ---------------------------
    private const int DD_EXPORT = 0;
    private const int DD_IMPORT = 1;
    private const int DD_RESOURCE = 2;
    private const int DD_EXCEPTION = 3;
    private const int DD_SECURITY = 4;
    private const int DD_BASERELOC = 5;
    private const int DD_DEBUG = 6;
    private const int DD_ARCH = 7;
    private const int DD_GLOBALPTR = 8;
    private const int DD_TLS = 9;
    private const int DD_LOAD_CONFIG = 10;
    private const int DD_BOUND_IMPORT = 11;
    private const int DD_IAT = 12;
    private const int DD_DELAY_IMPORT = 13;
    private const int DD_COM_DESCRIPTOR = 14;

    private IMAGE_DATA_DIRECTORY[] GetDirectories()
    {
        if (OptionalHeader32.HasValue) return OptionalHeader32.Value.DataDirectory;
        return OptionalHeader64.Value.DataDirectory;
    }

    private uint GetSizeOfHeaders()
    {
        return OptionalHeader32?.SizeOfHeaders ?? OptionalHeader64?.SizeOfHeaders ?? 0U;
    }

    private void ParseDataDirectoriesAndTables()
    {
        var dirs = GetDirectories();

        if (dirs.Length > DD_EXPORT && dirs[DD_EXPORT].VirtualAddress != 0)
            ParseExportTable(dirs[DD_EXPORT].VirtualAddress, dirs[DD_EXPORT].Size);

        if (dirs.Length > DD_IMPORT && dirs[DD_IMPORT].VirtualAddress != 0)
            ParseImportTable(dirs[DD_IMPORT].VirtualAddress, dirs[DD_IMPORT].Size);

        if (dirs.Length > DD_BASERELOC && dirs[DD_BASERELOC].VirtualAddress != 0)
            ParseBaseRelocations(dirs[DD_BASERELOC].VirtualAddress, dirs[DD_BASERELOC].Size);

        if (dirs.Length > DD_DELAY_IMPORT && dirs[DD_DELAY_IMPORT].VirtualAddress != 0)
            ParseDelayImports(dirs[DD_DELAY_IMPORT].VirtualAddress, dirs[DD_DELAY_IMPORT].Size);

        if (dirs.Length > DD_TLS && dirs[DD_TLS].VirtualAddress != 0)
            ParseTLS(dirs[DD_TLS].VirtualAddress, dirs[DD_TLS].Size);

        if (dirs.Length > DD_RESOURCE && dirs[DD_RESOURCE].VirtualAddress != 0)
            ParseResources(dirs[DD_RESOURCE].VirtualAddress, dirs[DD_RESOURCE].Size);
    }

    // ---------------------------
    // RVA helpers
    // ---------------------------

    /// <summary>
    /// Converts a Relative Virtual Address (RVA) to a file offset in the Data[].
    /// Returns -1 if the RVA is invalid, points outside the file, or points
    /// to uninitialized data (which has no file offset).
    /// </summary>
    public int RvaToOffset(uint rva)
    {
        uint soHeaders = GetSizeOfHeaders();
        if (rva < soHeaders)
        {
            // RVA is in the headers.
            // Check if it's within the bounds of the loaded file data.
            if (rva >= Data.Length) return -1;
            return (int)rva;
        }

        foreach (var s in SectionHeaders)
        {
            uint va = s.VirtualAddress;
            uint vsz = s.VirtualSize; // The size in memory
            uint rsz = s.SizeOfRawData; // The size on disk

            // Check if the RVA is within this section's memory range
            if (rva >= va && rva < va + vsz)
            {
                uint delta = rva - va;

                // If the offset within the section is greater than its raw size,
                // it points to uninitialized data (e.g., .bss). This has no
                // file offset.
                if (delta >= rsz)
                {
                    return -1;
                }

                int fileOffset = (int)(s.PointerToRawData + delta);

                // Final sanity check: does the calculated offset point within the file?
                // (rsz check should be sufficient, but this protects against
                // sections that point to raw data > file length)
                if (fileOffset < 0 || fileOffset + (rsz - delta) > Data.Length)
                {
                    return -1;
                }

                return fileOffset;
            }
        }
        return -1;
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

    // ---------------------------
    // BUILD IMAGE (headers + sections)
    // ---------------------------
    public byte[] BuildImageBuffer()
    {
        uint imageSize = SizeOfImage;
        if (imageSize == 0) throw new Exception("SizeOfImage is zero; cannot build image.");

        var img = new byte[imageSize];

        // Copy headers (bounded)
        uint sizeOfHeaders = GetSizeOfHeaders();
        int headersCopySize = (int)Math.Min(sizeOfHeaders == 0 ? (uint)Data.Length : sizeOfHeaders, (uint)Data.Length);
        Array.Copy(Data, 0, img, 0, headersCopySize);

        // Copy sections raw data to their VirtualAddress
        foreach (var s in SectionHeaders)
        {
            if (s.SizeOfRawData == 0) continue;
            int srcOff = (int)s.PointerToRawData;
            if (srcOff < 0 || srcOff >= Data.Length) continue;

            int destOff = (int)s.VirtualAddress;
            uint copySize = Math.Min(s.SizeOfRawData, s.VirtualSize);
            if (srcOff + copySize > Data.Length) copySize = (uint)Math.Max(0, Data.Length - srcOff);
            if (destOff + copySize > img.Length) copySize = (uint)Math.Max(0, img.Length - destOff);
            if (copySize > 0)
                Array.Copy(Data, srcOff, img, destOff, (int)copySize);

            // Zero the remainder up to VirtualSize if VirtualSize > SizeOfRawData
            if (s.VirtualSize > s.SizeOfRawData)
            {
                int padStart = destOff + (int)s.SizeOfRawData;
                int padLen = (int)Math.Min((ulong)(s.VirtualSize - s.SizeOfRawData), (ulong)(img.Length - padStart));
                if (padStart >= 0 && padLen > 0 && padStart + padLen <= img.Length)
                    Array.Clear(img, padStart, padLen);
            }
        }

        Image = img; // store
        return img;
    }

    // Convenience: convert RVA (relative to mapped image) to index in Image[]
    private int RvaToImageIndex(uint rva)
    {
        if (Image == null) throw new InvalidOperationException("Call BuildImageBuffer() first.");
        if (rva >= Image.Length) return -1;
        return (int)rva;
    }

    /// <summary>
    /// A cache for the DefaultWin32Resolver to avoid multiple LoadLibrary calls.
    /// </summary>
    private static Dictionary<string, IntPtr> _resolverModuleCache = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// A default ImportResolver that uses LoadLibrary/GetProcAddress to find function pointers.
    /// </summary>
    public static ulong DefaultWin32Resolver(string dllName, string functionName, ushort? ordinal)
    {
        if (!_resolverModuleCache.TryGetValue(dllName, out IntPtr hModule))
        {
            hModule = Native.LoadLibraryA(dllName);
            if (hModule == IntPtr.Zero)
            {
                // Console.WriteLine($"[Resolver] Failed to load {dllName}");
                return 0;
            }
            _resolverModuleCache[dllName] = hModule;
        }

        IntPtr pFunc = IntPtr.Zero;
        if (functionName != null)
        {
            pFunc = Native.GetProcAddress(hModule, functionName);
        }
        else if (ordinal.HasValue)
        {
            // Ordinals must be passed as an IntPtr (HIWORD=0, LOWORD=ordinal)
            pFunc = Native.GetProcAddress(hModule, (IntPtr)ordinal.Value);
        }

        // if (pFunc == IntPtr.Zero) Console.WriteLine($"[Resolver] Failed to find {functionName ?? ordinal.ToString()} in {dllName}");

        return (ulong)pFunc;
    }

    /// <summary>
    /// Clears the static module cache used by the DefaultWin32Resolver.
    /// </summary>
    public static void ClearResolverCache()
    {
        foreach (var kvp in _resolverModuleCache)
        {
            Native.FreeLibrary(kvp.Value);
        }
        _resolverModuleCache.Clear();
    }

    // ---------------------------
    // EXECUTION & LOADING
    // ---------------------------

    /// <summary>
    /// Simulates the Windows Loader:
    /// 1. Allocates executable memory.
    /// 2. Builds the image buffer (headers + sections).
    /// 3. Applies base relocations to the new address.
    /// 4. Resolves and writes the IAT.
    /// 5. Copies the final image into executable memory.
    /// Returns the native base address of the loaded image.
    /// </summary>
    public IntPtr LoadImage(ImportResolver resolver)
    {
        if (resolver == null) throw new ArgumentNullException(nameof(resolver));

        // 1. Build the image in a managed byte[] first
        BuildImageBuffer(); // Populates this.Image
        if (this.Image == null) throw new InvalidOperationException("BuildImageBuffer() failed.");

        // 2. Allocate native executable memory
        IntPtr nativeBase = Native.VirtualAlloc(
            IntPtr.Zero, // OS chooses address
            (UIntPtr)this.Image.Length,
            Native.MEM_COMMIT | Native.MEM_RESERVE,
            Native.PAGE_EXECUTE_READ_WRITE
        );
        if (nativeBase == IntPtr.Zero)
            throw new Exception("Failed to allocate executable memory.");

        // 3. Apply relocations based on the new native address
        ApplyRelocations((ulong)nativeBase);

        // 4. Resolve imports and write them into the IAT
        EmulateIATWrite(resolver);

        // 5. Copy the final, patched image into the executable memory
        Marshal.Copy(this.Image, 0, nativeBase, this.Image.Length);

        return nativeBase;
    }

    /// <summary>
    /// Executes the TLS callbacks (if any) for a loaded image.
    /// This MUST be called before the entry point.
    /// </summary>
    private void ExecuteTLSCallbacks(IntPtr nativeBase)
    {
        if (TLS == null || TLS.CallbackRVAs.Count == 0)
            return;

        foreach (uint rva in TLS.CallbackRVAs)
        {
            if (rva == 0) continue;
            IntPtr pCallback = IntPtr.Add(nativeBase, (int)rva);
            var callback = Marshal.GetDelegateForFunctionPointer<Native.DllMain>(pCallback);

            // Call the callback with DLL_PROCESS_ATTACH
            callback(nativeBase, Native.DLL_PROCESS_ATTACH, IntPtr.Zero);
        }
    }

    /// <summary>
    // Executes a loaded image at its native base address.
    // - Calls TLS Callbacks.
    // - If a DLL, calls DllMain(ATTACH) in the current thread.
    // - If an EXE, calls the EntryPoint in a new thread.
    /// </summary>
    /// <param name="nativeBase">The pointer returned by LoadImage().</param>
    /// <param name="waitForThread">If true, blocks until the new EXE thread exits.</param>
    /// <returns>The thread handle if an EXE is launched, otherwise IntPtr.Zero.</returns>
    public IntPtr ExecuteLoadedImage(IntPtr nativeBase, bool waitForThread = false)
    {
        if (nativeBase == IntPtr.Zero)
            throw new ArgumentException("nativeBase cannot be zero.");

        // 1. Execute TLS Callbacks
        ExecuteTLSCallbacks(nativeBase);

        // 2. Get the final entry point address
        uint aoe = AddressOfEntryPoint;
        if (aoe == 0)
            return IntPtr.Zero; // No entry point

        IntPtr pEntryPoint = IntPtr.Add(nativeBase, (int)aoe);

        if (IsDll)
        {
            // --- This is a DLL ---
            // Call DllMain(ATTACH) directly in this thread
            // This mimics LoadLibrary's behavior
            var dllMain = Marshal.GetDelegateForFunctionPointer<Native.DllMain>(pEntryPoint);
            dllMain(nativeBase, Native.DLL_PROCESS_ATTACH, IntPtr.Zero);
            return IntPtr.Zero; // No thread handle
        }
        else
        {
            // --- This is an EXE ---
            // Launch the entry point in a new thread
            IntPtr hThread = Native.CreateThread(
                IntPtr.Zero, 0,
                pEntryPoint,
                IntPtr.Zero, // No parameter
                0, // Run immediately
                out uint _
            );

            if (waitForThread && hThread != IntPtr.Zero)
            {
                Native.WaitForSingleObject(hThread, Native.INFINITE);
                Native.CloseHandle(hThread);
                return IntPtr.Zero;
            }

            return hThread; // Return the new thread's handle
        }
    }

    /// <summary>
    /// Cleans up a loaded image:
    /// 1. Calls DllMain(DETACH) if it's a DLL.
    /// 2. Frees the executable memory via VirtualFree.
    /// </summary>
    public void UnloadImage(IntPtr nativeBase)
    {
        if (nativeBase == IntPtr.Zero) return;

        // If it's a DLL, we must call DllMain(DETACH)
        if (IsDll && AddressOfEntryPoint != 0)
        {
            try
            {
                IntPtr pEntryPoint = IntPtr.Add(nativeBase, (int)AddressOfEntryPoint);
                var dllMain = Marshal.GetDelegateForFunctionPointer<Native.DllMain>(pEntryPoint);
                dllMain(nativeBase, Native.DLL_PROCESS_DETACH, IntPtr.Zero);
            }
            catch { /* Best-effort cleanup */ }
        }

        // Free the memory
        Native.VirtualFree(nativeBase, UIntPtr.Zero, Native.MEM_RELEASE);
    }

    // ---------------------------
    // IMPORTS
    // ---------------------------
    private void ParseImportTable(uint importTableRva, uint importTableSize)
    {
        Imports.Clear();
        int descSize = Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
        int offset = RvaToOffset(importTableRva);
        if (offset < 0) return;

        int cursor = offset;
        while (cursor + descSize <= Data.Length)
        {
            IMAGE_IMPORT_DESCRIPTOR desc = Helpers.FromBytes<IMAGE_IMPORT_DESCRIPTOR>(Data, cursor);
            // zero descriptor = end
            if (desc.OriginalFirstThunk == 0 && desc.Name == 0 && desc.FirstThunk == 0 &&
                desc.TimeDateStamp == 0 && desc.ForwarderChain == 0)
                break;

            var id = new ImportDescriptor();
            id.DLLName = ReadAsciiStringAtRva(desc.Name) ?? string.Empty;

            uint oft = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
            int thunkOff = RvaToOffset(oft);
            if (thunkOff >= 0)
            {
                if (Is64Bit)
                {
                    int tcur = thunkOff;
                    while (tcur + 8 <= Data.Length)
                    {
                        ulong entry = BitConverter.ToUInt64(Data, tcur);
                        if (entry == 0) break;

                        var ie = new ImportEntry
                        {
                            IATRVA = desc.FirstThunk + (uint)(tcur - thunkOff),
                            OriginalThunkRVA = oft + (uint)(tcur - thunkOff)
                        };

                        const ulong ORD64 = 0x8000000000000000UL;
                        if ((entry & ORD64) != 0)
                        {
                            ie.ByOrdinal = true;
                            ie.Ordinal = (ushort)(entry & 0xFFFF);
                        }
                        else
                        {
                            int hintOff = RvaToOffset((uint)entry);
                            int nameOff = RvaToOffset((uint)entry + 2);
                            if (hintOff >= 0) ie.Hint = BitConverter.ToUInt16(Data, hintOff);
                            if (nameOff >= 0) ie.Name = ReadAsciiStringAtOffset(nameOff);
                            ie.ByOrdinal = false;
                        }
                        id.Entries.Add(ie);
                        tcur += 8;
                    }
                }
                else
                {
                    int tcur = thunkOff;
                    while (tcur + 4 <= Data.Length)
                    {
                        uint entry = BitConverter.ToUInt32(Data, tcur);
                        if (entry == 0) break;

                        var ie = new ImportEntry
                        {
                            IATRVA = desc.FirstThunk + (uint)(tcur - thunkOff),
                            OriginalThunkRVA = oft + (uint)(tcur - thunkOff)
                        };

                        const uint ORD32 = 0x80000000U;
                        if ((entry & ORD32) != 0)
                        {
                            ie.ByOrdinal = true;
                            ie.Ordinal = (ushort)(entry & 0xFFFF);
                        }
                        else
                        {
                            int hintOff = RvaToOffset(entry);
                            int nameOff = RvaToOffset(entry + 2);
                            if (hintOff >= 0) ie.Hint = BitConverter.ToUInt16(Data, hintOff);
                            if (nameOff >= 0) ie.Name = ReadAsciiStringAtOffset(nameOff);
                            ie.ByOrdinal = false;
                        }
                        id.Entries.Add(ie);
                        tcur += 4;
                    }
                }
            }

            Imports.Add(id);
            cursor += descSize;
        }
    }

    private string ReadAsciiStringAtOffset(int off)
    {
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

    // ---------------------------
    // DELAY-LOAD IMPORTS
    // ---------------------------
    private void ParseDelayImports(uint rva, uint size)
    {
        DelayImports.Clear();
        int off = RvaToOffset(rva);
        if (off < 0) return;
        int descSize = Marshal.SizeOf(typeof(IMAGE_DELAYLOAD_DESCRIPTOR));

        int cur = off;
        while (cur + descSize <= Data.Length)
        {
            var d = Helpers.FromBytes<IMAGE_DELAYLOAD_DESCRIPTOR>(Data, cur);
            if (d.AllAttributes == 0 && d.DllNameRVA == 0 && d.ModuleHandleRVA == 0 &&
                d.ImportAddressTableRVA == 0 && d.DelayImportNameTableRVA == 0)
                break;

            var dd = new DelayImportDescriptor
            {
                Attributes = d.AllAttributes,
                DllName = ReadAsciiStringAtRva(d.DllNameRVA) ?? string.Empty
            };

            // Parse its INT/IAT like normal imports
            uint oft = d.DelayImportNameTableRVA;
            if (oft != 0)
            {
                int thunkOff = RvaToOffset(oft);
                if (thunkOff >= 0)
                {
                    if (Is64Bit)
                    {
                        int tcur = thunkOff;
                        while (tcur + 8 <= Data.Length)
                        {
                            ulong entry = BitConverter.ToUInt64(Data, tcur);
                            if (entry == 0) break;

                            var ie = new ImportEntry
                            {
                                IATRVA = d.ImportAddressTableRVA + (uint)(tcur - thunkOff),
                                OriginalThunkRVA = oft + (uint)(tcur - thunkOff)
                            };

                            const ulong ORD64 = 0x8000000000000000UL;
                            if ((entry & ORD64) != 0)
                            {
                                ie.ByOrdinal = true; ie.Ordinal = (ushort)(entry & 0xFFFF);
                            }
                            else
                            {
                                int hintOff = RvaToOffset((uint)entry);
                                int nameOff = RvaToOffset((uint)entry + 2);
                                if (hintOff >= 0) ie.Hint = BitConverter.ToUInt16(Data, hintOff);
                                if (nameOff >= 0) ie.Name = ReadAsciiStringAtOffset(nameOff);
                                ie.ByOrdinal = false;
                            }
                            dd.Entries.Add(ie);
                            tcur += 8;
                        }
                    }
                    else
                    {
                        int tcur = thunkOff;
                        while (tcur + 4 <= Data.Length)
                        {
                            uint entry = BitConverter.ToUInt32(Data, tcur);
                            if (entry == 0) break;

                            var ie = new ImportEntry
                            {
                                IATRVA = d.ImportAddressTableRVA + (uint)(tcur - thunkOff),
                                OriginalThunkRVA = oft + (uint)(tcur - thunkOff)
                            };

                            const uint ORD32 = 0x80000000U;
                            if ((entry & ORD32) != 0)
                            {
                                ie.ByOrdinal = true; ie.Ordinal = (ushort)(entry & 0xFFFF);
                            }
                            else
                            {
                                int hintOff = RvaToOffset(entry);
                                int nameOff = RvaToOffset(entry + 2);
                                if (hintOff >= 0) ie.Hint = BitConverter.ToUInt16(Data, hintOff);
                                if (nameOff >= 0) ie.Name = ReadAsciiStringAtOffset(nameOff);
                                ie.ByOrdinal = false;
                            }
                            dd.Entries.Add(ie);
                            tcur += 4;
                        }
                    }
                }
            }

            DelayImports.Add(dd);
            cur += descSize;
        }
    }

    // ---------------------------
    // EXPORTS
    // ---------------------------
    private void ParseExportTable(uint exportTableRva, uint exportTableSize)
    {
        Exports.Clear();
        int off = RvaToOffset(exportTableRva);
        if (off < 0) return;
        if (off + Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY)) > Data.Length) return;

        IMAGE_EXPORT_DIRECTORY ed = Helpers.FromBytes<IMAGE_EXPORT_DIRECTORY>(Data, off);

        int funcsOff = RvaToOffset(ed.AddressOfFunctions);
        int namesOff = RvaToOffset(ed.AddressOfNames);
        int ordOff = RvaToOffset(ed.AddressOfNameOrdinals);

        if (funcsOff < 0) return;

        for (uint i = 0; i < ed.NumberOfNames; i++)
        {
            uint nameRva = BitConverter.ToUInt32(Data, namesOff + (int)(i * 4));
            int nameOff = RvaToOffset(nameRva);
            if (nameOff < 0) continue;
            string name = ReadAsciiStringAtRva(nameRva);

            ushort ordinalIndex = BitConverter.ToUInt16(Data, ordOff + (int)(i * 2));
            uint funcRva = BitConverter.ToUInt32(Data, funcsOff + (int)(ordinalIndex * 4));

            Exports.Add(new ExportEntry
            {
                Name = name,
                Ordinal = (ushort)(ed.Base + ordinalIndex),
                AddressRva = funcRva
            });
        }
    }

    // ---------------------------
    // BASE RELOCATIONS
    // ---------------------------
    private void ParseBaseRelocations(uint baseRelocRva, uint baseRelocSize)
    {
        BaseRelocations.Clear();
        int curOff = RvaToOffset(baseRelocRva);
        if (curOff < 0) return;
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
                if (entriesOffset + i * 2 + 2 > Data.Length) break;
                ushort entry = BitConverter.ToUInt16(Data, entriesOffset + i * 2);
                block.TypeOffsetList.Add(entry);
            }

            BaseRelocations.Add(block);
            curOff += (int)hdr.SizeOfBlock;
        }
    }

    /// <summary>
    /// Apply relocations into Image[] if newBase != ImageBase. Call BuildImageBuffer() first.
    /// </summary>
    public void ApplyRelocations(ulong newBase)
    {
        if (Image == null) throw new InvalidOperationException("Call BuildImageBuffer() first.");
        if (newBase == ImageBase) return; // nothing to do
        long delta = unchecked((long)(newBase - ImageBase));

        foreach (var block in BaseRelocations)
        {
            uint pageRva = block.VirtualAddress;
            foreach (ushort e in block.TypeOffsetList)
            {
                int type = (e >> 12) & 0xF;
                int off = e & 0x0FFF;
                uint fixRva = pageRva + (uint)off;
                int idx = RvaToImageIndex(fixRva);
                if (idx < 0) continue;

                switch (type)
                {
                    case 0: // ABSOLUTE - skipped (padding)
                        break;

                    case 3: // HIGHLOW (32-bit)
                        if (idx + 4 <= Image.Length)
                        {
                            int orig = BitConverter.ToInt32(Image, idx);
                            int patched = unchecked(orig + (int)delta);
                            WriteInt32(Image, idx, patched);
                        }
                        break;

                    case 10: // DIR64 (64-bit)
                        if (idx + 8 <= Image.Length)
                        {
                            long orig = BitConverter.ToInt64(Image, idx);
                            long patched = unchecked(orig + delta);
                            WriteInt64(Image, idx, patched);
                        }
                        break;

                    case 1: // HIGH (add high 16 of delta) – uncommon in modern images
                        if (idx + 2 <= Image.Length)
                        {
                            short orig = BitConverter.ToInt16(Image, idx);
                            short patched = (short)(orig + ((delta >> 16) & 0xFFFF));
                            WriteInt16(Image, idx, patched);
                        }
                        break;

                    case 2: // LOW (add low 16 of delta)
                        if (idx + 2 <= Image.Length)
                        {
                            short orig = BitConverter.ToInt16(Image, idx);
                            short patched = (short)(orig + (delta & 0xFFFF));
                            WriteInt16(Image, idx, patched);
                        }
                        break;

                    default:
                        // Other relocation types not handled here (e.g., HIGHADJ); rarely used in typical PE32+/PE32 userland binaries.
                        break;
                }
            }
        }
    }

    // ---------------------------
    // IAT EMULATION
    // ---------------------------
    public delegate ulong ImportResolver(string dllName, string functionNameOrNull, ushort? ordinalOrNull);

    /// <summary>
    /// Writes function pointers into IAT locations inside Image using a resolver you provide.
    /// Handles both normal and delay-load imports.
    /// </summary>
    public void EmulateIATWrite(ImportResolver resolver)
    {
        if (Image == null) throw new InvalidOperationException("Call BuildImageBuffer() first.");
        if (resolver == null) throw new ArgumentNullException(nameof(resolver));

        // Regular imports
        foreach (var d in Imports)
        {
            foreach (var e in d.Entries)
            {
                ulong addr = e.ByOrdinal
                    ? resolver(d.DLLName, null, e.Ordinal)
                    : resolver(d.DLLName, e.Name, null);

                WritePointerToImage(e.IATRVA, addr);
            }
        }

        // Delay-load imports
        foreach (var d in DelayImports)
        {
            foreach (var e in d.Entries)
            {
                ulong addr = e.ByOrdinal
                    ? resolver(d.DllName, null, e.Ordinal)
                    : resolver(d.DllName, e.Name, null);

                WritePointerToImage(e.IATRVA, addr);
            }
        }
    }

    private void WritePointerToImage(uint rva, ulong value)
    {
        int idx = RvaToImageIndex(rva);
        if (idx < 0) return;

        if (Is64Bit)
        {
            if (idx + 8 <= Image.Length) WriteUInt64(Image, idx, value);
        }
        else
        {
            if (idx + 4 <= Image.Length) WriteUInt32(Image, idx, (uint)value);
        }
    }

    // ---------------------------
    // TLS
    // ---------------------------
    private void ParseTLS(uint rva, uint size)
    {
        int off = RvaToOffset(rva);
        if (off < 0) return;

        if (Is64Bit)
        {
            if (off + Marshal.SizeOf(typeof(IMAGE_TLS_DIRECTORY64)) > Data.Length) return;
            var t = Helpers.FromBytes<IMAGE_TLS_DIRECTORY64>(Data, off);
            TLS = new TLSDirectory
            {
                StartAddressOfRawData = t.StartAddressOfRawData,
                EndAddressOfRawData = t.EndAddressOfRawData,
                AddressOfIndex = t.AddressOfIndex,
                AddressOfCallBacks = t.AddressOfCallBacks,
                SizeOfZeroFill = t.SizeOfZeroFill,
                Characteristics = t.Characteristics,
                CallbackRVAs = ReadTLSCallbacks(t.AddressOfCallBacks)
            };
        }
        else
        {
            if (off + Marshal.SizeOf(typeof(IMAGE_TLS_DIRECTORY32)) > Data.Length) return;
            var t = Helpers.FromBytes<IMAGE_TLS_DIRECTORY32>(Data, off);
            TLS = new TLSDirectory
            {
                StartAddressOfRawData = t.StartAddressOfRawData,
                EndAddressOfRawData = t.EndAddressOfRawData,
                AddressOfIndex = t.AddressOfIndex,
                AddressOfCallBacks = t.AddressOfCallBacks,
                SizeOfZeroFill = t.SizeOfZeroFill,
                Characteristics = t.Characteristics,
                CallbackRVAs = ReadTLSCallbacks(t.AddressOfCallBacks)
            };
        }
    }

    private List<uint> ReadTLSCallbacks(ulong addressOfCallbacksVA)
    {
        // addressOfCallbacks is a VA in loaded image (ImageBase + rva), but in the file it's an RVA
        // In many files, this field is a VA; we convert to RVA by subtracting ImageBase (fits in uint).
        if (addressOfCallbacksVA == 0) return new List<uint>();
        ulong callbacksVA = addressOfCallbacksVA;
        if (callbacksVA >= ImageBase) // if it's a VA
        {
            ulong rva64 = callbacksVA - ImageBase;
            if (rva64 > uint.MaxValue) return new List<uint>();
            uint callbacksRva = (uint)rva64;
            int off = RvaToOffset(callbacksRva);
            return ReadTLSCallbacksAtOffset(off);
        }
        else
        {
            // Sometimes producers store RVA here (non-standard); attempt direct mapping
            uint callbacksRva = (uint)callbacksVA;
            int off = RvaToOffset(callbacksRva);
            return ReadTLSCallbacksAtOffset(off);
        }
    }

    private List<uint> ReadTLSCallbacksAtOffset(int off)
    {
        var list = new List<uint>();
        if (off < 0) return list;

        if (Is64Bit)
        {
            int cur = off;
            while (cur + 8 <= Data.Length)
            {
                ulong va = BitConverter.ToUInt64(Data, cur);
                if (va == 0) break;
                if (va >= ImageBase && (va - ImageBase) <= uint.MaxValue)
                    list.Add((uint)(va - ImageBase));
                cur += 8;
            }
        }
        else
        {
            int cur = off;
            while (cur + 4 <= Data.Length)
            {
                uint va = BitConverter.ToUInt32(Data, cur);
                if (va == 0) break;
                if (va >= (uint)ImageBase)
                    list.Add(va - (uint)ImageBase);
                cur += 4;
            }
        }

        return list;
    }

    // ---------------------------
    // RESOURCES (recursive)
    // ---------------------------
    private void ParseResources(uint rva, uint size)
    {
        int baseOff = RvaToOffset(rva);
        if (baseOff < 0) return;

        Resources = ParseResourceDirectory(rva, baseOff, 0);
    }

    private ResourceDirectory ParseResourceDirectory(uint dirRva, int dirBaseOff, int level)
    {
        var dir = Helpers.FromBytes<IMAGE_RESOURCE_DIRECTORY>(Data, dirBaseOff);
        int entryCount = dir.NumberOfNamedEntries + dir.NumberOfIdEntries;
        var rd = new ResourceDirectory
        {
            Characteristics = dir.Characteristics,
            TimeDateStamp = dir.TimeDateStamp,
            MajorVersion = dir.MajorVersion,
            MinorVersion = dir.MinorVersion,
            NumberOfNamedEntries = dir.NumberOfNamedEntries,
            NumberOfIdEntries = dir.NumberOfIdEntries,
            Entries = new List<ResourceEntry>()
        };

        int entryOff = dirBaseOff + Marshal.SizeOf(typeof(IMAGE_RESOURCE_DIRECTORY));
        int entrySize = Marshal.SizeOf(typeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));

        for (int i = 0; i < entryCount; i++)
        {
            int off = entryOff + i * entrySize;
            if (off + entrySize > Data.Length) break;
            var e = Helpers.FromBytes<IMAGE_RESOURCE_DIRECTORY_ENTRY>(Data, off);
            var re = new ResourceEntry();

            bool nameIsString = (e.Name & 0x80000000) != 0;
            if (nameIsString)
            {
                uint nameRva = (e.Name & 0x7FFFFFFF) + (dirRva); // resource dir space is self-relative
                re.Name = ReadUnicodeResourceString(nameRva);
            }
            else
            {
                re.Id = (ushort)(e.Name & 0xFFFF);
            }

            bool isDir = (e.OffsetToData & 0x80000000) != 0;
            uint childRva = (e.OffsetToData & 0x7FFFFFFF) + (dirRva);
            int childOff = RvaToOffset(childRva);

            if (isDir)
            {
                if (childOff >= 0)
                    re.Subdirectory = ParseResourceDirectory(childRva, childOff, level + 1);
            }
            else
            {
                if (childOff >= 0)
                {
                    var data = Helpers.FromBytes<IMAGE_RESOURCE_DATA_ENTRY>(Data, childOff);
                    re.DataEntry = new ResourceDataEntry
                    {
                        DataRVA = data.OffsetToData,
                        Size = data.Size,
                        CodePage = data.CodePage
                    };
                }
            }

            rd.Entries.Add(re);
        }

        return rd;
    }

    private string ReadUnicodeResourceString(uint rva)
    {
        int off = RvaToOffset(rva);
        if (off < 0 || off + 2 > Data.Length) return null;
        ushort len = BitConverter.ToUInt16(Data, off);
        int bytes = len * 2;
        if (off + 2 + bytes > Data.Length) return null;
        return Encoding.Unicode.GetString(Data, off + 2, bytes);
    }

    /// <summary>
    /// Convenience: fetch raw bytes of a resource given a path (e.g., typeId, nameId/string, langId).
    /// Pass null to skip a level by index. Returns null if not found.
    /// </summary>
    public byte[] GetResourceData(object typeKey, object nameKey, object langKey)
    {
        if (Resources == null) return null;
        var typeNode = FindResourceChild(Resources, typeKey);
        if (typeNode?.Subdirectory == null) return null;
        var nameNode = FindResourceChild(typeNode.Subdirectory, nameKey);
        if (nameNode?.Subdirectory == null) return null;
        var langNode = FindResourceChild(nameNode.Subdirectory, langKey);
        if (langNode?.DataEntry == null) return null;

        int off = RvaToOffset(langNode.DataEntry.DataRVA);
        if (off < 0) return null;
        int size = (int)Math.Min((uint)langNode.DataEntry.Size, (uint)Math.Max(0, Data.Length - off));
        var buf = new byte[size];
        Array.Copy(Data, off, buf, 0, size);
        return buf;
    }

    private ResourceEntry FindResourceChild(ResourceDirectory dir, object key)
    {
        foreach (var e in dir.Entries)
        {
            if (key is ushort id)
            {
                if (e.Id.HasValue && e.Id.Value == id) return e;
            }
            else if (key is string s)
            {
                if (e.Name != null && string.Equals(e.Name, s, StringComparison.OrdinalIgnoreCase)) return e;
            }
        }
        return null;
    }

    // ---------------------------
    // WRITE HELPERS
    // ---------------------------
    private static void WriteInt16(byte[] buf, int idx, short v)
    {
        var b = BitConverter.GetBytes(v);
        Buffer.BlockCopy(b, 0, buf, idx, 2);
    }
    private static void WriteInt32(byte[] buf, int idx, int v)
    {
        var b = BitConverter.GetBytes(v);
        Buffer.BlockCopy(b, 0, buf, idx, 4);
    }
    private static void WriteInt64(byte[] buf, int idx, long v)
    {
        var b = BitConverter.GetBytes(v);
        Buffer.BlockCopy(b, 0, buf, idx, 8);
    }
    private static void WriteUInt32(byte[] buf, int idx, uint v)
    {
        var b = BitConverter.GetBytes(v);
        Buffer.BlockCopy(b, 0, buf, idx, 4);
    }
    private static void WriteUInt64(byte[] buf, int idx, ulong v)
    {
        var b = BitConverter.GetBytes(v);
        Buffer.BlockCopy(b, 0, buf, idx, 8);
    }

    // ---------------------------
    // MODELS / STRUCTS
    // ---------------------------

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;      // MZ
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
        public ushort Magic;           // 0x10B
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
        public ushort Magic;           // 0x20B
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

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_IMPORT_DESCRIPTOR
    {
        public uint OriginalFirstThunk;    // RVA to INT
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;                  // RVA to ASCII dll name
        public uint FirstThunk;            // RVA to IAT
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;
        public uint AddressOfNames;
        public uint AddressOfNameOrdinals;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAddress;
        public uint SizeOfBlock;
    }

    // Delay-load descriptor (WINNT.H)
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DELAYLOAD_DESCRIPTOR
    {
        public uint AllAttributes;
        public uint DllNameRVA;
        public uint ModuleHandleRVA;
        public uint ImportAddressTableRVA;
        public uint DelayImportNameTableRVA;
        public uint BoundDelayImportTableRVA;
        public uint UnloadInformationTableRVA;
        public uint TimeDateStamp;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_TLS_DIRECTORY32
    {
        public uint StartAddressOfRawData;
        public uint EndAddressOfRawData;
        public uint AddressOfIndex;
        public uint AddressOfCallBacks;
        public uint SizeOfZeroFill;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_TLS_DIRECTORY64
    {
        public ulong StartAddressOfRawData;
        public ulong EndAddressOfRawData;
        public ulong AddressOfIndex;
        public ulong AddressOfCallBacks;
        public uint SizeOfZeroFill;
        public uint Characteristics;
    }

    // Resources
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public ushort NumberOfNamedEntries;
        public ushort NumberOfIdEntries;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DIRECTORY_ENTRY
    {
        public uint Name;           // high bit: name string
        public uint OffsetToData;   // high bit: points to a directory
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DATA_ENTRY
    {
        public uint OffsetToData;   // RVA
        public uint Size;
        public uint CodePage;
        public uint Reserved;
    }

    // Domain classes
    public class ImportDescriptor
    {
        public string DLLName { get; set; }
        public List<ImportEntry> Entries { get; } = new List<ImportEntry>();
    }

    public class DelayImportDescriptor
    {
        public uint Attributes { get; set; }
        public string DllName { get; set; }
        public List<ImportEntry> Entries { get; } = new List<ImportEntry>();
    }

    public class ImportEntry
    {
        public bool ByOrdinal { get; set; }
        public ushort Ordinal { get; set; }     // if by ordinal
        public string Name { get; set; }        // if by name
        public uint Hint { get; set; }          // hint (name imports)
        public uint IATRVA { get; set; }        // where the loader writes the function ptr
        public uint OriginalThunkRVA { get; set; }
    }

    public class ExportEntry
    {
        public string Name { get; set; }
        public ushort Ordinal { get; set; }
        public uint AddressRva { get; set; }
    }

    public class BaseRelocBlock
    {
        public uint VirtualAddress { get; set; }
        public uint SizeOfBlock { get; set; }
        public List<ushort> TypeOffsetList { get; } = new List<ushort>();
    }

    public class TLSDirectory
    {
        public ulong StartAddressOfRawData { get; set; }
        public ulong EndAddressOfRawData { get; set; }
        public ulong AddressOfIndex { get; set; }
        public ulong AddressOfCallBacks { get; set; }
        public uint SizeOfZeroFill { get; set; }
        public uint Characteristics { get; set; }
        public List<uint> CallbackRVAs { get; set; } = new List<uint>(); // RVAs in image
    }

    public class ResourceDirectory
    {
        public uint Characteristics { get; set; }
        public uint TimeDateStamp { get; set; }
        public ushort MajorVersion { get; set; }
        public ushort MinorVersion { get; set; }
        public ushort NumberOfNamedEntries { get; set; }
        public ushort NumberOfIdEntries { get; set; }
        public List<ResourceEntry> Entries { get; set; } = new List<ResourceEntry>();
    }

    public class ResourceEntry
    {
        public ushort? Id { get; set; }     // if ID
        public string Name { get; set; }    // if named
        public ResourceDirectory Subdirectory { get; set; } // if directory
        public ResourceDataEntry DataEntry { get; set; }    // if leaf
    }

    public class ResourceDataEntry
    {
        public uint DataRVA { get; set; }
        public uint Size { get; set; }
        public uint CodePage { get; set; }
    }
}
