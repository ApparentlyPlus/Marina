using Marina;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class PEBinary
{
    // Publicly visible parsed blobs, keep these stable for callers.
    public byte[] Data { get; private set; }
    public IMAGE_DOS_HEADER DosHeader { get; private set; }
    public IMAGE_FILE_HEADER FileHeader { get; private set; }

    // Exactly one of these will be populated.
    public IMAGE_OPTIONAL_HEADER32? OptionalHeader32 { get; private set; }
    public IMAGE_OPTIONAL_HEADER64? OptionalHeader64 { get; private set; }

    // Section table (disk headers)
    public List<IMAGE_SECTION_HEADER> SectionHeaders { get; private set; } = new List<IMAGE_SECTION_HEADER>();

    // Parsed directories / tables
    public List<ImportDescriptor> Imports { get; private set; } = new List<ImportDescriptor>();
    public List<ExportEntry> Exports { get; private set; } = new List<ExportEntry>();
    public List<BaseRelocBlock> BaseRelocations { get; private set; } = new List<BaseRelocBlock>();
    public List<DelayImportDescriptor> DelayImports { get; private set; } = new List<DelayImportDescriptor>();
    public TLSDirectory TLS { get; private set; } = null;
    public ResourceDirectory Resources { get; private set; } = null;

    // Built, mapped image (headers + sections, after we map it in memory)
    public byte[] Image { get; private set; } = null;

    // Convenience summary properties
    public bool Is64Bit => OptionalHeader64.HasValue;
    public ulong ImageBase => OptionalHeader64?.ImageBase ?? OptionalHeader32?.ImageBase ?? 0UL;
    public uint SizeOfImage => OptionalHeader64?.SizeOfImage ?? OptionalHeader32?.SizeOfImage ?? 0U;
    public uint AddressOfEntryPoint => OptionalHeader64?.AddressOfEntryPoint ?? OptionalHeader32?.AddressOfEntryPoint ?? 0U;

    private const ushort IMAGE_FILE_DLL = 0x2000;
    public bool IsDll => (FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;


    // ctor: read file and attempt parse
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
            // File.ReadAllBytes throws an exception for extremely large files on some runtimes
            throw new Exception("The file exceeds the maximum size allowed by File.ReadAllBytes(). Please choose a smaller file.");
        }

        TryParse();
    }

    private void TryParse()
    {
        // DOS header 
        DosHeader = Helpers.FromBytes<IMAGE_DOS_HEADER>(Data, 0);
        if (DosHeader.e_magic != 0x5A4D) // 'MZ'
            throw new Exception("Not a valid PE file (missing MZ header).");

        // NT header signature 
        int ntHdrOffset = DosHeader.e_lfanew;
        if (ntHdrOffset <= 0 || ntHdrOffset + 4 > Data.Length) throw new Exception("Invalid e_lfanew.");
        uint ntSignature = BitConverter.ToUInt32(Data, ntHdrOffset);
        if (ntSignature != 0x00004550) // 'PE\0\0'
            throw new Exception("Invalid NT Header signature.");

        // File header 
        int fileHdrOffset = ntHdrOffset + 4;
        FileHeader = Helpers.FromBytes<IMAGE_FILE_HEADER>(Data, fileHdrOffset);

        // Optional header 
        int optHdrOffset = fileHdrOffset + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));
        ushort optMagic = BitConverter.ToUInt16(Data, optHdrOffset);
        if (optMagic == 0x10b)
        {
            OptionalHeader32 = Helpers.FromBytes<IMAGE_OPTIONAL_HEADER32>(Data, optHdrOffset);
        }
        else if (optMagic == 0x20b)
        {
            OptionalHeader64 = Helpers.FromBytes<IMAGE_OPTIONAL_HEADER64>(Data, optHdrOffset);
        }
        else
        {
            throw new Exception("Unknown Optional Header Magic.");
        }

        // Section headers 
        int optionalHdrSize = FileHeader.SizeOfOptionalHeader;
        int secTableOffset = optHdrOffset + optionalHdrSize;
        int secEntrySize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
        SectionHeaders.Clear();

        // do not assume the file is perfectly formed, jesus have I seen some things over the years.
        for (int i = 0; i < FileHeader.NumberOfSections; i++)
        {
            int entryOffset = secTableOffset + i * secEntrySize;
            if (entryOffset + secEntrySize > Data.Length) break;
            var section = Helpers.FromBytes<IMAGE_SECTION_HEADER>(Data, entryOffset);
            SectionHeaders.Add(section);
        }

        // parse data directories (exports, imports, relocs, resources)
        ParseDataDirectoriesAndTables();
    }


    #region Data directory indices

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

    // Grab data directory array in a neutral way
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

    #endregion

    #region RVA helpers

    /// <summary>
    /// Convert RVA -> file offset in Data[].
    /// Returns -1 for invalid/unmapped RVA (like .bss).
    /// This function errs on the side of safety rather than optimism, hehe
    /// </summary>
    public int RvaToOffset(uint rva)
    {
        uint hdrSize = GetSizeOfHeaders();

        // If the RVA is within headers, it's a direct mapping (if file contains that many bytes)
        if (rva < hdrSize)
        {
            // ensure we don't return an offset beyond the file
            if (rva >= Data.Length) return -1;
            return (int)rva;
        }

        // Otherwise, find the section that contains this RVA.
        foreach (var s in SectionHeaders)
        {
            uint secVa = s.VirtualAddress;
            uint secVirtualSize = s.VirtualSize;   // size in memory
            uint secRawSize = s.SizeOfRawData;     // size on disk

            // If the RVA is within the memory area of the section
            if (rva >= secVa && rva < secVa + secVirtualSize)
            {
                uint offsetInSection = rva - secVa;

                // If offset falls into uninitialized (virtual-only) tail, there is no file data.
                if (offsetInSection >= secRawSize)
                {
                    return -1;
                }

                int fileOff = (int)(s.PointerToRawData + offsetInSection);

                // Sanity check
                if (fileOff < 0 || fileOff + (secRawSize - offsetInSection) > Data.Length)
                {
                    return -1;
                }

                return fileOff;
            }
        }

        // Not found in any section, invalid RVA.
        return -1;
    }

    // Read a null-terminated ASCII string from file using an RVA.
    // Returns null on error.
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

    #endregion

    #region BUILD IMAGE (headers + sections)

    public byte[] BuildImageBuffer()
    {
        uint imageSize = SizeOfImage;
        if (imageSize == 0) throw new Exception("SizeOfImage is zero; cannot build image.");

        var mapped = new byte[imageSize];

        // Copy the headers (but don't exceed the file's length).
        uint hdrSize = GetSizeOfHeaders();
        int copyLen = (int)Math.Min(hdrSize == 0 ? (uint)Data.Length : hdrSize, (uint)Data.Length);
        Array.Copy(Data, 0, mapped, 0, copyLen);

        // Copy sections into their virtual addresses inside the image buffer.
        foreach (var sec in SectionHeaders)
        {
            if (sec.SizeOfRawData == 0) continue;

            int srcOffset = (int)sec.PointerToRawData;
            if (srcOffset < 0 || srcOffset >= Data.Length) continue;

            int dstOffset = (int)sec.VirtualAddress;
            // We copy up to the lesser of raw size and virtual size.
            uint bytesToCopy = Math.Min(sec.SizeOfRawData, sec.VirtualSize);

            // Guard: don't read past the file.
            if (srcOffset + bytesToCopy > Data.Length)
                bytesToCopy = (uint)Math.Max(0, Data.Length - srcOffset);

            // Guard: don't write past the image buffer either.
            if (dstOffset + bytesToCopy > mapped.Length)
                bytesToCopy = (uint)Math.Max(0, mapped.Length - dstOffset);

            if (bytesToCopy > 0)
                Array.Copy(Data, srcOffset, mapped, dstOffset, (int)bytesToCopy);

            // If virtual size is larger than raw size, zero the remainder (BSS-like).
            if (sec.VirtualSize > sec.SizeOfRawData)
            {
                int padStart = dstOffset + (int)sec.SizeOfRawData;
                int padLen = (int)Math.Min((ulong)(sec.VirtualSize - sec.SizeOfRawData), (ulong)(mapped.Length - padStart));
                if (padStart >= 0 && padLen > 0 && padStart + padLen <= mapped.Length)
                    Array.Clear(mapped, padStart, padLen);
            }
        }

        Image = mapped; // keep a reference for further patching
        return mapped;
    }

    // Convert an RVA relative to the mapped image produced by BuildImageBuffer() into an index.
    private int RvaToImageIndex(uint rva)
    {
        if (Image == null) throw new InvalidOperationException("Call BuildImageBuffer() first.");
        if (rva >= Image.Length) return -1;
        return (int)rva;
    }

    /// <summary>
    /// A tiny resolver cache used by the DefaultWin32Resolver so we don't call LoadLibrary repeatedly.
    /// Not thread-safe intentionally — this is for tooling, not a high-concurrency server.
    /// </summary>
    private static Dictionary<string, IntPtr> _resolverModuleCache = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Default resolver: LoadLibraryA + GetProcAddress.
    /// Returns 0 when resolution fails.
    /// </summary>
    public static ulong DefaultWin32Resolver(string dllName, string functionName, ushort? ordinal)
    {
        if (!_resolverModuleCache.TryGetValue(dllName, out IntPtr hMod))
        {
            hMod = Native.LoadLibraryA(dllName);
            if (hMod == IntPtr.Zero)
            {
                // intentional silence: callers may expect missing imports in some analysis scenarios.
                return 0;
            }
            _resolverModuleCache[dllName] = hMod;
        }

        IntPtr pFn = IntPtr.Zero;
        if (functionName != null)
        {
            pFn = Native.GetProcAddress(hMod, functionName);
        }
        else if (ordinal.HasValue)
        {
            // GetProcAddress accepts ordinals as IntPtr on Win32.
            pFn = Native.GetProcAddress(hMod, (IntPtr)ordinal.Value);
        }

        return (ulong)pFn;
    }

    /// <summary>
    /// Free everything in the static resolver cache. Best-effort.
    /// </summary>
    public static void ClearResolverCache()
    {
        foreach (var kv in _resolverModuleCache)
        {
            Native.FreeLibrary(kv.Value);
        }
        _resolverModuleCache.Clear();
    }

    #endregion

    #region EXECUTION & LOADING

    /// <summary>
    /// Simulated loader:
    /// 1) Build a mapped image (managed).
    /// 2) Allocate RWX native memory.
    /// 3) Apply relocations for the chosen native base.
    /// 4) Resolve imports and write into the IAT(s).
    /// 5) Copy image to native memory and return its base address.
    /// 
    /// This intentionally mirrors Windows loader steps roughly; don't expect perfect parity.
    /// </summary>
    public IntPtr LoadImage(ImportResolver resolver)
    {
        if (resolver == null) throw new ArgumentNullException(nameof(resolver));

        // Step 1: build a mapped image buffer we can patch.
        BuildImageBuffer(); // side-effect: sets this.Image
        if (this.Image == null) throw new InvalidOperationException("BuildImageBuffer() failed.");

        // Step 2: allocate native executable memory (RWX for simplicity).
        IntPtr nativeBase = Native.VirtualAlloc(
            IntPtr.Zero,
            (UIntPtr)this.Image.Length,
            Native.MEM_COMMIT | Native.MEM_RESERVE,
            Native.PAGE_EXECUTE_READ_WRITE
        );

        if (nativeBase == IntPtr.Zero)
            throw new Exception("Failed to allocate executable memory.");

        // Step 3: apply relocations to the in-memory image (Image[]), using the newly chosen base.
        ApplyRelocations((ulong)nativeBase);

        // Step 4: resolve imports (both regular and delay-load) and write addresses into IAT.
        EmulateIATWrite(resolver);

        // Step 5: copy patched image into native memory.
        Marshal.Copy(this.Image, 0, nativeBase, this.Image.Length);

        return nativeBase;
    }

    /// <summary>
    /// Execute TLS callbacks (if any). Must be invoked before the module's entry point.
    /// This mirrors what the real loader does: callbacks are invoked in the loader's context.
    /// </summary>
    private void ExecuteTLSCallbacks(IntPtr nativeBase)
    {
        if (TLS == null || TLS.CallbackRVAs.Count == 0)
            return;

        foreach (uint rva in TLS.CallbackRVAs)
        {
            if (rva == 0) continue;
            IntPtr pCallback = IntPtr.Add(nativeBase, (int)rva);
            var cb = Marshal.GetDelegateForFunctionPointer<Native.DllMain>(pCallback);

            // DLL_PROCESS_ATTACH semantics.
            cb(nativeBase, Native.DLL_PROCESS_ATTACH, IntPtr.Zero);
        }
    }

    /// <summary>
    /// Execute an already-loaded image.
    /// - TLS callbacks are invoked.
    /// - For DLLs: DllMain(ATTACH) is called inline on current thread.
    /// - For EXEs: entry point is launched in a new thread (optionally waited upon).
    /// Returns thread handle for EXE threads; IntPtr.Zero for DLLs or on failure.
    /// </summary>
    public IntPtr ExecuteLoadedImage(IntPtr nativeBase, bool waitForThread = false)
    {
        if (nativeBase == IntPtr.Zero)
            throw new ArgumentException("nativeBase cannot be zero.");

        // 1. TLS callbacks
        ExecuteTLSCallbacks(nativeBase);

        // 2. Entry point RVA
        uint entryRva = AddressOfEntryPoint;
        if (entryRva == 0)
            return IntPtr.Zero;

        IntPtr pEntry = IntPtr.Add(nativeBase, (int)entryRva);

        if (IsDll)
        {
            // Call DllMain(ATTACH) in the current thread.
            var dllMain = Marshal.GetDelegateForFunctionPointer<Native.DllMain>(pEntry);
            dllMain(nativeBase, Native.DLL_PROCESS_ATTACH, IntPtr.Zero);
            return IntPtr.Zero;
        }
        else
        {
            // Launch EXE entry point in a new thread (signature matches CreateThread style).
            IntPtr hThread = Native.CreateThread(
                IntPtr.Zero, 0,
                pEntry,
                IntPtr.Zero, // no lpParameter
                0,           // run immediately
                out uint _
            );

            if (waitForThread && hThread != IntPtr.Zero)
            {
                Native.WaitForSingleObject(hThread, Native.INFINITE);
                Native.CloseHandle(hThread);
                return IntPtr.Zero;
            }

            return hThread;
        }
    }

    /// <summary>
    /// Unload an image previously allocated via LoadImage.
    /// Calls DllMain(DETACH) if appropriate and then frees memory.
    /// This is best-effort; swallow exceptions during DllMain to avoid leaving process in a bad state.
    /// </summary>
    public void UnloadImage(IntPtr nativeBase)
    {
        if (nativeBase == IntPtr.Zero) return;

        if (IsDll && AddressOfEntryPoint != 0)
        {
            try
            {
                IntPtr pEntry = IntPtr.Add(nativeBase, (int)AddressOfEntryPoint);
                var dllMain = Marshal.GetDelegateForFunctionPointer<Native.DllMain>(pEntry);
                dllMain(nativeBase, Native.DLL_PROCESS_DETACH, IntPtr.Zero);
            }
            catch
            {
                // Best-effort cleanup; swallow and proceed to free memory.
            }
        }

        Native.VirtualFree(nativeBase, UIntPtr.Zero, Native.MEM_RELEASE);
    }

    #endregion

    #region IMPORTS

    private void ParseImportTable(uint importTableRva, uint importTableSize)
    {
        Imports.Clear();
        int descSize = Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
        int tableOffset = RvaToOffset(importTableRva);
        if (tableOffset < 0) return;

        int cur = tableOffset;

        while (cur + descSize <= Data.Length)
        {
            IMAGE_IMPORT_DESCRIPTOR desc = Helpers.FromBytes<IMAGE_IMPORT_DESCRIPTOR>(Data, cur);

            // All-zero descriptor => end of table.
            if (desc.OriginalFirstThunk == 0 && desc.Name == 0 && desc.FirstThunk == 0 &&
                desc.TimeDateStamp == 0 && desc.ForwarderChain == 0)
                break;

            var importDesc = new ImportDescriptor();
            importDesc.DLLName = ReadAsciiStringAtRva(desc.Name) ?? string.Empty;

            // Some files omit OriginalFirstThunk; use FirstThunk as fallback.
            uint sourceThunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
            int thunkOffset = RvaToOffset(sourceThunkRva);

            if (thunkOffset >= 0)
            {
                if (Is64Bit)
                {
                    int pos = thunkOffset;
                    while (pos + 8 <= Data.Length)
                    {
                        ulong entry = BitConverter.ToUInt64(Data, pos);
                        if (entry == 0) break;

                        var ie = new ImportEntry
                        {
                            IATRVA = desc.FirstThunk + (uint)(pos - thunkOffset),
                            OriginalThunkRVA = sourceThunkRva + (uint)(pos - thunkOffset)
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

                        importDesc.Entries.Add(ie);
                        pos += 8;
                    }
                }
                else
                {
                    int pos = thunkOffset;
                    while (pos + 4 <= Data.Length)
                    {
                        uint entry = BitConverter.ToUInt32(Data, pos);
                        if (entry == 0) break;

                        var ie = new ImportEntry
                        {
                            IATRVA = desc.FirstThunk + (uint)(pos - thunkOffset),
                            OriginalThunkRVA = sourceThunkRva + (uint)(pos - thunkOffset)
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

                        importDesc.Entries.Add(ie);
                        pos += 4;
                    }
                }
            }

            Imports.Add(importDesc);
            cur += descSize;
        }
    }

    // Helper: read an ASCII string given a direct file offset (not RVA).
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

    #endregion

    #region D-LOAD IMPORTS
    
    private void ParseDelayImports(uint rva, uint size)
    {
        DelayImports.Clear();
        int baseOffset = RvaToOffset(rva);
        if (baseOffset < 0) return;
        int descSize = Marshal.SizeOf(typeof(IMAGE_DELAYLOAD_DESCRIPTOR));

        int cur = baseOffset;
        while (cur + descSize <= Data.Length)
        {
            var d = Helpers.FromBytes<IMAGE_DELAYLOAD_DESCRIPTOR>(Data, cur);

            // A table of zeros indicates termination.
            if (d.AllAttributes == 0 && d.DllNameRVA == 0 && d.ModuleHandleRVA == 0 &&
                d.ImportAddressTableRVA == 0 && d.DelayImportNameTableRVA == 0)
                break;

            var dd = new DelayImportDescriptor
            {
                Attributes = d.AllAttributes,
                DllName = ReadAsciiStringAtRva(d.DllNameRVA) ?? string.Empty
            };

            uint nameTblRva = d.DelayImportNameTableRVA;
            if (nameTblRva != 0)
            {
                int thunkOffset = RvaToOffset(nameTblRva);
                if (thunkOffset >= 0)
                {
                    if (Is64Bit)
                    {
                        int pos = thunkOffset;
                        while (pos + 8 <= Data.Length)
                        {
                            ulong entry = BitConverter.ToUInt64(Data, pos);
                            if (entry == 0) break;

                            var ie = new ImportEntry
                            {
                                IATRVA = d.ImportAddressTableRVA + (uint)(pos - thunkOffset),
                                OriginalThunkRVA = nameTblRva + (uint)(pos - thunkOffset)
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
                            pos += 8;
                        }
                    }
                    else
                    {
                        int pos = thunkOffset;
                        while (pos + 4 <= Data.Length)
                        {
                            uint entry = BitConverter.ToUInt32(Data, pos);
                            if (entry == 0) break;

                            var ie = new ImportEntry
                            {
                                IATRVA = d.ImportAddressTableRVA + (uint)(pos - thunkOffset),
                                OriginalThunkRVA = nameTblRva + (uint)(pos - thunkOffset)
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
                            pos += 4;
                        }
                    }
                }
            }

            DelayImports.Add(dd);
            cur += descSize;
        }
    }

    #endregion

    #region Exports

    private void ParseExportTable(uint exportTableRva, uint exportTableSize)
    {
        Exports.Clear();
        int dirFileOffset = RvaToOffset(exportTableRva);
        if (dirFileOffset < 0) return;
        if (dirFileOffset + Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY)) > Data.Length) return;

        IMAGE_EXPORT_DIRECTORY ed = Helpers.FromBytes<IMAGE_EXPORT_DIRECTORY>(Data, dirFileOffset);

        int funcsOff = RvaToOffset(ed.AddressOfFunctions);
        int namesOff = RvaToOffset(ed.AddressOfNames);
        int ordsOff = RvaToOffset(ed.AddressOfNameOrdinals);

        if (funcsOff < 0 || namesOff < 0 || ordsOff < 0) return;

        for (uint i = 0; i < ed.NumberOfNames; i++)
        {
            uint nameRva = BitConverter.ToUInt32(Data, namesOff + (int)(i * 4));
            int nameOff = RvaToOffset(nameRva);
            if (nameOff < 0) continue;
            string name = ReadAsciiStringAtRva(nameRva);

            ushort ordinalIndex = BitConverter.ToUInt16(Data, ordsOff + (int)(i * 2));
            uint funcRva = BitConverter.ToUInt32(Data, funcsOff + (int)(ordinalIndex * 4));

            Exports.Add(new ExportEntry
            {
                Name = name,
                Ordinal = (ushort)(ed.Base + ordinalIndex),
                AddressRva = funcRva
            });
        }
    }

    #endregion

    #region Base Reloc

    private void ParseBaseRelocations(uint baseRelocRva, uint baseRelocSize)
    {
        BaseRelocations.Clear();
        int curOff = RvaToOffset(baseRelocRva);
        if (curOff < 0) return;
        int endOff = curOff + (int)baseRelocSize;

        while (curOff + Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION)) <= Data.Length && curOff < endOff)
        {
            IMAGE_BASE_RELOCATION hdr = Helpers.FromBytes<IMAGE_BASE_RELOCATION>(Data, curOff);
            if (hdr.SizeOfBlock == 0) break;

            var block = new BaseRelocBlock { VirtualAddress = hdr.VirtualAddress, SizeOfBlock = hdr.SizeOfBlock };
            int entriesStart = curOff + Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION));
            int entriesCount = ((int)hdr.SizeOfBlock - Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION))) / 2;

            for (int i = 0; i < entriesCount; i++)
            {
                if (entriesStart + i * 2 + 2 > Data.Length) break;
                ushort entry = BitConverter.ToUInt16(Data, entriesStart + i * 2);
                block.TypeOffsetList.Add(entry);
            }

            BaseRelocations.Add(block);
            curOff += (int)hdr.SizeOfBlock;
        }
    }

    /// <summary>
    /// Apply relocations into Image[] if newBase != ImageBase.
    /// You must call BuildImageBuffer() first.
    /// </summary>
    public void ApplyRelocations(ulong newBase)
    {
        if (Image == null) throw new InvalidOperationException("Call BuildImageBuffer() first.");
        if (newBase == ImageBase) return; // nothing to patch

        long delta = unchecked((long)(newBase - ImageBase));

        foreach (var block in BaseRelocations)
        {
            uint pageRva = block.VirtualAddress;
            foreach (ushort entry in block.TypeOffsetList)
            {
                int type = (entry >> 12) & 0xF;
                int offset = entry & 0x0FFF;
                uint fixRva = pageRva + (uint)offset;
                int imgIdx = RvaToImageIndex(fixRva);
                if (imgIdx < 0) continue;

                switch (type)
                {
                    case 0: // ABSOLUTE: padding, skip.
                        break;

                    case 3: // HIGHLOW (32-bit patch)
                        if (imgIdx + 4 <= Image.Length)
                        {
                            int orig = BitConverter.ToInt32(Image, imgIdx);
                            int patched = unchecked(orig + (int)delta);
                            WriteInt32(Image, imgIdx, patched);
                        }
                        break;

                    case 10: // DIR64 (64-bit)
                        if (imgIdx + 8 <= Image.Length)
                        {
                            long orig = BitConverter.ToInt64(Image, imgIdx);
                            long patched = unchecked(orig + delta);
                            WriteInt64(Image, imgIdx, patched);
                        }
                        break;

                    case 1: // HIGH (rare): add high 16 bits of delta
                        if (imgIdx + 2 <= Image.Length)
                        {
                            short orig = BitConverter.ToInt16(Image, imgIdx);
                            short patched = (short)(orig + ((delta >> 16) & 0xFFFF));
                            WriteInt16(Image, imgIdx, patched);
                        }
                        break;

                    case 2: // LOW (rare): add low 16 bits
                        if (imgIdx + 2 <= Image.Length)
                        {
                            short orig = BitConverter.ToInt16(Image, imgIdx);
                            short patched = (short)(orig + (delta & 0xFFFF));
                            WriteInt16(Image, imgIdx, patched);
                        }
                        break;

                    default:
                        // Ignore exotic relocation types for now. Most userland binaries won't need them.
                        break;
                }
            }
        }
    }

    #endregion

    #region IAT Emu

    public delegate ulong ImportResolver(string dllName, string functionNameOrNull, ushort? ordinalOrNull);

    /// <summary>
    /// Resolve imports via the provided resolver and write pointers into the image IAT.
    /// Handles both regular imports and delay-load tables.
    /// </summary>
    public void EmulateIATWrite(ImportResolver resolver)
    {
        if (Image == null) throw new InvalidOperationException("Call BuildImageBuffer() first.");
        if (resolver == null) throw new ArgumentNullException(nameof(resolver));

        // Regular imports
        foreach (var imp in Imports)
        {
            foreach (var ent in imp.Entries)
            {
                ulong resolved = ent.ByOrdinal
                    ? resolver(imp.DLLName, null, ent.Ordinal)
                    : resolver(imp.DLLName, ent.Name, null);

                WritePointerToImage(ent.IATRVA, resolved);
            }
        }

        // Delay-load imports
        foreach (var dp in DelayImports)
        {
            foreach (var ent in dp.Entries)
            {
                ulong resolved = ent.ByOrdinal
                    ? resolver(dp.DllName, null, ent.Ordinal)
                    : resolver(dp.DllName, ent.Name, null);

                WritePointerToImage(ent.IATRVA, resolved);
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

    #endregion

    #region TLS

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
        // The field in the TLS directory may contain either VA or RVA.
        // If VA, convert to RVA by subtracting ImageBase; otherwise treat as RVA directly.
        if (addressOfCallbacksVA == 0) return new List<uint>();

        ulong callbacksVa = addressOfCallbacksVA;
        if (callbacksVa >= ImageBase)
        {
            ulong rva64 = callbacksVa - ImageBase;
            if (rva64 > uint.MaxValue) return new List<uint>();
            uint callbacksRva = (uint)rva64;
            int off = RvaToOffset(callbacksRva);
            return ReadTLSCallbacksAtOffset(off);
        }
        else
        {
            // Some builders store RVA here; try that.
            uint callbacksRva = (uint)callbacksVa;
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

    #endregion

    #region Resources

    private void ParseResources(uint rva, uint size)
    {
        int baseOff = RvaToOffset(rva);
        if (baseOff < 0) return;

        // the resource directory functions work in the "resource RVA space", which is
        // self-relative: child offsets are relative to the directory's RVA.
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
                // name is stored as RVA relative to the resource directory tree base (dirRva)
                uint nameRva = (e.Name & 0x7FFFFFFF) + (dirRva);
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
                    var dataEntry = Helpers.FromBytes<IMAGE_RESOURCE_DATA_ENTRY>(Data, childOff);
                    re.DataEntry = new ResourceDataEntry
                    {
                        DataRVA = dataEntry.OffsetToData,
                        Size = dataEntry.Size,
                        CodePage = dataEntry.CodePage
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
    /// Convenience: fetch raw bytes for a resource at a path like (type, name, lang).
    /// Passing null for a key is treated as "skip level by index" (not implemented).
    /// Returns null if not found.
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

    #endregion

    #region Write Helpers

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

    #endregion

    #region Models

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

    #endregion
}
