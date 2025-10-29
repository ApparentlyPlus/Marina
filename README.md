# Marina: A C\# Reflective Windows PE Loader

[![Marina CI](https://github.com/ApparentlyPlus/Marina/actions/workflows/dotnet.yml/badge.svg)](https://github.com/ApparentlyPlus/Marina/actions/workflows/dotnet.yml)

`Marina` is an educational C\# project that demonstrates the principles of **Reflective PE Loading**. It is split into C\# files, each implementing a part of the `PEBinary` class that parses a Windows Portable Executable (PE) file (an `.exe` or `.dll`) from disk, manually mimics the actions of the Windows OS loader, and executes the file *within its own process memory*.

This is **not** a wrapper for `Process.Start()`. It performs the complex, low-level operations required to "revive" a PE file from its disk state into a runnable, in-memory image. This project is intended for educational and security research purposes ONLY. 

> [!WARNING]
>
> ### **Security Warning**
>
> This tool is a **Reflective Loader**. It is the same core technology used by malware, shellcode, and in-memory agents to bypass antivirus (AV), endpoint detection (EDR), and application whitelisting.
>
>   * **Do NOT run untrusted PEs with this loader.** It executes arbitrary native code *inside* its own process with full permissions.
>   * Bugs in the loader (or features in the target PE) will cause your application to crash with a `0xc0000005 (STATUS_ACCESS_VIOLATION)` error, or worse.
>   * You are manually bypassing *all* OS security features (like ASLR) and process isolation.
>
> **Use this tool for learning and analysis on files you have compiled yourself.**

> [!CAUTION]
> Don t get any funny ideas, I kept it barebones on purpose. That way, script-kiddies can t just waltz in and load whatever fancy PE they find on the internet.

## Key Features

  * **Full PE Header Parsing:** Reads the DOS, NT, Optional (32/64-bit), and Section headers.
  * **Data Directory Parsing:** Parses the most critical data directories:
      * Imports (`.idata`)
      * Exports (`.edata`)
      * Base Relocations (`.reloc`)
      * Resources (`.rsrc`)
      * Thread-Local Storage (TLS)
      * Delay-Load Imports
  * **In-Memory Image Builder:** Correctly maps the file's sections from their disk layout (`PointerToRawData`) to their virtual memory layout (`VirtualAddress`).
  * **Base Relocation Applier:** Patches the in-memory image to fix all hardcoded addresses, allowing it to run at any memory location.
  * **IAT Resolver:** Emulates the OS loader by resolving the Import Address Table (IAT) using live `LoadLibrary` and `GetProcAddress` calls.
  * **Execution Engine:** Can "jump" to the loaded image's entry point, either by calling `DllMain` (for DLLs) or launching a new thread for an EXE's entry point.
  * **Architecture-Aware:** Correctly handles both 32-bit (x86) and 64-bit (x64) PE files.


## How It Works: An In-Depth Walkthrough

`Marina`'s job is to replicate the four main tasks of the Windows loader:

1.  **Parse** the PE file structure.
2.  **Map** the file from its disk layout to its virtual memory layout.
3.  **Patch** the image by applying relocations and resolving imports.
4.  **Execute** the image's entry point.

### Phase 1: Parsing the File (`TryParse`)

When you create a `PEBinary(string filePath)`, it reads the entire file into `byte[] Data` and begins parsing.

1.  **DOS Header (`IMAGE_DOS_HEADER`):** It starts at offset `0` and reads the DOS header, primarily to check for the `'MZ'` magic signature and to find one crucial field: `e_lfanew`.
2.  **NT Headers (`IMAGE_NT_HEADERS`):** The `e_lfanew` field gives the file offset to the `IMAGE_NT_HEADERS`. This struct is the "table of contents" for the PE file.
      * It checks for the `'PE\0\0'` signature.
      * It reads the `IMAGE_FILE_HEADER` to get `Machine` (x86/x64) and `NumberOfSections`.
3.  **Optional Header (`IMAGE_OPTIONAL_HEADER`):** This is the most important header.
      * The parser checks the `Magic` number (`0x10b` for 32-bit, `0x20b` for 64-bit) and parses either an `IMAGE_OPTIONAL_HEADER32` or `IMAGE_OPTIONAL_HEADER64`.
      * It extracts vital info:
          * `ImageBase`: The *preferred* memory address this file was compiled for.
          * `SizeOfImage`: The *total* size the image will occupy in virtual memory.
          * `AddressOfEntryPoint`: The RVA (Relative Virtual Address) of the first instruction to execute.
          * `DataDirectory`: An array of 16 `IMAGE_DATA_DIRECTORY` structs. This array is the map to everything else. For example, `DataDirectory[1]` points to the Import Table, and `DataDirectory[5]` points to the Relocation Table.
4.  **Section Headers (`IMAGE_SECTION_HEADER`):** Immediately after the optional header, it loops `NumberOfSections` times to read the section headers. Each header describes a block of code or data:
      * `.text`: Executable code.
      * `.data`: Initialized global variables.
      * `.rdata`: Read-only data (like strings).
      * `.idata`: The Import Table.
      * `.reloc`: The Relocation Table.
      * `.bss`: Uninitialized global variables.

### Phase 2: Building the Virtual Image (`BuildImageBuffer`)

A PE file's layout on disk is different from its layout in memory. Sections are packed tightly on disk but are aligned to "pages" in memory, often with gaps. This method builds a `byte[] Image` that mimics the final memory layout.

1.  A new `byte[]` named `Image` is allocated, with the exact size of `SizeOfImage`.
2.  The PE headers (from `Data[0]` up to `SizeOfHeaders`) are copied into `Image[0]`.
3.  The parser iterates through each `IMAGE_SECTION_HEADER`:
      * It copies the section's raw data from the file...
      * **From:** `Data` at `section.PointerToRawData`
      * **To:** `Image` at `section.VirtualAddress`
      * **Length:** `section.SizeOfRawData`
4.  This "mapping" is the core of `BuildImageBuffer`. It correctly places the `.text`, `.data`, and other sections at their proper virtual addresses.
5.  If a section has a `VirtualSize` *larger* than its `SizeOfRawData` (like the `.bss` section for uninitialized variables), the extra space is left as zeros, just as the OS loader would do.

### Phase 3: The "Loader" Magic (Patching the Image)

This is the most critical phase, handled by `LoadImage(resolver)`. It takes the "dead" `Image` buffer and makes it "live."

1.  **Allocate Executable Memory:** The loader calls `VirtualAlloc` to ask Windows for a new block of memory large enough to hold the image (`SizeOfImage`). It requests `PAGE_EXECUTE_READ_WRITE` permissions. Windows returns a *real* base address (e.g., `0x6740000`).
2.  **Apply Base Relocations (`ApplyRelocations`):**
      * **The Problem:** The PE was compiled for a *preferred* `ImageBase` (e.g., `0x400000`). But `VirtualAlloc` just gave us a *different* address (e.g., `0x6740000`). This means every hardcoded address in the code (e.g., `MOV EAX, 0x401000`) is now wrong.
      * **The Solution:** The `.reloc` section (parsed into `BaseRelocations`) is a list of *every single hardcoded address* in the PE that needs to be "fixed."
      * `ApplyRelocations` calculates a `delta = newBase - preferredBase`.
      * It then iterates through thousands of relocation entries. For each entry, it:
          * Goes to the RVA of the hardcoded address in our `Image` buffer.
          * Reads the 32-bit (or 64-bit) value.
          * Adds the `delta` to it.
          * Writes the new, "fixed" value back into the `Image` buffer.
      * This "patches" the entire image to be valid at its new memory address.
3.  **Resolve Imports (`EmulateIATWrite`):**
      * **The Problem:** The PE's code needs to call functions from Windows DLLs (e.g., `MessageBoxA` from `user32.dll`). The PE *doesn't know* the address of `MessageBoxA`. It just has a placeholder in its **Import Address Table (IAT)**.
      * **The Solution:** The `EmulateIATWrite` function iterates through every import (`Imports` list) for every DLL.
      * It calls the provided `ImportResolver` (e.g., `DefaultWin32Resolver`).
      * The resolver (running in *your* C\# process) calls `LoadLibraryA("user32.dll")` and `GetProcAddress(hModule, "MessageBoxA")`.
      * This gets the *real, live memory address* of `MessageBoxA` in your process.
      * This real address is then written into the IAT placeholder in the `Image` buffer.
      * After this, when the loaded code tries to `CALL [MessageBoxA_IAT_SLOT]`, it jumps directly to the real function.
4.  **Copy to Native Memory:** The fully patched `Image` buffer (which was in managed C\# memory) is copied into the executable memory buffer we got from `VirtualAlloc` using `Marshal.Copy`.

### Phase 4: Execution (`ExecuteLoadedImage`)

The image is now live in native, executable memory. All that's left is to jump to it.

1.  **TLS Callbacks:** First, it checks for a `TLSDirectory`. If one exists, it executes any TLS callback functions. This is a "production-ready" step that some programs require *before* their main code runs.
2.  **Find Entry Point:** It gets the `AddressOfEntryPoint` from the optional header.
3.  **Calculate Final Address:** It calculates `pEntryPoint = nativeBase + AddressOfEntryPoint`.
4.  **The Jump:**
      * **If it's an EXE:** It calls `CreateThread` to start a *new thread* in your process, with `pEntryPoint` as the start address. The EXE's code begins running inside your `Marina.exe` process.
      * **If it's a DLL:** It gets a function delegate for `pEntryPoint` and calls it directly, passing the `DLL_PROCESS_ATTACH` reason. This simulates `LoadLibrary` calling `DllMain`.

## Critical Concepts & Gotchas

These are the "hard-won" lessons of PE loading that cause `0xc0000005` crashes.

### 1\. The Architecture Mismatch (The Classic Crash)

**Problem:** You try to load a **32-bit (x86)** PE file, but your `Marina.exe` project is running as **"Any CPU"** on a 64-bit OS, so it defaults to **64-bit (x64)**.

**The Fatal Sequence:**

1.  Your **x64 host** calls `GetProcAddress("MessageBoxA")`.
2.  Windows returns a **64-bit pointer** (e.g., `0x00007FFB_12345678`).
3.  Your loader sees the target PE is 32-bit (`Is64Bit = false`).
4.  `WritePointerToImage` truncates the 64-bit pointer to 32 bits (`(uint)value`).
5.  It writes the **garbage 32-bit value** `0x12345678` into the IAT.
6.  The loaded 32-bit code tries to `CALL [0x12345678]` and instantly crashes.

**Solution:** The host process architecture **MUST** match the target PE architecture.

  * To load **x86 PEs**, set your `Marina` project's `<PlatformTarget>` to **`x86`**.
  * To load **x64 PEs**, set your `Marina` project's `<PlatformTarget>` to **`x64`**.

### 2\. The C-Runtime (CRT) Problem

**Problem:** You try to load a complex, release-build program (like `steam.exe`), and it crashes instantly, even with matching architectures.

**The Reason:**

  * Most C/C++ programs are linked against the **C Runtime (CRT)**.
  * The `AddressOfEntryPoint` for these programs *is not* your `main` or `WinMain` function. It's a CRT startup function (e.g., `__scrt_common_main_seh`).
  * This CRT startup code runs *before* `main` and performs critical initialization that your loader does not provide:
      * It initializes stack-smashing protection (`/GS`), which requires data from the `DD_LOAD_CONFIG` directory.
      * It registers Structured Exception Handlers (SEH) with the kernel, which requires the `DD_EXCEPTION` directory.
      * It initializes global variables, constructors, and more.
  * When the CRT code runs, it finds none of its expected environment and crashes.

**Solution:** This loader, in its current educational form, can only reliably load **simple PE files compiled *without* the CRT.** This is both to prevent malicious use from script kiddies on the internet, and because I reeaally don't have time for anything more complex :P

## How to Use This Loader

```csharp
PEBinary pe = new PEBinary(Console.ReadLine());

try
{
    Console.WriteLine($"[+] Parsed. Arch: {(pe.Is64Bit ? "x64" : "x86")}, Type: {(pe.IsDll ? "DLL" : "EXE")}");

    // Load the image into executable memory
    // This runs BuildImageBuffer, VirtualAlloc, ApplyRelocations, and EmulateIATWrite
    var nativeBase = pe.LoadImage(PEBinary.DefaultWin32Resolver);
    Console.WriteLine($"[+] Image loaded at: 0x{nativeBase.ToInt64():X}");

    //"Jump" to the entry point
    // This runs TLS callbacks and then calls the entry point
    IntPtr hThread = pe.ExecuteLoadedImage(nativeBase, false); // false = don't wait

    if (hThread != IntPtr.Zero)
    {
        Console.WriteLine($"[+] EXE launched in new thread. Handle: 0x{hThread.ToInt64():X}");
        // You could wait for it here if you want
        Native.WaitForSingleObject(hThread, Native.INFINITE);
        Console.WriteLine("[+] Thread exited.");
        Native.CloseHandle(hThread);
    }
    else
    {
        Console.WriteLine("[+] DLLMain(ATTACH) called. Load complete.");
    }

    // Note: If you load a DLL, it's now loaded in your process.
    // If you load an EXE, it's running in a new thread inside your process.
}
catch (Exception ex)
{
    Console.WriteLine($"[!] ERROR: {ex.Message}");
}
finally
{
    // Clean up
    // If you loaded an EXE, you might want to leave it running.
    // If you loaded a DLL, you'd unload it like this:

    // if (pe != null && nativeBase != IntPtr.Zero && pe.IsDll)
    // {
    //    Console.WriteLine("[+] Unloading DLL...");
    //    pe.UnloadImage(nativeBase);
    //    PEBinary.ClearResolverCache();
    // }
}
```

## How to Build a Marina-Friendly Test EXE

To test the loader, you must create a minimal PE without CRT dependencies.

1.  **Save as `minimal.c`:**

    ```c
    #include <windows.h>

    /* Our custom entry point */
    void MyEntryPoint()
    {
        MessageBoxA(NULL, "Hello from the reflectively loaded PE!", "It Worked!", MB_OK);
        
        /* We must exit this thread cleanly, or we crash the host */
        ExitThread(0); 
    }
    ```

2.  **Compile (from a Developer Command Prompt):**

    ```bash
    # 1. Compile (x86):
    cl.exe /c /GS- /nologo minimal.c

    # 2. Link (x86):
    link.exe /SUBSYSTEM:WINDOWS /NODEFAULTLIB /ENTRY:MyEntryPoint minimal.obj user32.lib kernel32.lib
    ```

      * `/GS-`: **Disables security cookies** (which require CRT).
      * `/NODEFAULTLIB`: **Disables the CRT**.
      * `/ENTRY:MyEntryPoint`: Sets our custom entry point.

This `minimal.exe` will now work perfectly with the `Marina` loader.