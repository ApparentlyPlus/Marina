# Marina: A C# Reflective Windows PE Loader

[![Marina CI](https://github.com/ApparentlyPlus/Marina/actions/workflows/dotnet.yml/badge.svg)](https://github.com/ApparentlyPlus/Marina/actions/workflows/dotnet.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.txt)
![.NET 8.0](https://img.shields.io/badge/runtime-.NET%208.0-512bd4)
![x86 | x64](https://img.shields.io/badge/arch-x86%20%7C%20x64-1263cf)

`Marina` is an educational C# project that demonstrates **Reflective PE Loading**: parsing a Windows Portable Executable (`.exe` or `.dll`) from disk, manually replicating what the OS loader (`ntdll`) normally does, and running it directly inside your own process memory.

This is **not** a wrapper around `Process.Start()`. There is no process creation, no fork, and no OS loader intervention. It parses the headers, maps sections into memory, applies base relocations, resolves the Import Address Table (IAT) on the fly, executes TLS callbacks, and jumps straight into the entry point.

I wrote this in managed C# with raw P/Invoke and byte buffers to see how cleanly the mechanics of the Windows loader could be expressed without dropping to C++.

> [!WARNING]
> **Use this strictly for research and learning on your own compiled binaries.**
> Reflective loading is the same underlying mechanism used by in-memory implants and shellcode loaders to evade disk-based detection. It executes native machine code directly inside the host process with full privileges. Running untrusted PEs is a great way to either get pwned or crash your host with a `0xc0000005` (`STATUS_ACCESS_VIOLATION`).

> [!CAUTION]
> Don't get any funny ideas, btw. I kept this barebones on purpose so that nobody can just waltz in and load arbitrary off-the-shelf malware. It only runs simple, standalone binaries, without CRT, so there is no meaningful attack vector here. It is a purely educational project.


## How It Works

Windows PE files on disk look very different from how they look when mapped into virtual memory. Marina replicates the four core jobs of the Windows loader:

```
[ Disk PE ] ──> Parse Headers & Directories
            ──> Map Sections into Virtual Buffer
            ──> Apply Relocations (Base Delta)
            ──> Resolve IAT (LoadLibrary / GetProcAddress)
            ──> Copy to Executable Memory (VirtualAlloc RWX)
            ──> Invoke TLS Callbacks ──> Jump to Entry Point
```

1. **Parsing (`TryParse`)**: Reads the DOS header (`MZ`), locates the NT headers via `e_lfanew`, validates the signature (`PE\0\0`), detects architecture (`0x10b` for 32-bit, `0x20b` for 64-bit), and enumerates the section table and data directories.
2. **Memory Mapping (`BuildImageBuffer`)**: Allocates a contiguous image buffer sized to `SizeOfImage`. Copies the headers into the base, then walks the section headers to place each section from disk (`PointerToRawData`) into its virtual address (`VirtualAddress`), zero-padding uninitialized space like `.bss`.
3. **Base Relocations (`ApplyRelocations`)**: When Windows compiles a PE, it assumes a preferred `ImageBase`. Because `VirtualAlloc` gives us a different address, every hardcoded absolute pointer in the binary is now broken. Marina parses `.reloc`, calculates `delta = newBase - preferredBase`, and patches every referenced address in the buffer.
4. **Import Resolution (`EmulateIATWrite`)**: The binary doesn't know where system APIs like `MessageBoxA` or `WriteFile` will live in memory. Marina walks the import descriptors (`.idata`), loads each required DLL via `LoadLibrary`, grabs the real export address via `GetProcAddress`, and writes the live pointer into the Import Address Table (IAT). Delay-load imports are also supported.
5. **Execution (`ExecuteLoadedImage`)**: Copies the patched buffer into executable native memory, fires any registered Thread-Local Storage (TLS) callbacks, and executes:
   * **DLLs**: Resolves the entry point and invokes `DllMain(DLL_PROCESS_ATTACH)` directly on the current thread.
   * **EXEs**: Calls `CreateThread` targeting `AddressOfEntryPoint` to launch the binary in a new thread inside the host process.


## Supported Data Directories

| Directory | Supported | What Marina does with it |
|---|:---:|---|
| **Imports (`.idata`)** | Yes | Walks DLL thunks and resolves live function pointers into the IAT. |
| **Delay Imports** | Yes | Parsed and bound upfront alongside standard imports. |
| **Relocations (`.reloc`)** | Yes | Patches `HIGHLOW` (x86) and `DIR64` (x64) relocation blocks. |
| **TLS (`.tls`)** | Yes | Enumerates TLS callback RVAs and fires them before the entry point runs. |
| **Exports (`.edata`)** | Yes | Parsed for inspection (function, name, and ordinal tables). |
| **Resources (`.rsrc`)** | Yes | Basic directory tree parsing. |


## What's *not* Supported (And Why)

Better to know upfront:

* **No C-Runtime (CRT) Initialization**: Standard release builds compiled against MSVCRT expect things like stack canary cookies (`/GS`), Structured Exception Handling tables (`DD_EXCEPTION`), and runtime tables (`DD_LOAD_CONFIG`) to be set up by the OS before `main` runs. Marina is intentionally minimal, because emulating the entire CRT startup routine is out of scope and dangerous. Target binaries must be compiled without the CRT.
* **No Cross-Architecture Loading**: An x64 process cannot execute 32-bit code (or vice versa) in the same address space without WOW64 transitions. Your host build of Marina must match the architecture of the PE you're loading.
* **No Per-Section Page Protections**: For simplicity, Marina allocates the entire image buffer with `PAGE_EXECUTE_READ_WRITE`. Applying granular `PAGE_READONLY`, `PAGE_EXECUTE_READ`, and `PAGE_READWRITE` protections across individual sections via `VirtualProtect` is left as an exercise for the reader.
* **No Process Hollowing / Remote Injection**: Marina is an in-process loader. It doesn't spawn suspended processes, unmap memory, or inject into external targets.


## Quickstart

### Running Marina

Requirements: **.NET 8.0 SDK** on Windows.

```bash
# Clone and build
git clone https://github.com/ApparentlyPlus/Marina.git
cd Marina
dotnet build -c Release /p:Platform="Any CPU"

# Run interactively (prompts for file path)
dotnet run --project Marina.csproj

# Or pass the PE path directly
dotnet run --project Marina.csproj -- path\to\target.exe
```

### Using the API in C#

You can also use `PEBinary` directly in your own code:

```csharp
using Marina;

// Parse the PE from disk
var pe = new PEBinary("minimal.exe");
Console.WriteLine($"[+] Parsed: {(pe.Is64Bit ? "x64" : "x86")} {(pe.IsDll ? "DLL" : "EXE")}");

// Map, allocate native memory, apply relocations, and resolve IAT
IntPtr nativeBase = pe.LoadImage(PEBinary.DefaultWin32Resolver);
Console.WriteLine($"[+] Loaded at: 0x{nativeBase.ToInt64():X}");

// Run TLS callbacks and jump to entry point
IntPtr hThread = pe.ExecuteLoadedImage(nativeBase, waitForThread: true);

if (hThread != IntPtr.Zero)
{
    // For EXEs: wait for the thread to complete
    Native.WaitForSingleObject(hThread, Native.INFINITE);
    Native.CloseHandle(hThread);
}
else
{
    Console.WriteLine("[+] DLLMain called.");
}

// Cleanup (for DLLs)
if (pe.IsDll && nativeBase != IntPtr.Zero)
{
    pe.UnloadImage(nativeBase);
    PEBinary.ClearResolverCache();
}
```


## How to Build a Compatible Test Binary

Because Marina does not provide CRT startup scaffolding, you need to compile test binaries **without the C Runtime and without security cookies**:

### 1. Minimal Console Binary (`minimal.c`)

```c
#include <windows.h>

const char msg[] = "Hello from in-memory reflective execution!\n";

void MyEntryPoint()
{
    DWORD written;
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(hStdOut, msg, sizeof(msg) - 1, &written, NULL);

    /* Exit the thread cleanly so the host process doesn't terminate */
    ExitThread(0);
}
```

Or for a GUI pop-up:

```c
#include <windows.h>

void MyEntryPoint()
{
    MessageBoxA(NULL, "It works!", "Marina Loader", MB_OK);
    ExitThread(0);
}
```

### 2. Compiling with MSVC

Run this from a **Developer Command Prompt**:

```bash
# Compile without security cookies (/GS-)
cl.exe /c /GS- /nologo minimal.c

# Link with custom entry point and NO default CRT (/NODEFAULTLIB)
link.exe /SUBSYSTEM:CONSOLE /NODEFAULTLIB /ENTRY:MyEntryPoint minimal.obj kernel32.lib
```

For GUI binaries, use `/SUBSYSTEM:WINDOWS` and link `user32.lib`.

* `/GS-`: Disables stack-smashing protection cookies (which require CRT initialization).
* `/NODEFAULTLIB`: Drops standard CRT libraries (`msvcrt`, `libcmt`).
* `/ENTRY:MyEntryPoint`: Tells the linker to start execution directly at your function instead of CRT's `mainCRTStartup`.


## Critical Gotchas

### 1. The Architecture Mismatch
If your Marina host process is running as **64-bit** and you feed it a **32-bit (x86)** binary:
* `GetProcAddress` returns a 64-bit pointer (e.g. `0x00007FFB_12345678`).
* The loader truncates it to 32 bits (`0x12345678`) when writing into the 32-bit IAT.
* The loaded code jumps to garbage memory and instantly dies with `0xc0000005`.

**Fix**: Set `<PlatformTarget>` or build with the matching platform:
* For 32-bit PEs: `dotnet build /p:Platform=x86`
* For 64-bit PEs: `dotnet build /p:Platform="Any CPU"` (or `x64`)

### 2. The CRT Trap
If you compile a test binary with standard `cl.exe main.c` and try to load it, it will crash immediately. The compiler points the entry point to `__scrt_common_main_seh` rather than your code, which immediately probes for CRT security cookies and exception tables that aren't there. Keep test files standalone with `/GS-` and `/NODEFAULTLIB`.


## Repository Layout

```
Submodules/
├── Exports.cs         Export directory (.edata) parsing
├── IAT.cs             Import Address Table emulation and patching
├── Image.cs           Virtual image memory layout builder (BuildImageBuffer)
├── Imports.cs         Import directory (.idata) parsing & Win32 resolver
├── Loading.cs         Memory allocation, image execution, and TLS dispatcher
├── Models.cs          Win32 PE structures (DOS, NT, Section, Data directories)
├── Relocations.cs     Base relocation parsing and delta patching (.reloc)
├── Resources.cs       Resource directory tree parsing (.rsrc)
├── TLS.cs             Thread-Local Storage directory and callback parsing (.tls)
└── WriteHelpers.cs    Memory buffer pointer and integer writer helpers
PEBinary.cs            Main orchestrator: header parsing and directory dispatch
Native.cs              P/Invoke Win32 API declarations
Helpers.cs             Byte marshaling and startup banner
Program.cs             CLI driver and entry point
```


## License

This project is licensed under the [MIT License](LICENSE.txt).