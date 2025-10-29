
using System.IO;

namespace Marina
{
    internal class Program
    {
        static void Main(string[] args)
        {
            PEBinary pe = new PEBinary(Console.ReadLine());

            try
            {
                Console.WriteLine($"[+] Parsed. Arch: {(pe.Is64Bit ? "x64" : "x86")}, Type: {(pe.IsDll ? "DLL" : "EXE")}");

                // 2. Load the image into executable memory
                // This runs BuildImageBuffer, VirtualAlloc, ApplyRelocations, and EmulateIATWrite
                var nativeBase = pe.LoadImage(PEBinary.DefaultWin32Resolver);
                Console.WriteLine($"[+] Image loaded at: 0x{nativeBase.ToInt64():X}");

                // 3. "Jump" to the entry point
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

        }
    }
}
