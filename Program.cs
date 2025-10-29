using System;
using System.IO;

namespace Marina
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string pePath;

            // Check if a file path was passed as a command-line argument
            if (args.Length > 0)
            {
                // Non-interactive (CI) mode
                pePath = args[0];
            }
            else
            {
                // Interactive mode
                Helpers.PrintBanner();
                Console.Write("Enter path to PE file (DLL or EXE): ");
                pePath = Console.ReadLine();
            }

            // Basic validation
            if (string.IsNullOrEmpty(pePath) || !File.Exists(pePath))
            {
                Console.WriteLine($"[!] ERROR: File not found or path is empty: '{pePath}'");
                return;
            }

            PEBinary pe = null;
            IntPtr nativeBase = IntPtr.Zero; // Defined here for use in finally block

            try
            {
                pe = new PEBinary(pePath);
                Console.WriteLine($"[+] Parsed. Arch: {(pe.Is64Bit ? "x64" : "x86")}, Type: {(pe.IsDll ? "DLL" : "EXE")}");

                nativeBase = pe.LoadImage(PEBinary.DefaultWin32Resolver);
                Console.WriteLine($"[+] Image loaded at: 0x{nativeBase.ToInt64():X}");

                // This logic from your original file will now work for BOTH
                // interactive use and the CI build, as it waits for EXEs
                // to finish.
                IntPtr hThread = pe.ExecuteLoadedImage(nativeBase, false); // false = don't wait

                if (hThread != IntPtr.Zero)
                {
                    Console.WriteLine($"[+] EXE launched in new thread. Handle: 0x{hThread.ToInt64():X}");
                    // This wait is crucial for the CI build to capture output
                    Native.WaitForSingleObject(hThread, Native.INFINITE);
                    Console.WriteLine("[+] Thread exited.");
                    Native.CloseHandle(hThread);
                }
                else
                {
                    Console.WriteLine("[+] DLLMain(ATTACH) called. Load complete.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] ERROR: {ex.Message}");
            }
            finally
            {
                if (pe != null && nativeBase != IntPtr.Zero && pe.IsDll)
                {
                    Console.WriteLine("[+] Unloading DLL...");
                    pe.UnloadImage(nativeBase);
                    PEBinary.ClearResolverCache();
                }
            }
        }
    }
}