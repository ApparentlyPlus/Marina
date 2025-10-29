
using System.IO;

namespace Marina
{
    internal class Program
    {
        static void Main(string[] args)
        {
            PEBinary pe = new PEBinary(Console.ReadLine());

            Console.WriteLine($"[+] Architecture: {(pe.Is64Bit ? "x64 (PE32+)" : "x86 (PE32)")}");
            Console.WriteLine($"[+] ImageBase: 0x{pe.ImageBase:X}");
            Console.WriteLine($"[+] EntryPoint: 0x{pe.AddressOfEntryPoint:X}");
            Console.WriteLine($"[+] Sections: {pe.SectionHeaders.Count}");

            foreach (var s in pe.SectionHeaders)
                Console.WriteLine($"    - {s.SectionName,-8} RVA=0x{s.VirtualAddress:X8} Size=0x{s.VirtualSize:X8}");

            // 2. Build a mapped image (like the Windows loader does)
            Console.WriteLine("[*] Building in-memory image...");
            var image = pe.BuildImageBuffer();
            Console.WriteLine($"[+] Image mapped successfully (Size: {image.Length / 1024.0:F1} KB)");

            // 3. Apply relocations if we pretend to load at a different base
            ulong newBase = pe.ImageBase + 0x100000; // just offset by 1MB for demo
            Console.WriteLine($"[*] Applying relocations to new base 0x{newBase:X}...");
            pe.ApplyRelocations(newBase);
            Console.WriteLine("[+] Relocations applied.");

            // 4. Emulate Import Address Table writes
            Console.WriteLine("[*] Resolving imports...");
            pe.EmulateIATWrite((dll, name, ordinal) =>
            {
                // Simple resolver for demo — just return fake pointers.
                // Real loader would use GetProcAddress(LoadLibrary(dll), name/ordinal)
                ulong fakeAddress = (ulong)(0x7FFF00000000 + ((ulong)dll.GetHashCode() & 0xFFFFFF) + (ulong)(name?.GetHashCode() ?? ordinal ?? 0));
                Console.WriteLine($"    {dll}!{(name ?? $"Ordinal{ordinal}")} -> 0x{fakeAddress:X}");
                return fakeAddress;
            });

            Console.WriteLine("[+] Imports resolved.");

            // 5. Display exports
            if (pe.Exports.Count > 0)
            {
                Console.WriteLine("[*] Exported functions:");
                foreach (var exp in pe.Exports)
                    Console.WriteLine($"    {exp.Name} (Ordinal {exp.Ordinal}) RVA=0x{exp.AddressRva:X}");
            }

            // 6. Display TLS callbacks (if any)
            if (pe.TLS != null && pe.TLS.CallbackRVAs.Count > 0)
            {
                Console.WriteLine("[*] TLS Callbacks:");
                foreach (var cb in pe.TLS.CallbackRVAs)
                    Console.WriteLine($"    Callback RVA=0x{cb:X}");
            }

            // 7. (Optional) Access resources
            if (pe.Resources != null)
            {
                Console.WriteLine("[*] Resource directory parsed successfully.");
                // You can explore pe.Resources.Entries recursively
            }

            Console.WriteLine("[✓] PE loaded and parsed successfully.");
        }
    }
}
