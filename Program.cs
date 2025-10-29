
namespace Marina
{
    internal class Program
    {
        static void Main(string[] args)
        {
            PEBinary pe = new PEBinary(Console.ReadLine());
            Console.WriteLine($"ImageBase: 0x{pe.ImageBase:X}, Entry: 0x{pe.AddressOfEntryPoint:X}");
            foreach (var imp in pe.Imports)
            {
                Console.WriteLine("DLL: " + imp.DLLName);
                foreach (var e in imp.Entries)
                    Console.WriteLine($"  {(e.ByOrdinal ? $"Ordinal {e.Ordinal}" : e.Name)}");
            }
            var image = pe.BuildImageBuffer(); // get the in-memory mapped image bytes
        }
    }
}
