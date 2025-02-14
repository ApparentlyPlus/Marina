using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Marina
{
    public static class Helpers
    {
        // Helper function to read a structure of type T from bytes starting at the given offset.
        public static T FromBytes<T>(byte[] Data, int offset) where T : struct
        {
            int size = Marshal.SizeOf(typeof(T));
            byte[] bytes = new byte[size];
            Buffer.BlockCopy(Data, offset, bytes, 0, size);
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T result = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return result;
        }
    }
}
