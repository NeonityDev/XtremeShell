using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace XtremeShell5
{
    public static class RecycleBinClear
    {
        [Flags]
        private enum RecycleFlags : uint
        {
            SHERB_NOCONFIRMATION = 0x00000001,
            SHERB_NOPROGRESSUI = 0x00000002,
            SHERB_NOSOUND = 0x00000004
        }

        [DllImport("Shell32.dll", CharSet = CharSet.Unicode)]
        private static extern uint SHEmptyRecycleBin(
            IntPtr hwnd,
            string? pszRootPath,
            RecycleFlags dwFlags
        );

        public sealed record Result(bool Success, uint HResult);

        public static Task<Result> EmptyAsync(string? rootPath = null)
        {
            return Task.Run(() =>
            {
                var flags = RecycleFlags.SHERB_NOCONFIRMATION
                          | RecycleFlags.SHERB_NOPROGRESSUI
                          | RecycleFlags.SHERB_NOSOUND;

                uint hr = SHEmptyRecycleBin(IntPtr.Zero, rootPath, flags);
                return new Result(hr == 0, hr);
            });
        }
    }
}
