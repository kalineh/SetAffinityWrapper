using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;
using System.Runtime.InteropServices;

namespace SetAffinityWrapper
{
    class Program
    {
        private static Process hosted;
        private static List<int> childIds;
        private static IntPtr processAffinity;

        static void Main(string[] args)
        {
            // catch terminate commands
            SetConsoleCtrlHandler(new HandlerRoutine(ConsoleCtrlHandler), true);

            if (args.Length <= 0)
            {
                Console.WriteLine("Insufficient args");
                Console.WriteLine("format: SetAffinityWrapper.exe (affinity-mask) (filename) [args]");
                return;
            }

            var affinity = args[0];
            var filename = args[1];
            var arguments = "";

            for (int i = 2; i < args.Length; ++i)
                arguments += args[i] + ' ';

            // debug testing
            //var filename = "C:\\Program Files\\Unity\\Hub\\Editor\\2018.2.14f1\\Editor\\Unity.exe";
            //var arguments = "-batchmode -quit -projectPath \"C:\\dev\\starboat-baking\\tools\\..\\Unity\\\" -stackTraceLogType Full -executeMethod LightmapBatchBuilder.BuildFake";

            Console.WriteLine(string.Format("SetAffinityWrapper: starting '{0}' with '{1}'...", filename, arguments));

            processAffinity = (IntPtr)System.Convert.ToUInt32(affinity, 16);

            Console.WriteLine(string.Format("> using affinity {0}", processAffinity));

            var cache = new List<PROCESSENTRY32>();

            var processInfo = new ProcessStartInfo(filename, arguments);
            var process = Process.Start(processInfo);
            var processId = process.Id;

            process.ProcessorAffinity = processAffinity;

            // need to check all childrens
            hosted = process;
            childIds = new List<int>();

            while (!process.HasExited)
            {
                Thread.Sleep(500);

                try
                {
                    if (Console.KeyAvailable)
                    {
                        var keyInfo = Console.ReadKey();
                        var key = keyInfo.Key;

                        if (key == ConsoleKey.D0) ChangeAffinityMask(0);
                        if (key == ConsoleKey.D1) ChangeAffinityMask(1);
                        if (key == ConsoleKey.D2) ChangeAffinityMask(2);
                        if (key == ConsoleKey.D3) ChangeAffinityMask(3);
                        if (key == ConsoleKey.D4) ChangeAffinityMask(4);
                        if (key == ConsoleKey.D5) ChangeAffinityMask(5);
                        if (key == ConsoleKey.D6) ChangeAffinityMask(6);
                        if (key == ConsoleKey.D7) ChangeAffinityMask(7);
                        if (key == ConsoleKey.D8) ChangeAffinityMask(8);
                    }
                }
                catch
                {
                    // ignore
                }

                childIds.Clear();

                var sw = Stopwatch.StartNew();

                CacheRebuild(cache);
                CacheFindChildrenProcessIDs(cache, childIds, processId);

                //Console.WriteLine(string.Format("SetAffinityWrapper: > process scan took {0}ms", sw.ElapsedMilliseconds));

                foreach (var childId in childIds)
                {
                    try
                    {
                        var childProc = Process.GetProcessById(childId);
                        if (childProc.ProcessorAffinity != processAffinity)
                        {
                            Console.WriteLine(string.Format("SetAffinityWrapper: > setting affinity: {0} ({1})", childProc.Id, childProc.ProcessName));
                            childProc.ProcessorAffinity = processAffinity;
                        }
                    }
                    catch
                    {
                        // just ignore failures if processes are invalid in any way
                    }

                    //Thread.Sleep(100);
                }
            }

            Console.WriteLine(string.Format("SetAffinityWrapper: process exited, complete"));
        }

        private const int TH32CS_SNAPPROCESS = 0x00000002;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            const int MAX_PATH = 260;
            internal UInt32 dwSize;
            internal UInt32 cntUsage;
            internal UInt32 th32ProcessID;
            internal IntPtr th32DefaultHeapID;
            internal UInt32 th32ModuleID;
            internal UInt32 cntThreads;
            internal UInt32 th32ParentProcessID;
            internal Int32 pcPriClassBase;
            internal UInt32 dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string szExeFile;
        }

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern IntPtr CreateToolhelp32Snapshot([In]UInt32 dwFlags, [In]UInt32 th32ProcessID);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32First([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32Next([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle([In] IntPtr hObject);

        private static void CacheRebuild(List<PROCESSENTRY32> cache)
        {
            cache.Clear();

            IntPtr handleToSnapshot = IntPtr.Zero;
            try
            {
                PROCESSENTRY32 procEntry = new PROCESSENTRY32();
                procEntry.dwSize = (UInt32)Marshal.SizeOf(typeof(PROCESSENTRY32));
                handleToSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (Process32First(handleToSnapshot, ref procEntry))
                {
                    do
                    {
                        cache.Add(procEntry);
                    } while (Process32Next(handleToSnapshot, ref procEntry));
                }
                else
                {
                    Console.WriteLine(string.Format("SetAffinityWrapper: > failed native"));
                }
            }
            catch
            {
                Console.WriteLine(string.Format("SetAffinityWrapper: > native exception"));
            }

            //for (int i = 0; i < processCache.Count; ++i)
                //Console.WriteLine(string.Format("Cache: {0}: {1} <- {2}", i, processCache[i].th32ProcessID, processCache[i].th32ParentProcessID));
        }

        private static void CacheFindChildrenProcessIDs(List<PROCESSENTRY32> cache, List<int> output, int pid)
        {
            for (int i = 0; i < cache.Count; ++i)
            {
                var entry = cache[i];
                if (entry.th32ParentProcessID == pid)
                {
                    output.Add((int)entry.th32ProcessID);
                    CacheFindChildrenProcessIDs(cache, output, (int)entry.th32ProcessID);
                }
            }
        }

        // so slow (100ms+, with 20%~ cpu consumed)
        private static void RecursiveScanChildProcessesWMI(List<Process> output, int parentId)
        {
            var query = string.Format("SELECT * FROM Win32_Process WHERE ParentProcessId={0}", parentId);
            var search = new ManagementObjectSearcher(query);
            var results = search.Get();

            foreach (var result in results)
            {
                var pid = (int)((UInt32)result["ProcessId"]);
                var process = (Process)null;

                try
                {
                    process = Process.GetProcessById(pid);
                }
                catch
                {
                    // not valid pid, safe to ignore
                    continue;
                }

                output.Add(process);
                RecursiveScanChildProcessesWMI(output, pid);
            }
        }

        [DllImport("Kernel32")]
        public static extern bool SetConsoleCtrlHandler(HandlerRoutine Handler, bool Add);

        public delegate bool HandlerRoutine(CtrlTypes CtrlType);

        public enum CtrlTypes
        {
            CTRL_C_EVENT = 0,
            CTRL_BREAK_EVENT,
            CTRL_CLOSE_EVENT,
            CTRL_LOGOFF_EVENT = 5,
            CTRL_SHUTDOWN_EVENT
        }

        private static bool ConsoleCtrlHandler(CtrlTypes ctrlType)
        {
            Console.WriteLine(string.Format("SetAffinityWrapper: > ctrl handler: {0}", ctrlType));

            switch (ctrlType)
            {
                case CtrlTypes.CTRL_C_EVENT: TerminateAll(); break;
                case CtrlTypes.CTRL_BREAK_EVENT:  TerminateAll(); break;
                case CtrlTypes.CTRL_CLOSE_EVENT:  TerminateAll(); break;
                case CtrlTypes.CTRL_LOGOFF_EVENT: TerminateAll(); break;
                case CtrlTypes.CTRL_SHUTDOWN_EVENT: TerminateAll(); break;
            }

            return true;
        }

        private static void TerminateAll()
        {
            Console.WriteLine(string.Format("SetAffinityWrapper: > terminating with {0} child processes", childIds.Count));

            var processId = Process.GetCurrentProcess().Id;

            foreach (var childId in childIds)
            {
                try
                {
                    if (childId == processId)
                        continue;

                    var childProc = Process.GetProcessById(childId);
                    if (childProc == null)
                        continue;

                    if (childProc.HasExited)
                        continue;

                    // cannot access process name for some reason
                    //Console.WriteLine(string.Format("SetAffinityWrapper: > terminate child {0} ({1})}", child.ProcessName, child.Id));
                    Console.WriteLine(string.Format("SetAffinityWrapper: > terminate child ({0})", childId));

                    childProc.Kill();
                }
                catch
                {
                    // ignore
                }
            }

            try
            {
                Console.WriteLine(string.Format("SetAffinityWrapper: > terminate hosted ({0})", hosted.Id));
                hosted.Kill();
            }
            catch
            {
            }

            Environment.Exit(0);
        }

        private static void ChangeAffinityMask(int cores)
        {
            var mask = 0;
            for (int i = 0; i < cores; ++i)
                mask = mask | (1 << i);

            processAffinity = (IntPtr)mask;

            Console.WriteLine(string.Format("SetAffinityWrapper: > changed affinity to {0} cores (mask: {1})", cores, mask));
        }
    }
}
