using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;

// Windows SDK: fwpmu.h, fwpmtypes.h, fwptypes.h. x64 only.
public sealed class VpnGuard : IDisposable
{
    public static readonly Guid Policy = new Guid("83db10ed-b467-43ec-87a9-6ea72d170af1");
    public static readonly Guid TestPolicy = new Guid("b48a527c-0b16-475d-bb24-81d477f20a53");
    static readonly Guid App = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static readonly Guid Package = new Guid("71bc78fa-f17c-4997-a602-6abb261f351c");
    static readonly Guid LocalInterface = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
    static readonly Guid Flags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");
    static readonly Guid[] Layers = {
        new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), // AUTH_CONNECT v4
        new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"), // AUTH_CONNECT v6
        new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), // AUTH_RECV_ACCEPT v4
        new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f")  // AUTH_RECV_ACCEPT v6
    };
    IntPtr engine;
    readonly Guid policy;
    readonly bool persistent;
    IntPtr readSecurity;

    [StructLayout(LayoutKind.Sequential)] struct Display { public IntPtr name, description; }
    [StructLayout(LayoutKind.Sequential)] struct Blob { public uint size; public IntPtr data; }
    [StructLayout(LayoutKind.Explicit, Size=16)] struct Value {
        [FieldOffset(0)] public uint type;
        [FieldOffset(8)] public uint number;
        [FieldOffset(8)] public IntPtr pointer;
    }
    [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid key; public uint match; public Value value; }
    [StructLayout(LayoutKind.Sequential)] struct Action { public uint type; public Guid key; }
    [StructLayout(LayoutKind.Explicit, Size=16)] struct Context { [FieldOffset(0)] public ulong raw; }
    [StructLayout(LayoutKind.Sequential)] struct Filter {
        public Guid key; public Display display; public uint flags; public IntPtr provider;
        public Blob data; public Guid layer, sublayer; public Value weight;
        public uint count; public IntPtr conditions; public Action action; public Context context;
        public IntPtr reserved; public ulong id; public Value effectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] struct Sublayer {
        public Guid key; public Display display; public uint flags; public IntPtr provider;
        public Blob data; public ushort weight;
    }
    [StructLayout(LayoutKind.Sequential)] struct Session {
        public Guid key; public Display display; public uint flags, timeout, processId;
        public IntPtr sid, username; public int kernel;
    }
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server, uint auth, IntPtr identity, ref Session session, out IntPtr handle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr handle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr handle, uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr handle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr handle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr handle, ref Sublayer layer, IntPtr security);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr handle, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr handle, ref Filter filter, IntPtr security, out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteById0(IntPtr handle, ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr handle, ref Guid key, out IntPtr filter);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr handle, IntPtr template, out IntPtr iterator);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr handle, IntPtr iterator, uint count, out IntPtr entries, out uint returned);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr handle, IntPtr iterator);
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string path, out IntPtr blob);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("iphlpapi.dll")] static extern uint ConvertInterfaceGuidToLuid(ref Guid guid, out ulong luid);
    [DllImport("userenv.dll", CharSet=CharSet.Unicode)] static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);

    static void Check(uint code, string operation) {
        if (code != 0) throw new Win32Exception(unchecked((int)code), operation + " failed: 0x" + code.ToString("X8"));
    }
    public static void CheckLayout() {
        if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(Filter)) != 200 ||
            Marshal.SizeOf(typeof(Condition)) != 40 || Marshal.SizeOf(typeof(Value)) != 16 ||
            Marshal.OffsetOf(typeof(Filter), "conditions").ToInt32() != 120)
            throw new InvalidOperationException("Unsupported native WFP structure layout; x64 required.");
    }
    public VpnGuard(bool test) : this(test, !test) { }
    public VpnGuard(bool test, bool keep) : this(test, keep, WindowsIdentity.GetCurrent().User.Value) { }
    public VpnGuard(bool test, bool keep, string readerSid) : this(test, keep, readerSid, !keep) { }
    public VpnGuard(bool test, bool keep, string readerSid, bool dynamicSession) {
        CheckLayout(); policy = test ? TestPolicy : Policy; persistent = keep;
        Session session = new Session(); session.flags = dynamicSession ? 1u : 0u;
        Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out engine), "Open WFP engine (administrator required)");
        uint sdSize;
        // The tray monitor may read these objects, but cannot edit them or enumerate global policy.
        readerSid = new SecurityIdentifier(readerSid).Value;
        string sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;" + readerSid + ")";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out readSecurity, out sdSize)) {
            int error = Marshal.GetLastWin32Error(); Dispose(); throw new Win32Exception(error);
        }
    }
    // Return managed copies: native display pointers cannot survive enumeration cleanup.
    List<Filter> OwnFilters() {
        List<Filter> result = new List<Filter>(); IntPtr iterator;
        Check(FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out iterator), "Enumerate filters");
        try {
            while (true) {
                IntPtr entries = IntPtr.Zero; uint count;
                Check(FwpmFilterEnum0(engine, iterator, 256, out entries, out count), "Read filters");
                try {
                    for (int i=0; i<count; i++) {
                        Filter f = (Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries, i*IntPtr.Size), typeof(Filter));
                        if (f.sublayer == policy) {
                            // Only the id/key/flags are consumed after the buffer is freed.
                            f.display = new Display(); result.Add(f);
                        }
                    }
                } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
                if (count == 0) break;
            }
        } finally { FwpmFilterDestroyEnumHandle0(engine, iterator); }
        return result;
    }
    public int Count() { return OwnFilters().Count; }
    public int DisabledCount() { return OwnFilters().FindAll(delegate(Filter f) { return (f.flags & 0x20) != 0; }).Count; }
    public string[] ProofKeys() { return OwnFilters().ConvertAll(delegate(Filter f) { return f.key.ToString(); }).ToArray(); }
    public static bool IsActive(string[] keys) {
        if (keys == null || keys.Length == 0) return false;
        using (VpnGuard guard = new VpnGuard(false)) {
            foreach (string text in keys) {
                Guid key = new Guid(text); IntPtr memory;
                uint code = FwpmFilterGetByKey0(guard.engine, ref key, out memory);
                if (code == 0x80320003u) return false;
                Check(code, "Read own filter");
                try {
                    Filter filter = (Filter)Marshal.PtrToStructure(memory, typeof(Filter));
                    if (filter.sublayer != Policy || (filter.flags & 0x20) != 0) return false;
                } finally { FwpmFreeMemory0(ref memory); }
            }
        }
        return true;
    }
    public int Replace(string[] paths, string[] packages, string[] tunnelGuids, bool locked) {
        if (paths == null || paths.Length == 0) throw new ArgumentException("No executable targets.");
        if (packages == null || tunnelGuids == null) throw new ArgumentException("Missing policy fields.");
        List<ulong> luids = new List<ulong>();
        foreach (string text in tunnelGuids) {
            Guid g = new Guid(text); ulong luid;
            // A missing adapter must never broaden access. Keep only the unconditional block.
            if (ConvertInterfaceGuidToLuid(ref g, out luid) == 0 && !luids.Contains(luid)) luids.Add(luid);
        }
        List<Filter> previous = OwnFilters();
        Check(FwpmTransactionBegin0(engine, 0), "Begin atomic policy update");
        try {
            Sublayer sub = new Sublayer(); sub.key = policy; sub.flags = persistent ? 1u : 0u; sub.weight = 0xFF00;
            sub.display.name = Marshal.StringToHGlobalUni("VPN Guard: selected applications");
            try {
                uint code = FwpmSubLayerAdd0(engine, ref sub, IntPtr.Zero);
                if (code != 0 && code != 0x80320009u) Check(code, "Add sublayer");
            } finally { Marshal.FreeHGlobal(sub.display.name); }
            int added = 0;
            foreach (string path in paths) {
                if (String.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path) || !File.Exists(path) ||
                    !String.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Executable missing or invalid: " + path);
                IntPtr blob;
                Check(FwpmGetAppIdFromFileName0(Path.GetFullPath(path), out blob), "Resolve executable " + path);
                try {
                    Condition identity = new Condition(); identity.key = App; identity.value.type = 12; identity.value.pointer = blob;
                    added += AddIdentity(identity, Path.GetFileName(path), luids, locked);
                } finally { FwpmFreeMemory0(ref blob); }
            }
            foreach (string family in packages) {
                if (String.IsNullOrWhiteSpace(family) || !family.Contains("_")) throw new ArgumentException("Invalid package family.");
                IntPtr sid;
                int sidResult = DeriveAppContainerSidFromAppContainerName(family, out sid);
                if (sidResult != 0) Marshal.ThrowExceptionForHR(sidResult);
                try {
                    Condition identity = new Condition(); identity.key = Package; identity.value.type = 13; identity.value.pointer = sid;
                    added += AddIdentity(identity, family, luids, locked);
                } finally { FreeSid(sid); }
            }
            foreach (Filter old in previous) Check(FwpmFilterDeleteById0(engine, old.id), "Replace previous filter");
            Check(FwpmTransactionCommit0(engine), "Commit policy"); return added;
        } catch { FwpmTransactionAbort0(engine); throw; }
    }
    int AddIdentity(Condition identity, string label, List<ulong> luids, bool locked) {
        int count = 0;
        foreach (Guid layer in Layers) {
            AddFilter(layer, new Condition[] { identity }, false, 1, label + " / BLOCK outside VPN"); count++;
            // Local callbacks and IPC remain available. A local forwarding proxy is outside this policy's scope.
            Condition loopback = new Condition(); loopback.key = Flags; loopback.match = 6;
            loopback.value.type = 3; loopback.value.number = 1;
            AddFilter(layer, new Condition[] { identity, loopback }, true, 15, label + " / local IPC"); count++;
            if (!locked) foreach (ulong luid in luids) {
                IntPtr value = Marshal.AllocHGlobal(8);
                try {
                    Marshal.WriteInt64(value, unchecked((long)luid));
                    Condition nic = new Condition(); nic.key = LocalInterface; nic.value.type = 4; nic.value.pointer = value;
                    AddFilter(layer, new Condition[] { identity, nic }, true, 14, label + " / trusted VPN"); count++;
                } finally { Marshal.FreeHGlobal(value); }
            }
        }
        return count;
    }
    void AddFilter(Guid layer, Condition[] conditions, bool allow, uint weight, string label) {
        int size = Marshal.SizeOf(typeof(Condition)); IntPtr buffer = Marshal.AllocHGlobal(size*conditions.Length);
        IntPtr name = Marshal.StringToHGlobalUni("VPN Guard / " + label);
        try {
            for (int i=0; i<conditions.Length; i++) Marshal.StructureToPtr(conditions[i], IntPtr.Add(buffer,i*size), false);
            Filter f = new Filter(); f.key = Guid.NewGuid(); f.display.name = name;
            // No provider dependency: persistent filters must remain enabled when BFE restarts.
            f.flags = persistent ? 1u : 0u; f.layer = layer; f.sublayer = policy;
            f.weight.type = 1; f.weight.number = weight;
            f.count = (uint)conditions.Length; f.conditions = buffer;
            f.action.type = allow ? 0x1002u : 0x1001u; // soft permit; do not override another provider's blocks
            ulong id; Check(FwpmFilterAdd0(engine, ref f, readSecurity, out id), "Add " + label);
        } finally { Marshal.FreeHGlobal(buffer); Marshal.FreeHGlobal(name); }
    }
    public void Remove() {
        List<Filter> filters = OwnFilters();
        Check(FwpmTransactionBegin0(engine, 0), "Begin removal");
        try {
            foreach (Filter filter in filters) Check(FwpmFilterDeleteById0(engine, filter.id), "Delete own filter");
            Guid key = policy; uint code = FwpmSubLayerDeleteByKey0(engine, ref key);
            if (code != 0 && code != 0x80320007u) Check(code, "Delete own sublayer");
            Check(FwpmTransactionCommit0(engine), "Commit removal");
        } catch { FwpmTransactionAbort0(engine); throw; }
    }
    public void Dispose() {
        if (engine != IntPtr.Zero) { FwpmEngineClose0(engine); engine = IntPtr.Zero; }
        if (readSecurity != IntPtr.Zero) { LocalFree(readSecurity); readSecurity = IntPtr.Zero; }
    }
}
