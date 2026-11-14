using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace PCKumanda {
    internal static class SocketLifetime {
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
        public static void Private(System.Net.Sockets.Socket socket) {
            if (!SetHandleInformation(socket.Handle,1,0))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
    }
    internal static class DesktopFeatures {
        public static int Monitor = -1;
        public static Rectangle Bounds {
            get { Screen[] screens = Screen.AllScreens; int selected = Monitor;
                return selected >= 0 && selected < screens.Length ? screens[selected].Bounds : SystemInformation.VirtualScreen; }
        }
        public static string Monitors() {
            var list = new List<object>(); Screen[] screens = Screen.AllScreens;
            for (int i=0;i<screens.Length;i++) list.Add(new {id=i, name="Ekran " + (i+1), primary=screens[i].Primary,
                width=screens[i].Bounds.Width,height=screens[i].Bounds.Height});
            return new JavaScriptSerializer().Serialize(new {ok=true, selected=Monitor, monitors=list});
        }
        private static readonly object gate = new object();
        private static ulong oldIdle,oldKernel,oldUser;
        private static long oldNetwork,oldStamp;
        private static string cachedCpuName = "";
        private static double cachedCpuSpeedGHz = 0;
        private static int cachedCpuCores = 0;
        private static PerformanceCounter diskWriteCounter;
        private static PerformanceCounter diskReadCounter;
        private static bool countersFailed = false;

        private static void InitCpuInfo() {
            if (cachedCpuCores > 0) return;
            try {
                cachedCpuCores = Environment.ProcessorCount;
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0")) {
                    if (key != null) {
                        object nameObj = key.GetValue("ProcessorNameString");
                        if (nameObj != null) cachedCpuName = nameObj.ToString().Trim();
                        object mhzObj = key.GetValue("~MHz");
                        if (mhzObj != null) {
                            int mhz = Convert.ToInt32(mhzObj);
                            cachedCpuSpeedGHz = Math.Round(mhz / 1000.0, 2);
                        }
                    }
                }
            } catch {}
        }

        [StructLayout(LayoutKind.Sequential)] private struct Memory {
            public uint length,load; public ulong totalPhys,availPhys,totalPage,availPage,totalVirtual,availVirtual,extended;
        }
        [DllImport("kernel32.dll")] private static extern bool GlobalMemoryStatusEx(ref Memory m);
        [DllImport("kernel32.dll")] private static extern bool GetSystemTimes(out long idle,out long kernel,out long user);
        public static string Stats() {
            lock(gate) {
                InitCpuInfo();
                long idle,kernel,user; double cpu=-1,network=0;
                if(GetSystemTimes(out idle,out kernel,out user)) {
                    ulong total=(ulong)kernel-oldKernel+(ulong)user-oldUser;
                    if(oldKernel!=0 && total>0) cpu=Math.Max(0,Math.Min(100,100.0*(total-((ulong)idle-oldIdle))/total));
                    oldIdle=(ulong)idle; oldKernel=(ulong)kernel; oldUser=(ulong)user;
                }
                Memory m=new Memory(); m.length=(uint)Marshal.SizeOf(typeof(Memory));
                bool memoryOk=GlobalMemoryStatusEx(ref m);
                long bytes=0;
                foreach(var nic in NetworkInterface.GetAllNetworkInterfaces())
                    if(nic.OperationalStatus==OperationalStatus.Up && nic.NetworkInterfaceType!=NetworkInterfaceType.Loopback)
                        try { var n=nic.GetIPv4Statistics(); bytes+=n.BytesReceived+n.BytesSent; } catch {}
                long stamp=Stopwatch.GetTimestamp();
                if(oldStamp!=0 && bytes>=oldNetwork) network=(bytes-oldNetwork)*Stopwatch.Frequency/(double)(stamp-oldStamp)/1024;
                oldNetwork=bytes;oldStamp=stamp;
                var battery=SystemInformation.PowerStatus;
                bool hasBattery=(battery.BatteryChargeStatus & BatteryChargeStatus.NoSystemBattery)==0 && battery.BatteryChargeStatus!=BatteryChargeStatus.Unknown;

                double diskWriteMBs = 0, diskReadMBs = 0;
                if (!countersFailed) {
                    try {
                        if (diskWriteCounter == null) {
                            diskWriteCounter = new PerformanceCounter("PhysicalDisk", "Disk Write Bytes/sec", "_Total");
                            diskReadCounter = new PerformanceCounter("PhysicalDisk", "Disk Read Bytes/sec", "_Total");
                            diskWriteCounter.NextValue();
                            diskReadCounter.NextValue();
                        } else {
                            diskWriteMBs = Math.Round(diskWriteCounter.NextValue() / (1024.0 * 1024.0), 1);
                            diskReadMBs = Math.Round(diskReadCounter.NextValue() / (1024.0 * 1024.0), 1);
                        }
                    } catch {
                        countersFailed = true;
                    }
                }
                double ramUsed = memoryOk ? Math.Round((m.totalPhys - m.availPhys) / 1073741824.0, 1) : 0;
                double ramTotal = memoryOk ? Math.Round(m.totalPhys / 1073741824.0, 1) : 0;
                double ramAvail = memoryOk ? Math.Round(m.availPhys / 1073741824.0, 1) : 0;

                return new JavaScriptSerializer().Serialize(new {
                    ok = true,
                    cpu = Math.Round(cpu, 1),
                    cpuName = cachedCpuName,
                    cpuSpeedGHz = cachedCpuSpeedGHz,
                    cpuCores = cachedCpuCores,
                    ramPercent = memoryOk ? (int)m.load : -1,
                    ramUsedGB = ramUsed,
                    ramTotalGB = ramTotal,
                    ramAvailGB = ramAvail,
                    diskWriteMBs = diskWriteMBs,
                    diskReadMBs = diskReadMBs,
                    networkKBps = Math.Round(network, 1),
                    battery = hasBattery ? (int)(battery.BatteryLifePercent * 100) : -1,
                    plugged = battery.PowerLineStatus == PowerLineStatus.Online
                });
            }
        }
        public static string PairPage(int port) {
            string script;
            using(Stream stream=typeof(DesktopFeatures).Assembly.GetManifestResourceStream("qrcode.js"))
            using(StreamReader reader=new StreamReader(stream)) script=reader.ReadToEnd();
            // QR, yerel ucta PIN'i de tasir; telefon ilk baglantida bu PIN'i kullanir.
            string pin = Pairing.Secret;
            return "<!doctype html><html lang='tr'><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>PC Kumanda — QR bağlantı</title><style>body{background:#101114;color:#f5f5fa;font:18px Segoe UI;text-align:center;padding:40px}#qr{background:white;padding:24px;display:inline-block;border-radius:20px}p{color:#b8bbcb}</style><h1>Telefonunla bağlan</h1><p>PC Kumanda → QR ile bağlan</p><div id='qr'></div><p id='address'></p><p>Telefon ve PC aynı Wi-Fi ağında olmalı.<br>İlk bağlantıyı PC'den onaylayın.</p><script>"+script+"</script><script>var h=location.hostname;var u='pckumanda://connect?host='+encodeURIComponent(h)+'&port="+port+"&pin="+pin+"';new QRCode(document.getElementById('qr'),{text:u,width:280,height:280});document.getElementById('address').textContent=h+':"+port+" — PIN: "+pin+"';</script></html>";
        }

        internal class ProcessItem {
            public int pid;
            public string name;
            public string title;
            public long memMB;
            public bool hasWindow;
        }

        public static string ProcessList() {
            var apps = new List<ProcessItem>();
            Process[] procs = Process.GetProcesses();
            foreach (Process p in procs) {
                try {
                    int pid = p.Id;
                    if (pid <= 4) continue;
                    string name = p.ProcessName;
                    string title = "";
                    try { title = p.MainWindowTitle; } catch {}
                    long memMB = 0;
                    try { memMB = p.WorkingSet64 / (1024 * 1024); } catch {}
                    bool hasWindow = !string.IsNullOrEmpty(title);

                    apps.Add(new ProcessItem {
                        pid = pid,
                        name = name,
                        title = title,
                        memMB = memMB,
                        hasWindow = hasWindow
                    });
                } catch {}
            }

            apps.Sort((a, b) => {
                if (a.hasWindow != b.hasWindow) return b.hasWindow ? 1 : -1;
                return b.memMB.CompareTo(a.memMB);
            });

            if (apps.Count > 60) apps = apps.GetRange(0, 60);
            return new JavaScriptSerializer().Serialize(new { ok = true, processes = apps });
        }

        public static string ProcessKill(int pid) {
            if (pid <= 4) return "{\"ok\":false,\"error\":\"Sistem işlemi sonlandırılamaz\"}";
            try {
                Process p = Process.GetProcessById(pid);
                string name = p.ProcessName;
                p.Kill();
                return new JavaScriptSerializer().Serialize(new { ok = true, name = name, pid = pid });
            } catch (Exception ex) {
                return new JavaScriptSerializer().Serialize(new { ok = false, error = ex.Message });
            }
        }
    }
    internal static class GameInput {
        private static readonly object gate=new object();
        private static readonly HashSet<ushort> held=new HashSet<ushort>();
        private static long last;
        private static bool heldFire;
        // Indirection allows safety tests without injecting input into the user's desktop.
        private static Action<ushort,bool> writeKey=Input.HoldKey;
        private static Action<int,bool> writeButton=Input.Button;
        private static Action<int,int> movePointer=Input.Move;
        private static string owner="";
        private static readonly System.Threading.Timer watchdog=new System.Threading.Timer(delegate { lock(gate) {
            if(Stopwatch.GetTimestamp()-last>Stopwatch.Frequency*1.2) Release();
        }},null,250,250);
        public static string Update(string session,string names,double dx,double dy,bool fire,bool dry) {
            if (string.IsNullOrEmpty(session) || session.Length > 100) throw new ArgumentException("Oyun oturumu geçersiz");
            var next=new HashSet<ushort>();
            foreach(string name in names.Split(',')) { ushort key; if(name.Length>0) {
                if(!Input.TryVk(name,out key)) throw new ArgumentException("Geçersiz oyun tuşu: "+name);
                next.Add(key);
            }}
            if(next.Count>16) throw new ArgumentException("Çok fazla tuş");
            if(dry) return "{\"ok\":true,\"dry\":true}";
            lock(gate) {
                if(owner!=session && Stopwatch.GetTimestamp()-last<=Stopwatch.Frequency*1.2 && owner!="") return "{\"ok\":false,\"error\":\"Oyun kumandası başka cihazda açık\"}";
                owner=session;last=Stopwatch.GetTimestamp();
                foreach(ushort key in held) if(!next.Contains(key)) writeKey(key,false);
                foreach(ushort key in next) if(!held.Contains(key)) writeKey(key,true);
                held.Clear(); foreach(ushort key in next) held.Add(key);
                if (heldFire != fire) { writeButton(0,fire); heldFire=fire; }
                if(dx!=0 || dy!=0) movePointer((int)Math.Max(-100,Math.Min(100,dx)),(int)Math.Max(-100,Math.Min(100,dy)));
                if(held.Count==0 && !fire && dx==0 && dy==0) owner="";
            }
            return "{\"ok\":true}";
        }
        private static void Release() { foreach(ushort key in held) writeKey(key,false);held.Clear();if(heldFire)writeButton(0,false);heldFire=false;owner=""; }
    }
}
