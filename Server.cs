// PC Kumanda Sunucu — Windows tarafı
// Telefondan (aynı ağ) ses, fare ve güç kontrolü için HTTP + UDP keşif sunucusu.
// Derleme: csc /target:winexe (bkz. build.cmd)

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace PCKumanda
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            bool created;
            Mutex mx = new Mutex(true, "PCKumandaServerMutex", out created);
            if (!created)
            {
                MessageBox.Show("PC Kumanda Sunucu zaten çalışıyor.\nSaat yanındaki sistem tepsisine bakın.", "PC Kumanda", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            bool startMin = false;
            if (args != null)
            {
                foreach (string a in args)
                {
                    if (a == "-min" || a == "/min" || a == "--min") startMin = true;
                }
            }
            Application.Run(new MainForm(startMin));
            GC.KeepAlive(mx);
        }
    }

    // ------------------------- Yapılandırma -------------------------

    internal class Config
    {
        public int Port = 40555;
        public int MicDev = -1; // telefon mikrofonunun çalınacağı ses çıkışı (-1 varsayılan)
        public bool AutoMinimize = true; // açıldıktan sonra tepsiye küçül

        private static string Dir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PCKumanda"); }
        }
        private static string FilePath
        {
            get { return Path.Combine(Dir, "config.txt"); }
        }

        public static Config Load()
        {
            Config c = new Config();
            try
            {
                if (File.Exists(FilePath))
                {
                    foreach (string line in File.ReadAllLines(FilePath))
                    {
                        int i = line.IndexOf('=');
                        if (i <= 0) continue;
                        string k = line.Substring(0, i).Trim();
                        string v = line.Substring(i + 1).Trim();
                        if (k == "port") { int p; if (int.TryParse(v, out p)) c.Port = p; }
                        else if (k == "micdev") { int p; if (int.TryParse(v, out p)) c.MicDev = p; }
                        else if (k == "automin") { bool b; if (bool.TryParse(v, out b)) c.AutoMinimize = b; }
                    }
                }
            }
            catch { }
            return c;
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(Dir);
                File.WriteAllText(FilePath, "port=" + Port + "\r\nmicdev=" + MicDev + "\r\nautomin=" + AutoMinimize + "\r\n");
            }
            catch { }
        }
    }

    // ------------------------- Eşleme PIN'i -------------------------
    // Telefon ve tarayıcı, her istekte bu PIN'i göstermek zorundadir.
    // Yanlis PIN -> onay penceresi hic acilmadan 403 (CSRF / onay-spam korumasi).

    internal static class Pairing
    {
        private static string secret;
        private static readonly object pinGate = new object();

        private static string FilePath
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PCKumanda", "pairing.txt"); }
        }

        public static string Secret
        {
            get
            {
                lock (pinGate)
                {
                    if (secret == null) Load();
                    return secret;
                }
            }
        }

        private static void Load()
        {
            try
            {
                if (File.Exists(FilePath))
                {
                    string v = File.ReadAllText(FilePath).Trim();
                    if (v.Length == 6 && IsDigits(v)) { secret = v; return; }
                }
            }
            catch { }
            secret = Generate();
            Save();
        }

        public static string Regenerate()
        {
            lock (pinGate)
            {
                secret = Generate();
                Save();
            }
            return Secret;
        }

        private static string Generate()
        {
            // 6 haneli PIN — QR ile tasinir, elle girilebilir
            using (System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                byte[] b = new byte[4];
                rng.GetBytes(b);
                int n = Math.Abs(BitConverter.ToInt32(b, 0)) % 1000000;
                return n.ToString("D6");
            }
        }

        private static bool IsDigits(string s)
        {
            foreach (char c in s) if (c < '0' || c > '9') return false;
            return true;
        }

        private static void Save()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath));
                File.WriteAllText(FilePath, secret);
            }
            catch { }
        }

        public static bool IsValid(string pin)
        {
            return !string.IsNullOrEmpty(pin) && pin == Secret;
        }

        // ---- Basit IP basina rate limit: 8 yanlis deneme / 2 dakika -> 5 dakika kilit ----
        private class FailInfo { public int Count; public DateTime FirstFail; public DateTime LockedUntil; }
        private static Dictionary<string, FailInfo> fails = new Dictionary<string, FailInfo>();
        private static readonly object failGate = new object();

        public static bool IsLockedOut(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;
            lock (failGate)
            {
                FailInfo f;
                if (!fails.TryGetValue(ip, out f)) return false;
                if (f.LockedUntil > DateTime.UtcNow) return true;
                if (f.Count == 0) return false;
                if ((DateTime.UtcNow - f.FirstFail).TotalMinutes > 2) { fails.Remove(ip); return false; }
                return false;
            }
        }

        public static void RecordFail(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return;
            lock (failGate)
            {
                FailInfo f;
                if (!fails.TryGetValue(ip, out f)) { f = new FailInfo(); fails[ip] = f; }
                if ((DateTime.UtcNow - f.FirstFail).TotalMinutes > 2) { f.Count = 0; f.FirstFail = DateTime.UtcNow; }
                if (f.Count == 0) f.FirstFail = DateTime.UtcNow;
                f.Count++;
                if (f.Count >= 8) f.LockedUntil = DateTime.UtcNow.AddMinutes(5);
            }
        }

        public static void Reset(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return;
            lock (failGate) { fails.Remove(ip); }
        }
    }

    // ------------------------- Ana pencere -------------------------

    internal class MainForm : Form
    {
        public static MainForm Instance;
        private Label lblAddr;
        private Label lblMac;
        private Label lblPin;
        private Label lblMicStatus;
        private TextBox txtLog;
        private CheckBox chkAuto;
        private CheckBox chkAutoMin;
        private NotifyIcon tray;
        private Config cfg;
        private ScreenViewerForm screenViewer;
        private bool allowVisible;
        private bool hasAutoMinimized = false;

        public MainForm(bool startMinimized = false)
        {
            Instance = this;
            this.allowVisible = !startMinimized;
            cfg = Config.Load();
            // EXE'ye gömülü logo (telefondakiyle aynı)
            try
            {
                System.Drawing.Icon appIcon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath);
                if (appIcon != null) Icon = appIcon;
            }
            catch { }

            Text = "PC Kumanda Sunucu";
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(420, 474);
            Font = new Font("Segoe UI", 9.5f);
            // ikon yukarida EXE'den alindi

            Label t1 = new Label { Text = "Bilgisayar adı: " + Environment.MachineName, Location = new Point(15, 12), AutoSize = true };
            lblAddr = new Label { Text = "", Location = new Point(15, 34), AutoSize = true, ForeColor = Color.DarkGreen, Font = new Font("Segoe UI", 10f, FontStyle.Bold) };
            lblMac = new Label { Text = "MAC (WoL): …", Location = new Point(15, 58), AutoSize = true, ForeColor = Color.DimGray };

            chkAuto = new CheckBox { Text = "Windows ile başlat", Location = new Point(15, 84), AutoSize = true };
            chkAuto.CheckedChanged += delegate { SetAutoStart(chkAuto.Checked); };
            chkAuto.Checked = IsAutoStart();

            chkAutoMin = new CheckBox { Text = "Açılışta tepsiye küçült", Location = new Point(185, 84), AutoSize = true };
            chkAutoMin.Checked = cfg.AutoMinimize;
            chkAutoMin.CheckedChanged += delegate
            {
                cfg.AutoMinimize = chkAutoMin.Checked;
                cfg.Save();
            };

            Label lblMic = new Label { Text = "Mikrofon çıktısı:", Location = new Point(15, 114), AutoSize = true };
            ComboBox cmbMic = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Location = new Point(125, 110), Size = new Size(280, 28) };
            cmbMic.Items.Add("Varsayılan (hoparlörler)");
            string[] devices = MicServer.ListDevices();
            foreach (string d in devices) cmbMic.Items.Add(d);
            int cableIdx = -1;
            for (int i = 0; i < devices.Length; i++)
            {
                if (devices[i].IndexOf("CABLE Input", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    cableIdx = i;
                    break;
                }
            }
            if (cableIdx >= 0 && (cfg.MicDev < 0 || cfg.MicDev >= devices.Length || devices[cfg.MicDev].IndexOf("CABLE Input", StringComparison.OrdinalIgnoreCase) < 0))
            {
                cfg.MicDev = cableIdx;
                cfg.Save();
            }
            int micIdx = cfg.MicDev + 1;
            if (micIdx >= 0 && micIdx < cmbMic.Items.Count) cmbMic.SelectedIndex = micIdx;
            cmbMic.SelectedIndexChanged += delegate
            {
                cfg.MicDev = cmbMic.SelectedIndex - 1;
                cfg.Save();
                MicServer.SelectedDevice = cfg.MicDev;
                MicServer.ReopenWave();
            };

            Button btnPair = new Button { Text = "QR ile bağlan", Location = new Point(295, 178), Size = new Size(110, 28) };
            btnPair.Click += delegate {
                string ip = "";
                foreach (IPAddress a in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
                    if (a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a)) { ip = a.ToString(); break; }
                if (ip.Length > 0) Process.Start(new ProcessStartInfo("http://" + ip + ":" + cfg.Port + "/pair") { UseShellExecute = true });
            };
            Controls.Add(btnPair);
            Button btnViewer = new Button { Text = "Telefon Ekranı", Location = new Point(15, 146), Size = new Size(115, 28) };
            btnViewer.Click += delegate
            {
                screenViewer.Show();
                screenViewer.WindowState = FormWindowState.Normal;
                screenViewer.Activate();
            };
            Button btnFw = new Button { Text = "Güvenlik Duvarı Ekle", Location = new Point(135, 146), Size = new Size(150, 28) };
            btnFw.Click += delegate
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo("netsh",
                        "advfirewall firewall add rule name=\"PC Kumanda\" dir=in action=allow program=\"" + Application.ExecutablePath + "\" enable=yes profile=any");
                    psi.Verb = "runas"; // yönetici onayı (UAC)
                    psi.UseShellExecute = true;
                    Process.Start(psi);
                    Log("Güvenlik duvarı kuralı istendi (UAC onayı sonrası eklenir).");
                }
                catch (Exception ex)
                {
                    Log("Güvenlik duvarı kuralı eklenemedi: " + ex.Message);
                }
            };
            Button btnMin = new Button { Text = "Tepsiye Küçült", Location = new Point(290, 146), Size = new Size(115, 28) };
            btnMin.Click += delegate
            {
                WindowState = FormWindowState.Minimized;
                Hide();
            };

            Button btnWebcam = new Button { Text = "Webcam’i Aç", Location = new Point(15, 178), Size = new Size(125, 28) };
            btnWebcam.Click += delegate
            {
                EnsureObsWebcam();
                Log("Webcam açılıyor. Uygulamanızda OBS Virtual Camera’yı seçin.");
            };
            Button btnCameraPreview = new Button { Text = "Kamera Önizleme", Location = new Point(145, 178), Size = new Size(145, 28) };
            btnCameraPreview.Click += delegate { Process.Start("http://127.0.0.1:40560/"); };
            Label webcamHint = new Label { Text = "Kamera: OBS Virtual Camera  |  Mikrofon: CABLE Output", Location = new Point(15, 210), Size = new Size(390, 35), ForeColor = Color.DimGray };
            Controls.Add(btnWebcam); Controls.Add(btnCameraPreview); Controls.Add(webcamHint);

            lblMicStatus = new Label { Text = "mikrofon: bekleniyor", Location = new Point(15, 246), AutoSize = true, ForeColor = Color.DimGray };
            MicServer.SelectedDevice = cfg.MicDev;
            MicServer.Status = delegate(string s)
            {
                Log("mikrofon: " + s);
                try
                {
                    BeginInvoke((MethodInvoker)delegate { lblMicStatus.Text = "mikrofon: " + s; });
                }
                catch { }
            };

            txtLog = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Location = new Point(15, 272), Size = new Size(390, 155), BackColor = Color.White, Font = new Font("Consolas", 8.5f) };

            lblPin = new Label { Text = "", Location = new Point(15, 434), AutoSize = true, ForeColor = Color.DarkBlue, Font = new Font("Segoe UI", 10f, FontStyle.Bold) };
            lblPin.Text = "Eşleme PIN'i: " + Pairing.Secret;
            Button btnPin = new Button { Text = "PIN'i Yenile", Location = new Point(295, 430), Size = new Size(110, 28) };
            btnPin.Click += delegate
            {
                Pairing.Regenerate();
                lblPin.Text = "Eşleme PIN'i: " + Pairing.Secret;
                Log("Eşleme PIN'i yenilendi. QR'ı tekrar okutun / PIN'i tekrar girin.");
            };

            Controls.Add(t1);
            Controls.Add(lblAddr);
            Controls.Add(lblMac);
            Controls.Add(chkAuto);
            Controls.Add(chkAutoMin);
            Controls.Add(btnViewer);
            Controls.Add(btnFw);
            Controls.Add(btnMin);
            Controls.Add(lblMic);
            Controls.Add(cmbMic);
            Controls.Add(lblMicStatus);
            Controls.Add(lblPin);
            Controls.Add(btnPin);
            Controls.Add(txtLog);

            tray = new NotifyIcon();
            tray.Icon = Icon;
            tray.Text = "PC Kumanda Sunucu";
            tray.Visible = true;
            ContextMenu cm = new ContextMenu();
            cm.MenuItems.Add("Göster", delegate { ShowSelf(); });
            cm.MenuItems.Add("Çıkış", delegate { tray.Visible = false; Application.Exit(); });
            tray.ContextMenu = cm;
            tray.DoubleClick += delegate { ShowSelf(); };

            Resize += delegate { if (WindowState == FormWindowState.Minimized) Hide(); };
            FormClosing += delegate(object s, FormClosingEventArgs e)
            {
                if (e.CloseReason == CloseReason.UserClosing)
                {
                    e.Cancel = true;
                    Hide();
                    return;
                }
                tray.Visible = false;
            };

            Shown += delegate
            {
                if (startMinimized)
                {
                    WindowState = FormWindowState.Minimized;
                    Hide();
                    return;
                }
                if (cfg.AutoMinimize && !hasAutoMinimized)
                {
                    hasAutoMinimized = true;
                    System.Windows.Forms.Timer minTimer = new System.Windows.Forms.Timer();
                    minTimer.Interval = 1200;
                    minTimer.Tick += delegate
                    {
                        minTimer.Stop();
                        minTimer.Dispose();
                        if (WindowState != FormWindowState.Minimized)
                        {
                            WindowState = FormWindowState.Minimized;
                            Hide();
                            try
                            {
                                tray.ShowBalloonTip(2000, "PC Kumanda", "Sunucu hazır. Sistem tepsisinde çalışıyor.", ToolTipIcon.Info);
                            }
                            catch { }
                        }
                    };
                    minTimer.Start();
                }
            };

            string ips = "?";
            try
            {
                List<string> v4 = new List<string>();
                IPAddress[] list = Dns.GetHostEntry(Dns.GetHostName()).AddressList;
                foreach (IPAddress a in list)
                    if (a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
                        v4.Add(a.ToString());
                ips = string.Join(",  ", v4.ToArray());
            }
            catch { }

            string firstIp = ips;
            int comma = ips.IndexOf(',');
            if (comma > 0) firstIp = ips.Substring(0, comma);
            lblAddr.Text = "Adres: " + firstIp + "   Port: " + cfg.Port;
            lblMac.Text = "MAC (WoL): " + NetServer.GetMac();
            Log("Bilgisayardaki tüm adresler: " + ips);
            Log("Sunucu başlatılıyor (port " + cfg.Port + ")...");

            try
            {
                NetServer.Start(cfg, Log, AuthorizeDevice);
                NetServer.ClipGet = delegate
                {
                    string s = "";
                    Invoke((MethodInvoker)delegate { try { s = Clipboard.GetText(); } catch { } });
                    return s;
                };
                NetServer.ClipSet = delegate(string t)
                {
                    Invoke((MethodInvoker)delegate { try { Clipboard.SetText(t); } catch { } });
                };
                NetServer.BalloonShow = delegate(string t, string m)
                {
                    try { tray.ShowBalloonTip(3000, t, m, ToolTipIcon.Info); } catch { }
                };
                MicServer.Start();
                CameraServer.Status = delegate(string text)
                {
                    Log("kamera: " + text);
                    if (text != null && text.IndexOf("canlı", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        EnsureObsWebcam();
                    }
                };
                EnsureObsWebcam();
                CameraServer.Start();
                VideoServer.logRef = Log;
                VideoServer.Start();
                screenViewer = new ScreenViewerForm();
                screenViewer.StartListening();
                Log("Hazır. Telefondan bağlanabilirsiniz.");
                Log("Not: İlk seferde Windows güvenlik duvarı sorarsa 'İzin ver' seçin (Özel ağlar).");
            }
            catch (Exception ex)
            {
                Log("HATA: " + ex.Message);
                MessageBox.Show("Sunucu başlatılamadı: " + ex.Message, "PC Kumanda", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public static void EnsureObsWebcam()
        {
            try
            {
                string obs = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "tools", "obs", "bin", "64bit", "obs64.exe"));
                if (!File.Exists(obs)) return;
                foreach (Process process in Process.GetProcessesByName("obs64"))
                {
                    try
                    {
                        if (string.Equals(process.MainModule.FileName, obs, StringComparison.OrdinalIgnoreCase)) return;
                    }
                    catch { return; }
                }
                ProcessStartInfo info = new ProcessStartInfo(obs, "--portable --profile \"PC Kumanda\" --collection \"PC Kumanda\" --startvirtualcam --minimize-to-tray --disable-updater");
                info.WorkingDirectory = Path.GetDirectoryName(obs);
                info.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(info);
            }
            catch { }
        }

        protected override void SetVisibleCore(bool value)
        {
            if (!allowVisible)
            {
                value = false;
                if (!IsHandleCreated) CreateHandle();
            }
            base.SetVisibleCore(value);
        }

        private void ShowSelf()
        {
            allowVisible = true;
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        // Telefonda bilinmeyen bir cihaz bağlanmaya çalıştığında PC'de onay penceresi.
        // Dönüş: 0 = reddet, 1 = bu istek için izin, 2 = sürekli izin.
        private int AuthorizeDevice(string devKey, string devName)
        {
            int[] result = { 0 };
            if (InvokeRequired)
            {
                Invoke((MethodInvoker)delegate { result[0] = AuthorizeDevice(devKey, devName); });
                return result[0];
            }
            using (Form f = new Form())
            {
                f.Text = "Bağlantı izni";
                f.FormBorderStyle = FormBorderStyle.FixedDialog;
                f.MinimizeBox = false;
                f.MaximizeBox = false;
                f.TopMost = true;
                f.StartPosition = FormStartPosition.CenterScreen;
                f.ClientSize = new Size(400, 190);
                f.Icon = Icon;

                Label l = new Label
                {
                    Text = "Bu cihaz bağlanmaya çalışıyor:",
                    Location = new Point(15, 15),
                    AutoSize = true
                };
                Label l2 = new Label
                {
                    Text = devName,
                    Location = new Point(15, 38),
                    AutoSize = true,
                    Font = new Font("Segoe UI", 11f, FontStyle.Bold),
                    ForeColor = Color.FromArgb(180, 40, 40),
                    MaximumSize = new Size(370, 0)
                };
                Label l3 = new Label
                {
                    Text = "İzin verilsin mi?",
                    Location = new Point(15, 84),
                    AutoSize = true
                };
                Button bAlways = new Button { Text = "Sürekli izin ver", Location = new Point(15, 130), Size = new Size(150, 38) };
                Button bOnce = new Button { Text = "İzin ver", Location = new Point(172, 130), Size = new Size(105, 38) };
                Button bDeny = new Button { Text = "Reddet", Location = new Point(284, 130), Size = new Size(100, 38) };
                bAlways.Click += delegate { result[0] = 2; f.Close(); };
                bOnce.Click += delegate { result[0] = 1; f.Close(); };
                bDeny.Click += delegate { result[0] = 0; f.Close(); };
                f.Controls.Add(l);
                f.Controls.Add(l2);
                f.Controls.Add(l3);
                f.Controls.Add(bAlways);
                f.Controls.Add(bOnce);
                f.Controls.Add(bDeny);
                f.ShowDialog(this);
            }
            return result[0];
        }

        private void Log(string msg)
        {
            try
            {
                if (InvokeRequired) { BeginInvoke((MethodInvoker)delegate { Log(msg); }); return; }
                txtLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + msg + Environment.NewLine);
            }
            catch { }
        }

        private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private bool IsAutoStart()
        {
            try
            {
                using (Microsoft.Win32.RegistryKey k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKey))
                {
                    return k != null && k.GetValue("PCKumandaServer") != null;
                }
            }
            catch { return false; }
        }
        private void SetAutoStart(bool on)
        {
            try
            {
                using (Microsoft.Win32.RegistryKey k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RunKey))
                    if (on) k.SetValue("PCKumandaServer", "\"" + Application.ExecutablePath + "\" -min");
                    else k.DeleteValue("PCKumandaServer", false);
            }
            catch { }
        }
    }

    // ------------------------- Ses (Core Audio) -------------------------

    internal static class Audio
    {
        [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
        private class MMDeviceEnumeratorComObject { }

        private enum EDataFlow { eRender = 0, eCapture = 1 }
        private enum ERole { eConsole = 0 }

        [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IMMDeviceEnumerator
        {
            int EnumAudioEndpoints(EDataFlow dataFlow, int dwStateMask, out IntPtr devices);
            int GetDefaultAudioEndpoint(EDataFlow dataFlow, ERole role, out IMMDevice endpoint);
            int GetDevice([MarshalAs(UnmanagedType.LPWStr)] string pwstrId, out IMMDevice device);
            int RegisterEndpointNotificationCallback(IntPtr pClient);
            int UnregisterEndpointNotificationCallback(IntPtr pClient);
        }

        [Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IMMDevice
        {
            int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [MarshalAs(UnmanagedType.IUnknown)] out object iface);
            int OpenPropertyStore(int stgmAccess, out IntPtr props);
            int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);
            int GetState(out int state);
        }

        [Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IAudioEndpointVolume
        {
            int RegisterControlChangeNotify(IntPtr pNotify);
            int UnregisterControlChangeNotify(IntPtr pNotify);
            int GetChannelCount(out uint pnChannelCount);
            int SetMasterVolumeLevel(float fLevelDB, ref Guid ctx);
            int SetMasterVolumeLevelScalar(float fLevel, ref Guid ctx);
            int GetMasterVolumeLevel(out float fLevelDB);
            int GetMasterVolumeLevelScalar(out float fLevel);
            int SetChannelVolumeLevel(uint nChannel, float fLevelDB, ref Guid ctx);
            int SetChannelVolumeLevelScalar(uint nChannel, float fLevel, ref Guid ctx);
            int GetChannelVolumeLevel(uint nChannel, out float fLevelDB);
            int GetChannelVolumeLevelScalar(uint nChannel, out float fLevel);
            int SetMute(bool bMute, ref Guid ctx);
            int GetMute(out bool bMute);
            int GetVolumeStepInfo(out uint pnStep, out uint pnStepCount);
            int VolumeStepUp(ref Guid ctx);
            int VolumeStepDown(ref Guid ctx);
            int QueryHardwareSupport(out uint pdwSupport);
            int GetVolumeRange(out float minDb, out float maxDb, out float incDb);
        }

        [DllImport("user32.dll")]
        private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
        private const uint KEYEVENTF_KEYUP = 0x0002;
        private const byte VK_VOLUME_MUTE = 0xAD, VK_VOLUME_DOWN = 0xAE, VK_VOLUME_UP = 0xAF;

        private static IAudioEndpointVolume vol;
        private static bool comFailed;
        private static object gate = new object();

        private static IAudioEndpointVolume GetVol()
        {
            lock (gate)
            {
                if (vol != null) return vol;
                if (comFailed) return null;
                try
                {
                    object oEnum = new MMDeviceEnumeratorComObject();
                    IMMDeviceEnumerator en = (IMMDeviceEnumerator)oEnum;
                    IMMDevice dev;
                    int hr = en.GetDefaultAudioEndpoint(EDataFlow.eRender, ERole.eConsole, out dev);
                    if (hr != 0) throw new Exception("GetDefaultAudioEndpoint hr=" + hr);
                    Guid iid = typeof(IAudioEndpointVolume).GUID;
                    object iface;
                    hr = dev.Activate(ref iid, 23, IntPtr.Zero, out iface); // CLSCTX_ALL
                    if (hr != 0) throw new Exception("Activate hr=" + hr);
                    vol = (IAudioEndpointVolume)iface;
                    return vol;
                }
                catch
                {
                    comFailed = true;
                    return null;
                }
            }
        }

        public static int GetLevel() // 0-100, başarısızsa -1
        {
            IAudioEndpointVolume v = GetVol();
            if (v == null) return -1;
            float f;
            Guid g = Guid.Empty;
            return (v.GetMasterVolumeLevelScalar(out f) == 0) ? (int)Math.Round(f * 100f) : -1;
        }

        public static bool GetMute()
        {
            IAudioEndpointVolume v = GetVol();
            if (v == null) return false;
            bool m;
            return v.GetMute(out m) == 0 ? m : false;
        }

        public static void SetLevel(int level)
        {
            IAudioEndpointVolume v = GetVol();
            if (level < 0) level = 0;
            if (level > 100) level = 100;
            if (v != null)
            {
                Guid g = Guid.Empty;
                v.SetMasterVolumeLevelScalar(level / 100f, ref g);
                bool m; v.GetMute(out m);
                if (m && level > 0) SetMute(false);
            }
            else
            {
                Tap(VK_VOLUME_DOWN, 50); // en aşağı
                if (level > 0) Tap(VK_VOLUME_UP, level / 2);
            }
            VolumeOsdForm.ShowOsd(level, GetMute());
        }
        public static void Step(int deltaPercent)
        {
            IAudioEndpointVolume v = GetVol();
            if (v != null)
            {
                int cur = GetLevel();
                SetLevel(cur + deltaPercent);
            }
            else
            {
                Tap(deltaPercent > 0 ? VK_VOLUME_UP : VK_VOLUME_DOWN, 1);
            }
        }

        public static bool ToggleMute()
        {
            IAudioEndpointVolume v = GetVol();
            if (v != null)
            {
                SetMute(!GetMute());
                return GetMute();
            }
            Tap(VK_VOLUME_MUTE, 1);
            return false;
        }

        public static void SetMute(bool m)
        {
            IAudioEndpointVolume v = GetVol();
            if (v != null)
            {
                Guid g = Guid.Empty;
                v.SetMute(m, ref g);
            }
            else Tap(VK_VOLUME_MUTE, 1);
            VolumeOsdForm.ShowOsd(GetLevel(), m);
        }
        public static void MediaKey(int vk)
        {
            keybd_event((byte)vk, 0, 0, UIntPtr.Zero);
            keybd_event((byte)vk, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
        }

        private static void Tap(byte vk, int times)
        {
            for (int i = 0; i < times; i++)
            {
                keybd_event(vk, 0, 0, UIntPtr.Zero);
                keybd_event(vk, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
            }
        }
    }

    // ------------------------- Ses Göstergesi (Volume OSD) -------------------------
    internal class VolumeOsdForm : Form
    {
        private static VolumeOsdForm instance;
        private System.Windows.Forms.Timer hideTimer;
        private int currentLevel = 0;
        private bool isMuted = false;

        public VolumeOsdForm()
        {
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.Manual;
            ShowInTaskbar = false;
            TopMost = true;
            BackColor = Color.FromArgb(24, 25, 30);
            DoubleBuffered = true;
            Size = new Size(480, 120);

            hideTimer = new System.Windows.Forms.Timer();
            hideTimer.Interval = 1800;
            hideTimer.Tick += delegate
            {
                hideTimer.Stop();
                Hide();
            };
        }

        protected override CreateParams CreateParams
        {
            get
            {
                CreateParams cp = base.CreateParams;
                // WS_EX_NOACTIVATE (0x08000000) | WS_EX_TOOLWINDOW (0x00000080) | WS_EX_TOPMOST (0x00000008)
                cp.ExStyle |= 0x08000000 | 0x00000080 | 0x00000008;
                return cp;
            }
        }

        public static void ShowOsd(int level, bool muted)
        {
            if (MainForm.Instance != null && MainForm.Instance.InvokeRequired)
            {
                try
                {
                    MainForm.Instance.BeginInvoke(new Action(() => ShowOsdInternal(level, muted)));
                    return;
                }
                catch { }
            }
            ShowOsdInternal(level, muted);
        }

        private static void ShowOsdInternal(int level, bool muted)
        {
            try
            {
                if (instance == null || instance.IsDisposed)
                {
                    instance = new VolumeOsdForm();
                }
                instance.currentLevel = Math.Max(0, Math.Min(100, level));
                instance.isMuted = muted;

                Rectangle bounds = Screen.PrimaryScreen.WorkingArea;
                int x = bounds.X + (bounds.Width - instance.Width) / 2;
                int y = bounds.Y + bounds.Height - instance.Height - 80;

                instance.hideTimer.Stop();
                instance.hideTimer.Start();

                if (!instance.Visible)
                {
                    ShowWindow(instance.Handle, 4); // SW_SHOWNOACTIVATE
                }
                instance.Invalidate();
            }
            catch { }
        }

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            // Arka plan ve yuvarlak çerçeve
            Rectangle rect = new Rectangle(0, 0, Width - 1, Height - 1);
            using (GraphicsPath path = RoundedRect(rect, 22))
            {
                using (SolidBrush bgBrush = new SolidBrush(Color.FromArgb(24, 25, 32)))
                    g.FillPath(bgBrush, path);
                using (Pen borderPen = new Pen(Color.FromArgb(64, 67, 82), 2f))
                    g.DrawPath(borderPen, path);
            }

            // İkon / Ses Başlığı (2x büyük font)
            string iconStr = isMuted ? "Sessiz (Muted)" : (currentLevel == 0 ? "Ses: Kapalı" : "Ses Seviyesi");
            using (Font iconFont = new Font("Segoe UI", 16, FontStyle.Bold))
            {
                g.DrawString(iconStr, iconFont, isMuted ? Brushes.Tomato : Brushes.White, new PointF(28, 24));
            }

            // Ses Seviyesi Yüzdesi (2x büyük kalın font)
            string pctText = isMuted ? "KAPALI" : ("% " + currentLevel);
            using (Font pctFont = new Font("Segoe UI", 24, FontStyle.Bold))
            {
                SizeF size = g.MeasureString(pctText, pctFont);
                g.DrawString(pctText, pctFont, isMuted ? Brushes.Tomato : Brushes.White, new PointF(Width - size.Width - 28, 16));
            }

            // Ses İlerleme Çubuğu (2x kalın ve geniş progress bar)
            int barX = 28;
            int barY = 74;
            int barW = Width - barX - 28;
            int barH = 16;
            Rectangle barBg = new Rectangle(barX, barY, barW, barH);
            using (GraphicsPath barBgPath = RoundedRect(barBg, 8))
            using (SolidBrush bgb = new SolidBrush(Color.FromArgb(45, 47, 58)))
            {
                g.FillPath(bgb, barBgPath);
            }

            if (!isMuted && currentLevel > 0)
            {
                int fillW = (int)(barW * (currentLevel / 100f));
                if (fillW > 0)
                {
                    Rectangle barFill = new Rectangle(barX, barY, fillW, barH);
                    using (GraphicsPath fillPath = RoundedRect(barFill, 8))
                    using (SolidBrush fillBrush = new SolidBrush(Color.FromArgb(112, 87, 201))) // modern primary purple
                    {
                        g.FillPath(fillBrush, fillPath);
                    }
                }
            }
        }

        private static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            GraphicsPath path = new GraphicsPath();
            int d = radius * 2;
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    // ------------------------- Fare / Güç -------------------------

    internal static class Input
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int X; public int Y; }

        [DllImport("user32.dll")] private static extern bool SetCursorPos(int X, int Y);
        [DllImport("user32.dll")] private static extern bool GetCursorPos(out POINT p);
        [DllImport("user32.dll")] private static extern void mouse_event(uint dwFlags, uint dx, uint dy, int dwData, UIntPtr dwExtraInfo);
        [DllImport("user32.dll")] private static extern bool LockWorkStation();
        [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, IntPtr lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
        [DllImport("powrprof.dll")] private static extern bool SetSuspendState(bool hibernate, bool forceCritical, bool disableWakeEvent);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
        [DllImport("user32.dll")]
        private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

        [DllImport("kernel32.dll")] private static extern uint SetThreadExecutionState(uint esFlags);
        [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr FindWindowEx(IntPtr parent, IntPtr after, string cls, string win);
        [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, ref bool pvParam, uint fWinIni);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);
        private const uint SPI_GETSCREENSAVERRUNNING = 0x0072;
        private const uint SPI_SETSCREENSAVEACTIVE = 0x0011;
        private const uint ES_CONTINUOUS = 0x80000000;
        private const uint ES_SYSTEM_REQUIRED = 0x00000001;
        private const uint ES_DISPLAY_REQUIRED = 0x00000002;
        private const uint WM_CLOSE = 0x0010;

        private static int lastWakeTick = 0;

        /// <summary>
        /// Ekran koruyucuyu kapatır ve monitörü açar. Telefondan gelen sentetik girdi
        /// (SetCursorPos) ekran koruyucunun ayrı input desktop'una ulaşmadığından
        /// PC boşta kaldıktan sonra bağlanıldığında koruyucu kapanmaz; bu yüzden
        /// Shift tuşu darbesi, sentetik fare hareketi ve işlem sonlandırma birlikte uygulanır.
        /// </summary>
        public static void WakeScreen()
        {
            // Sürekli fare hareketlerinde gereksiz klavye/fare darbesi ve CPU yükünü önlemek için
            // uyandırma işlemlerini en fazla 2 saniyede bir kez çalıştır.
            int now = Environment.TickCount;
            if (Math.Abs(now - lastWakeTick) < 2000) return;
            lastWakeTick = now;

            // 1. Shift tuşu darbesi: Windows ekran koruyucuyu ve kilit ekranını kapatan en kesin yöntem
            try
            {
                keybd_event(0x10, 0, 0, UIntPtr.Zero); // VK_SHIFT down
                keybd_event(0x10, 0, KEYEVENTF_KEYUP, UIntPtr.Zero); // VK_SHIFT up
            }
            catch { }

            // 2. Sentetik fare hareketi darbesi (donanımsal HID hareketi simülasyonu)
            try
            {
                mouse_event(0x0001, 1, 1, 0, UIntPtr.Zero);
                mouse_event(0x0001, unchecked((uint)-1), unchecked((uint)-1), 0, UIntPtr.Zero);
            }
            catch { }

            // 3. Monitörü donanımsal aç (SC_MONITORPOWER -1 = on)
            try
            {
                UIntPtr res;
                SendMessageTimeout(HWND_BROADCAST, WM_SYSCOMMAND, (UIntPtr)SC_MONITORPOWER,
                    (IntPtr)(-1), 2, 500, out res);
            }
            catch { }

            // 4. Çalışan .scr ekran koruyucu işlemlerini doğrudan kapat
            try
            {
                foreach (Process proc in Process.GetProcesses())
                {
                    try
                    {
                        string pName = proc.ProcessName.ToLowerInvariant();
                        if (pName.EndsWith(".scr") || pName == "scrnsave" || pName == "mystify" ||
                            pName == "bubbles" || pName == "ribbons" || pName == "photoscreensaver" || pName == "sstext3d")
                        {
                            proc.Kill();
                        }
                    }
                    catch { }
                }
            }
            catch { }

            // 5. SPI toggle ile koruyucu aktifliğini tazele
            try
            {
                bool running = false;
                SystemParametersInfo(SPI_GETSCREENSAVERRUNNING, 0, ref running, 0);
                if (running)
                {
                    SystemParametersInfo(SPI_SETSCREENSAVEACTIVE, 0, IntPtr.Zero, 0);
                    SystemParametersInfo(SPI_SETSCREENSAVEACTIVE, 1, IntPtr.Zero, 0);
                }
            }
            catch { }

            // 6. Eski pencere kapatma yöntemi (fallback)
            try
            {
                IntPtr saver = FindWindowEx(IntPtr.Zero, IntPtr.Zero, "WindowsScreenSaverClass", null);
                if (saver != IntPtr.Zero) PostMessage(saver, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
            }
            catch { }

            // 7. Boşta sayacını sıfırla (ekran + sistem)
            try { SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED); } catch { }
            try { SetThreadExecutionState(ES_CONTINUOUS); } catch { }
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
        [StructLayout(LayoutKind.Sequential)]
        private struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
        [StructLayout(LayoutKind.Explicit)]
        private struct INPUTUNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
        [StructLayout(LayoutKind.Sequential)]
        private struct INPUT { public uint type; public INPUTUNION u; }

        private const uint KEYEVENTF_KEYUP = 0x0002;
        private const uint KEYEVENTF_UNICODE = 0x0004;

        private const uint LEFTDOWN = 0x0002, LEFTUP = 0x0004, RIGHTDOWN = 0x0008, RIGHTUP = 0x0010;
        private const uint MIDDLEDOWN = 0x0020, MIDDLEUP = 0x0040, WHEEL = 0x0800, HWHEEL = 0x1000;
        private const uint WM_SYSCOMMAND = 0x0112, SC_MONITORPOWER = 0xF170;
        private static readonly IntPtr HWND_BROADCAST = new IntPtr(0xffff);

        public static void Move(int dx, int dy)
        {
            WakeScreen();
            POINT p;
            if (!GetCursorPos(out p)) return;
            SetCursorPos(p.X + dx, p.Y + dy);
        }

        public static void SetPos(int x, int y)
        {
            WakeScreen();
            SetCursorPos(x, y);
        }

        /// <summary>Cursor pozisyonunun ekran oranı (0-1). Başarısızsa (0.5, 0.5).</summary>
        public static void CursorRatio(out float cx, out float cy)
        {
            POINT p;
            if (GetCursorPos(out p))
            {
                Rectangle vs = DesktopFeatures.Bounds;
                cx = (p.X - vs.X) / (float)vs.Width;
                cy = (p.Y - vs.Y) / (float)vs.Height;
            }
            else { cx = 0.5f; cy = 0.5f; }
        }

        public static void Button(int button, bool down)
        {
            uint f = 0;
            if (button == 0) f = down ? LEFTDOWN : LEFTUP;
            else if (button == 1) f = down ? RIGHTDOWN : RIGHTUP;
            else f = down ? MIDDLEDOWN : MIDDLEUP;
            mouse_event(f, 0, 0, 0, UIntPtr.Zero);
        }

        public static void Click(int button, int count)
        {
            for (int i = 0; i < count; i++)
            {
                Button(button, true);
                Button(button, false);
                if (count > 1) Thread.Sleep(30);
            }
        }

        // dy > 0 → aşağı kaydır (Windows varsayılanı: parmak aşağı = içerik aşağı)
        public static void Scroll(float dy, float dx)
        {
            if (Math.Abs(dy) > 0.001f)
                mouse_event(WHEEL, 0, 0, -(int)Math.Round(dy * 120f), UIntPtr.Zero);
            if (Math.Abs(dx) > 0.001f)
                mouse_event(HWHEEL, 0, 0, (int)Math.Round(dx * 120f), UIntPtr.Zero);
        }

        public static void Lock() { LockWorkStation(); }

        public static void MonitorOff()
        {
            UIntPtr res;
            SendMessageTimeout(HWND_BROADCAST, WM_SYSCOMMAND, (UIntPtr)SC_MONITORPOWER, (IntPtr)2, 2, 1000, out res);
        }

        public static void Sleep() { SetSuspendState(false, false, false); }

        // Telefonda yazılan metni PC'de tuşlar (Unicode SendInput; ğüşıöç destekli)
        public static int KeyText(string text)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            if (text.Length > 4000) text = text.Substring(0, 4000);
            List<INPUT> list = new List<INPUT>(text.Length * 2);
            foreach (char c in text)
            {
                if (c == '\n' || c == '\r')
                {
                    list.Add(Kd(0x0D, 0x1C, 0));
                    list.Add(Kd(0, 0, KEYEVENTF_KEYUP));
                }
                else if (c == '\t')
                {
                    list.Add(Kd(0x09, 0x0F, 0));
                    list.Add(Kd(0, 0, KEYEVENTF_KEYUP));
                }
                else if (c == '\b')
                {
                    list.Add(Kd(0x08, 0x0E, 0));
                    list.Add(Kd(0, 0, KEYEVENTF_KEYUP));
                }
                else if (c >= 32)
                {
                    list.Add(Kd(0, (ushort)c, KEYEVENTF_UNICODE));
                    list.Add(Kd(0, (ushort)c, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
                }
            }
            if (list.Count == 0) return 0;
            INPUT[] arr = list.ToArray();
            uint sent = SendInput((uint)arr.Length, arr, Marshal.SizeOf(typeof(INPUT)));
            return (int)sent;
        }

        private static INPUT Kd(ushort vk, ushort scan, uint flags)
        {
            INPUT i = new INPUT();
            i.type = 1; // INPUT_KEYBOARD
            i.u.ki.wVk = vk;
            i.u.ki.wScan = scan;
            i.u.ki.dwFlags = flags;
            return i;
        }

        // ---- Klavye kısayolları (Ctrl+C, Alt+Tab, Win+D vb.) ----

        public static bool TryVk(string name, out ushort vk)
        {
            string n = name.Trim().ToLowerInvariant();
            switch (n)
            {
                case "ctrl": vk = 0x11; return true;
                case "alt": vk = 0x12; return true;
                case "shift": vk = 0x10; return true;
                case "win": vk = 0x5B; return true;
                case "esc": vk = 0x1B; return true;
                case "tab": vk = 0x09; return true;
                case "enter": vk = 0x0D; return true;
                case "backspace": vk = 0x08; return true;
                case "delete": vk = 0x2E; return true;
                case "space": vk = 0x20; return true;
                case "up": vk = 0x26; return true;
                case "down": vk = 0x28; return true;
                case "left": vk = 0x25; return true;
                case "right": vk = 0x27; return true;
                case "home": vk = 0x24; return true;
                case "end": vk = 0x23; return true;
                case "pgup": vk = 0x21; return true;
                case "pgdn": vk = 0x22; return true;
                case "printscreen": vk = 0x2C; return true;
                case "num0": vk = 0x60; return true;
                case "num1": vk = 0x61; return true;
                case "num2": vk = 0x62; return true;
                case "num3": vk = 0x63; return true;
                case "num4": vk = 0x64; return true;
                case "num5": vk = 0x65; return true;
                case "num6": vk = 0x66; return true;
                case "num7": vk = 0x67; return true;
                case "num8": vk = 0x68; return true;
                case "num9": vk = 0x69; return true;
                case "numplus": vk = 0x6B; return true;
                case "numminus": vk = 0x6D; return true;
                case "nummul": vk = 0x6A; return true;
                case "numdiv": vk = 0x6F; return true;
                case "numdot": vk = 0x6E; return true;
                case "numenter": vk = 0x0D; return true;
            }
            if (n.Length == 1)
            {
                char c = char.ToLowerInvariant(n[0]);
                if (c >= 'a' && c <= 'z') { vk = (ushort)('A' + (c - 'a')); return true; }
                if (c >= '0' && c <= '9') { vk = (ushort)('0' + (c - '0')); return true; }
            }
            if (n.Length >= 2 && n[0] == 'f')
            {
                int fn;
                if (int.TryParse(n.Substring(1), out fn) && fn >= 1 && fn <= 12) { vk = (ushort)(0x70 + fn - 1); return true; }
            }
            vk = 0;
            return false;
        }

        [DllImport("user32.dll")] private static extern uint MapVirtualKey(uint code, uint type);
        public static void HoldKey(ushort vk, bool down) {
            uint scan = MapVirtualKey(vk, 0);
            uint flags = 0x0008 | (down ? 0u : KEYEVENTF_KEYUP);
            if (vk >= 0x21 && vk <= 0x2E) flags |= 1;
            SendInput(1, new INPUT[] { Kd(0, (ushort)scan, flags) }, Marshal.SizeOf(typeof(INPUT)));
        }

        public static int KeyCombo(string[] names)
        {
            List<ushort> vks = new List<ushort>();
            foreach (string n in names)
            {
                ushort v;
                if (TryVk(n, out v)) vks.Add(v);
            }
            if (vks.Count == 0) return 0;
            foreach (ushort v in vks) keybd_event((byte)v, 0, 0, UIntPtr.Zero);
            for (int i = vks.Count - 1; i >= 0; i--) keybd_event((byte)vks[i], 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
            return vks.Count;
        }

        // ---- Mutlak konum tıklama (ekran yansıtma için) ----

        public static void AbsClick(double nx, double ny, int button, int count)
        {
            if (nx < 0) nx = 0; if (nx > 1) nx = 1;
            if (ny < 0) ny = 0; if (ny > 1) ny = 1;
            Rectangle vs = DesktopFeatures.Bounds;
            SetCursorPos(vs.X + (int)(nx * vs.Width), vs.Y + (int)(ny * vs.Height));
            Click(button, count);
        }

        // ---- İki parmak kıstırma = Ctrl+tekerlek (yakınlaştırma) ----
        // dy < 0: yaklaş (tekerlek yukarı), dy > 0: uzaklaş
        public static void CtrlWheel(float dy)
        {
            if (Math.Abs(dy) < 0.01f) return;
            keybd_event(0x11, 0, 0, UIntPtr.Zero); // CTRL bas
            mouse_event(WHEEL, 0, 0, -(int)Math.Round(dy * 120f), UIntPtr.Zero);
            keybd_event(0x11, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
        }
    }

    internal static class Power
    {
        private static System.Threading.Timer sleepTimer;

        public static void Shutdown() { Run("shutdown", "/s /t 5 /c \"PC Kumanda: 5 sn icinde kapanacak\""); }
        public static void Restart() { Run("shutdown", "/r /t 5 /c \"PC Kumanda: 5 sn icinde yeniden baslayacak\""); }
        public static void Abort() { Run("shutdown", "/a"); }

        public static void RunApp(string name, string customPath)
        {
            string n = (name ?? "").Trim().ToLowerInvariant();
            string path = (customPath ?? "").Trim();
            switch (n)
            {
                case "chrome": Run("cmd", "/c start \"\" chrome"); break;
                case "edge": Run("cmd", "/c start \"\" msedge"); break;
                case "explorer": Run("explorer.exe", ""); break;
                case "notepad": Run("notepad.exe", ""); break;
                case "calc": Run("calc.exe", ""); break;
                case "cmd": Run("cmd.exe", ""); break;
                case "taskmgr": Run("taskmgr.exe", ""); break;
                case "custom":
                    // Kabuk icermeden calistir: cmd/start birlestirmesi enjeksiyona izin verirdi.
                    if (path.Length == 0) throw new Exception("yol bos");
                    if (path.IndexOf('"') >= 0 || path.IndexOf('&') >= 0 || path.IndexOf('|') >= 0 ||
                        path.IndexOf('^') >= 0 || path.IndexOf('<') >= 0 || path.IndexOf('>') >= 0 ||
                        path.IndexOf('%') >= 0)
                        throw new Exception("yol gecersiz karakter iceriyor");
                    foreach (char c in path) if (c < 32) throw new Exception("yol gecersiz karakter iceriyor");
                    ShellStart(path);
                    break;
                default: throw new Exception("bilinmeyen uygulama: " + n);
            }
        }

        // Dogrudan ShellExecute: exe/belge/klasor acar, kabuk yorumlama yok
        public static void ShellStart(string target)
        {
            ProcessStartInfo pi = new ProcessStartInfo();
            pi.FileName = target;
            pi.UseShellExecute = true;
            Process.Start(pi);
        }

        public static void StartTimer(int seconds, string mode)
        {
            CancelTimer();
            if (mode == "sleep")
            {
                int s = seconds;
                sleepTimer = new System.Threading.Timer(delegate { Input.Sleep(); }, null, s * 1000, Timeout.Infinite);
            }
            else
            {
                Run("shutdown", (mode == "restart" ? "/r" : "/s") + " /t " + seconds);
            }
        }

        public static void CancelTimer()
        {
            if (sleepTimer != null) { sleepTimer.Dispose(); sleepTimer = null; }
            Run("shutdown", "/a");
        }

        public static void Run(string exe, string args)
        {
            ProcessStartInfo pi = new ProcessStartInfo();
            pi.FileName = exe;
            pi.Arguments = args;
            pi.UseShellExecute = false;
            pi.CreateNoWindow = true;
            Process.Start(pi);
        }
    }

    // Ekran görüntüsü yakalama (telefonda izlemek için JPEG; gerçek Windows imleci çizilir)
    internal static class ScreenCapture
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int X; public int Y; }

        [StructLayout(LayoutKind.Sequential)]
        private struct CURSORINFO { public int cbSize; public int flags; public IntPtr hCursor; public POINT ptScreenPos; }

        [StructLayout(LayoutKind.Sequential)]
        private struct ICONINFO { public bool fIcon; public int xHotspot; public int yHotspot; public IntPtr hbmMask; public IntPtr hbmColor; }

        [DllImport("user32.dll")]
        private static extern bool GetCursorInfo(ref CURSORINFO pci);

        [DllImport("user32.dll")]
        private static extern bool GetIconInfo(IntPtr hIcon, out ICONINFO piconinfo);

        [DllImport("user32.dll")]
        private static extern bool DrawIconEx(IntPtr hdc, int xLeft, int yTop, IntPtr hIcon, int cxWidth, int cyWidth, uint istepIfAniCur, IntPtr hbrFlickerFreeDraw, uint diFlags);

        [DllImport("user32.dll")]
        private static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("gdi32.dll")]
        private static extern bool DeleteObject(IntPtr hObject);

        [DllImport("gdi32.dll")]
        private static extern int SetStretchBltMode(IntPtr hdc, int iStretchMode);

        [DllImport("gdi32.dll")]
        private static extern bool StretchBlt(IntPtr hdcDest, int nXOriginDest, int nYOriginDest, int nWidthDest, int nHeightDest,
            IntPtr hdcSrc, int nXOriginSrc, int nYOriginSrc, int nWidthSrc, int nHeightSrc, int dwRop);

        public static string LastError = "";

        private static Bitmap sharedBmp = null;
        private static Graphics sharedG = null;
        private static int lastW = 0, lastH = 0;
        private static readonly object capLock = new object();
        private static readonly ImageCodecInfo jpegCodec;

        static ScreenCapture()
        {
            foreach (ImageCodecInfo c in ImageCodecInfo.GetImageEncoders())
            {
                if (c.FormatID == ImageFormat.Jpeg.Guid) { jpegCodec = c; break; }
            }
        }

        public static byte[] Jpeg(int targetW, int quality)
        {
            lock (capLock)
            {
                try
                {
                    Rectangle vs = DesktopFeatures.Bounds;
                    int targetH = Math.Max(1, vs.Height * targetW / Math.Max(1, vs.Width));

                    if (sharedBmp == null || lastW != targetW || lastH != targetH)
                    {
                        if (sharedG != null) { sharedG.Dispose(); sharedG = null; }
                        if (sharedBmp != null) { sharedBmp.Dispose(); sharedBmp = null; }
                        sharedBmp = new Bitmap(targetW, targetH, PixelFormat.Format24bppRgb);
                        sharedG = Graphics.FromImage(sharedBmp);
                        lastW = targetW;
                        lastH = targetH;
                    }

                    IntPtr hdcDest = sharedG.GetHdc();
                    IntPtr hdcSrc = GetDC(IntPtr.Zero);
                    try
                    {
                        SetStretchBltMode(hdcDest, 3); // COLORONCOLOR
                        StretchBlt(hdcDest, 0, 0, targetW, targetH,
                            hdcSrc, vs.X, vs.Y, vs.Width, vs.Height, 0x00CC0020 /* SRCCOPY */);

                        // Windows imlecini gerçek şekliyle çiz
                        try
                        {
                            CURSORINFO ci = new CURSORINFO();
                            ci.cbSize = Marshal.SizeOf(typeof(CURSORINFO));
                            if (GetCursorInfo(ref ci) && ci.hCursor != IntPtr.Zero && (ci.flags & 1) != 0)
                            {
                                ICONINFO ii;
                                if (GetIconInfo(ci.hCursor, out ii))
                                {
                                    try
                                    {
                                        float sx = targetW / (float)vs.Width;
                                        float sy = targetH / (float)vs.Height;
                                        int cx = (int)((ci.ptScreenPos.X - ii.xHotspot - vs.X) * sx);
                                        int cy = (int)((ci.ptScreenPos.Y - ii.yHotspot - vs.Y) * sy);
                                        DrawIconEx(hdcDest, cx, cy, ci.hCursor, 0, 0, 0, IntPtr.Zero, 0x0003 /* DI_NORMAL */);
                                    }
                                    finally
                                    {
                                        if (ii.hbmMask != IntPtr.Zero) DeleteObject(ii.hbmMask);
                                        if (ii.hbmColor != IntPtr.Zero) DeleteObject(ii.hbmColor);
                                    }
                                }
                            }
                        }
                        catch (Exception cex) { LastError = "imlec: " + cex.Message; }
                    }
                    finally
                    {
                        ReleaseDC(IntPtr.Zero, hdcSrc);
                        sharedG.ReleaseHdc(hdcDest);
                    }

                    if (jpegCodec == null) return null;
                    using (MemoryStream ms = new MemoryStream(targetW * targetH / 4))
                    {
                        using (EncoderParameters ep = new EncoderParameters(1))
                        {
                            ep.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, (long)quality);
                            sharedBmp.Save(ms, jpegCodec, ep);
                            return ms.ToArray();
                        }
                    }
                }
                catch (Exception jex)
                {
                    LastError = "jpeg: " + jex.Message;
                    return null;
                }
            }
        }
    }

    // ------------------------- Sürekli ekran akışı (video) -------------------------
    // Telefon TCP 40557'ye bağlanır, ayar satırı yazar ("w=1280 q=60 devid=...\n"),
    // sunucu her kareyi [4 bayt uzunluk][JPEG] biçiminde kesintisiz push eder (~30 fps).
    internal static class VideoServer
    {
        private static TcpListener listener;
        private static TcpClient current;

        public static void Start()
        {
            listener = new TcpListener(IPAddress.Any, 40557);
            SocketLifetime.Private(listener.Server);
            listener.Start();
            Thread t = new Thread(AcceptLoop);
            t.IsBackground = true;
            t.Start();
        }

        private static void AcceptLoop()
        {
            while (true)
            {
                TcpClient c = null;
                try
                {
                    c = listener.AcceptTcpClient(); SocketLifetime.Private(c.Client);
                    c.NoDelay = true;
                    TcpClient prev = Interlocked.Exchange(ref current, c);
                    try { if (prev != null) prev.Close(); } catch { }
                    Thread st = new Thread(() => Serve(c));
                    st.IsBackground = true;
                    st.Start();
                }
                catch
                {
                    try { if (c != null) c.Close(); } catch { }
                }
            }
        }

        private static string ReadLine(NetworkStream ns)
        {
            StringBuilder sb = new StringBuilder();
            while (sb.Length < 256)
            {
                int b = ns.ReadByte();
                if (b < 0) throw new IOException("kopdu");
                if (b == '\n') break;
                if (b != '\r') sb.Append((char)b);
            }
            return sb.ToString();
        }

        private static void Serve(TcpClient c)
        {
            try
            {
                NetworkStream ns = c.GetStream();
                c.ReceiveTimeout = 5000; // el sıkışma aşamasında takılan bağlantıları düşür
                string hello = ReadLine(ns);
                int w = 1920, q = 90;
                bool ackMode = false;
                string devid = "";
                string pin = "";
                foreach (string part in hello.Split(' '))
                {
                    string[] kv = part.Split('=');
                    if (kv.Length != 2) continue;
                    if (kv[0] == "w") { int t; if (int.TryParse(kv[1], out t)) w = Math.Max(320, Math.Min(1920, t)); }
                    else if (kv[0] == "q") { int t; if (int.TryParse(kv[1], out t)) q = Math.Max(20, Math.Min(90, t)); }
                    else if (kv[0] == "ack") ackMode = (kv[1] == "1");
                    else if (kv[0] == "devid") devid = kv[1];
                    else if (kv[0] == "pin") pin = kv[1];
                }
                // PIN dogru degilse hicbir sey akitilmaz (eski istemciler pin gondermez -> reddedilir)
                if (!Pairing.IsValid(pin))
                {
                    if (logRef != null) logRef("video: PIN reddi — akış verilmedi");
                    return;
                }
                // Yetkisiz cihaz video akışı alamaz
                if (!NetServer.IsDeviceAllowed(devid))
                {
                    if (logRef != null) logRef("video: yetkisiz cihaz reddedildi (" + devid + ")");
                    return;
                }
                c.ReceiveTimeout = 0; // akış modunda engelleyici okuma serbest
                if (logRef != null) logRef("video: akış başladı (" + w + "px, ack=" + ackMode + ")");
                int frameMs = 1000 / 30;
                int consecutiveFails = 0;
                int frameCount = 0;
                while (true)
                {
                    if (ackMode && frameCount > 0)
                    {
                        c.ReceiveTimeout = 3000;
                        int ack = ns.ReadByte();
                        if (ack < 0) break; // İstemci bağlantıyı kapattı
                    }

                    System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
                    byte[] jpg = ScreenCapture.Jpeg(w, q);
                    if (jpg == null)
                    {
                        if (logRef != null) logRef("video: kare üretilemedi — " + ScreenCapture.LastError);
                        consecutiveFails++;
                        if (consecutiveFails >= 10) break; // geçici hatalarda akışı sürdür
                        Thread.Sleep(30);
                        continue;
                    }
                    consecutiveFails = 0;
                    frameCount++;

                    // Cursor oranını hesapla (0-1)
                    float cx, cy;
                    Input.CursorRatio(out cx, out cy);
                    int payloadLen = 8 + jpg.Length; // 4 byte cx + 4 byte cy + JPEG
                    byte[] head = new byte[12]; // 4 len + 4 cx + 4 cy
                    head[0] = (byte)(payloadLen >> 24);
                    head[1] = (byte)(payloadLen >> 16);
                    head[2] = (byte)(payloadLen >> 8);
                    head[3] = (byte)payloadLen;
                    byte[] cxb = BitConverter.GetBytes(cx);
                    byte[] cyb = BitConverter.GetBytes(cy);
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(cxb);
                        Array.Reverse(cyb);
                    }
                    Buffer.BlockCopy(cxb, 0, head, 4, 4);
                    Buffer.BlockCopy(cyb, 0, head, 8, 4);
                    ns.Write(head, 0, 12);
                    ns.Write(jpg, 0, jpg.Length);
                    ns.Flush();

                    if (!ackMode)
                    {
                        int rest = frameMs - (int)sw.ElapsedMilliseconds;
                        if (rest > 0) Thread.Sleep(rest);
                    }
                }
            }
            catch (Exception vex)
            {
                if (logRef != null) logRef("video hata: " + vex.Message);
            }
            try { if (ReferenceEquals(current, c)) current = null; c.Close(); } catch { }
            if (logRef != null) logRef("video: akış bitti");
        }

        public static Action<string> logRef;
    }

    // ------------------------- Telefon ekranı izleyici -------------------------

    internal class ScreenViewerForm : Form
    {
        private readonly object controlGate = new object();
        private TcpClient controlClient;
        private Button btnBack, btnHome, btnRecents, btnLandscape, btnPortrait;
        private bool phoneInputEnabled;
        private Point? touchStart;
        private DateTime touchStartedAt;
        private PictureBox pb;
        private Label lblStatus, lblConnection;
        private bool pingPending;
        private TcpListener listener;
        private volatile bool on;

        private bool fullscreen;
        private FormWindowState previousWindowState;
        private Rectangle previousBounds;

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData != Keys.F11 && (keyData != Keys.Escape || !fullscreen))
                return base.ProcessCmdKey(ref msg, keyData);

            if (!fullscreen)
            {
                Rectangle screen = Screen.FromControl(this).Bounds;
                previousWindowState = WindowState;
                previousBounds = WindowState == FormWindowState.Normal ? Bounds : RestoreBounds;
                WindowState = FormWindowState.Normal;
                FormBorderStyle = FormBorderStyle.None;
                Bounds = screen;
            }
            else
            {
                FormBorderStyle = FormBorderStyle.Sizable;
                Bounds = previousBounds;
                WindowState = previousWindowState;
            }
            fullscreen = !fullscreen;
            return true;
        }

        public ScreenViewerForm()
        {
            Text = "Telefon Ekranı — yansıtma bekleniyor";
            ClientSize = new Size(360, 680);
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            lblStatus = new Label
            {
                Dock = DockStyle.Top,
                Height = 42,
                Text = "Port 40558 dinleniyor — telefonda 'Yansıtmayı Başlat' deyin",
                TextAlign = ContentAlignment.MiddleCenter,
                ForeColor = Color.DimGray
            };
            pb = new PictureBox { Dock = DockStyle.Fill, SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.Black };
            pb.Cursor = Cursors.Hand;
            pb.MouseDown += delegate(object sender, MouseEventArgs e)
            {
                Point point;
                if (e.Button != MouseButtons.Left) return;
                touchStart = null;
                if (!phoneInputEnabled || !TryPhonePoint(e.Location, out point)) return;
                touchStart = point;
                touchStartedAt = DateTime.UtcNow;
                pb.Capture = true;
            };
            pb.MouseUp += delegate(object sender, MouseEventArgs e)
            {
                Point? start = touchStart;
                touchStart = null;
                pb.Capture = false;
                Point end;
                if (e.Button != MouseButtons.Left || !start.HasValue || !TryPhonePoint(e.Location, out end)) return;
                int duration = (int)Math.Min(2000, Math.Max(50, (DateTime.UtcNow - touchStartedAt).TotalMilliseconds));
                if (Math.Abs(start.Value.X - end.X) < 350 && Math.Abs(start.Value.Y - end.Y) < 350) end = start.Value;
                SendTouch(start.Value, end, duration);
            };
            MouseWheel += delegate(object sender, MouseEventArgs e)
            {
                Point point;
                if (!phoneInputEnabled || e.Delta == 0 || !TryPhonePoint(pb.PointToClient(Cursor.Position), out point)) return;
                int distance = Math.Min(30000, Math.Max(1, Math.Abs(e.Delta) / SystemInformation.MouseWheelScrollDelta) * 12000);
                int startY = Math.Max(0, Math.Min(65535 - distance, point.Y - distance / 2));
                Point top = new Point(point.X, startY);
                Point bottom = new Point(point.X, startY + distance);
                if (e.Delta > 0) SendTouch(top, bottom, 220);
                else SendTouch(bottom, top, 220);
            };
            new ToolTip().SetToolTip(pb, "Tıkla: dokun • Sürükle: kaydır • F11: tam ekran");
            Controls.Add(pb);
            Controls.Add(lblStatus);
            lblConnection = new Label { Dock = DockStyle.Top, Height = 24, TextAlign = ContentAlignment.MiddleCenter,
                Text = "Bağlantı bekleniyor   |   Ping: —" };
            Controls.Add(lblConnection);
            FlowLayoutPanel rotation = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 38, Padding = new Padding(6, 3, 6, 0), WrapContents = false };
            btnLandscape = new Button { Text = "Yatay", Width = 100, Height = 28, Enabled = false };
            btnPortrait = new Button { Text = "Dikey", Width = 100, Height = 28, Enabled = false };
            btnLandscape.Click += delegate { SendNavigation((byte)'Y'); };
            btnPortrait.Click += delegate { SendNavigation((byte)'P'); };
            rotation.Controls.Add(btnLandscape);
            rotation.Controls.Add(btnPortrait);
            Controls.Add(rotation);
            var connectionTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            connectionTimer.Tick += UpdateConnectionStatus;
            Disposed += delegate { connectionTimer.Dispose(); };
            connectionTimer.Start();
            FlowLayoutPanel navigation = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 42, Padding = new Padding(6), WrapContents = false };
            btnBack = new Button { Text = "Geri", Width = 100, Height = 28, Enabled = false };
            btnHome = new Button { Text = "Ana ekran", Width = 120, Height = 28, Enabled = false };
            btnBack.Click += delegate { SendNavigation((byte)'B'); };
            btnHome.Click += delegate { SendNavigation((byte)'H'); };
            navigation.Controls.Add(btnBack);
            navigation.Controls.Add(btnHome);
            btnRecents = new Button { Text = "Son uygulamalar", Width = 130, Height = 28, Enabled = false };
            btnRecents.Click += delegate { SendNavigation((byte)'A'); };
            navigation.Controls.Add(btnRecents);
            Controls.Add(navigation);

            FormClosing += delegate(object sender, FormClosingEventArgs e)
            {
                if (e.CloseReason == CloseReason.UserClosing)
                {
                    e.Cancel = true;
                    Hide();
                    return;
                }
                on = false;
                try { listener.Stop(); } catch { }
            };
        }

        private async void UpdateConnectionStatus(object sender, EventArgs e)
        {
            if (!Visible || pingPending) return;

            TcpClient client;
            IPAddress localAddress;
            IPAddress phoneAddress;
            lock (controlGate)
            {
                client = controlClient;
                if (client == null)
                {
                    lblConnection.Text = "Bağlantı bekleniyor   |   Ping: —";
                    return;
                }
                localAddress = ((IPEndPoint)client.Client.LocalEndPoint).Address;
                phoneAddress = ((IPEndPoint)client.Client.RemoteEndPoint).Address;
            }

            string connection = ConnectionLabel(localAddress);
            string latency = "—";
            pingPending = true;
            try
            {
                using (var ping = new System.Net.NetworkInformation.Ping())
                {
                    var reply = await ping.SendPingAsync(phoneAddress, 800);
                    if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                        latency = reply.RoundtripTime + " ms";
                }
            }
            catch (System.Net.NetworkInformation.PingException) { }
            finally { pingPending = false; }

            lock (controlGate)
            {
                if (!IsDisposed && ReferenceEquals(controlClient, client))
                    lblConnection.Text = connection + "   |   Ping: " + latency;
            }
        }

        private static string ConnectionLabel(IPAddress localAddress)
        {
            foreach (var adapter in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var address in adapter.GetIPProperties().UnicastAddresses)
                {
                    if (!address.Address.Equals(localAddress)) continue;
                    string description = adapter.Description;
                    if (description.IndexOf("RNDIS", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        description.IndexOf("NCM", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        description.IndexOf("Internet Sharing", StringComparison.OrdinalIgnoreCase) >= 0)
                        return "USB ile bağlı";
                    if (adapter.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211)
                        return "Wi-Fi ile bağlı";
                    return "Yerel ağ ile bağlı";
                }
            }
            return "Ağ ile bağlı";
        }

        private bool TryPhonePoint(Point mouse, out Point point)
        {
            point = Point.Empty;
            if (pb.Image == null || pb.ClientSize.Width <= 0 || pb.ClientSize.Height <= 0) return false;
            double scale = Math.Min((double)pb.ClientSize.Width / pb.Image.Width, (double)pb.ClientSize.Height / pb.Image.Height);
            double width = pb.Image.Width * scale, height = pb.Image.Height * scale;
            double x = mouse.X - (pb.ClientSize.Width - width) / 2;
            double y = mouse.Y - (pb.ClientSize.Height - height) / 2;
            if (x < 0 || y < 0 || x >= width || y >= height) return false;
            point = new Point((int)(x / width * 65535), (int)(y / height * 65535));
            return true;
        }

        private void SendTouch(Point start, Point end, int duration)
        {
            byte[] packet = new byte[11];
            packet[0] = (byte)'T';
            int[] values = { start.X, start.Y, end.X, end.Y, duration };
            for (int i = 0; i < values.Length; i++)
            {
                packet[1 + i * 2] = (byte)(values[i] >> 8);
                packet[2 + i * 2] = (byte)values[i];
            }
            try
            {
                lock (controlGate)
                {
                    if (controlClient == null) return;
                    controlClient.GetStream().Write(packet, 0, packet.Length);
                }
            }
            catch { SetStatus("Dokunma gönderilemedi — bağlantıyı kontrol edin"); }
        }

        private void SendNavigation(byte command)
        {
            try
            {
                lock (controlGate)
                {
                    if (controlClient == null) return;
                    controlClient.GetStream().WriteByte(command);
                }
            }
            catch { SetStatus("Tuş gönderilemedi — bağlantıyı kontrol edin"); }
        }

        private void SetNavigationEnabled(bool enabled)
        {
            try { BeginInvoke((MethodInvoker)delegate { phoneInputEnabled = enabled; btnBack.Enabled = enabled; btnHome.Enabled = enabled; btnRecents.Enabled = enabled; btnLandscape.Enabled = enabled; btnPortrait.Enabled = enabled; pb.Cursor = enabled ? Cursors.Hand : Cursors.Default; }); }
            catch { }
        }

        public void StartListening()
        {
            if (on) return;
            // Create a UI handle without showing the window; receive while in the tray.
            IntPtr handle = Handle;
            on = true;
            try
            {
                listener = new TcpListener(IPAddress.Any, 40558);
            SocketLifetime.Private(listener.Server);
                listener.Start();
                Thread accThread = new Thread(AcceptLoop);
                accThread.IsBackground = true;
                accThread.Start();
            }
            catch (Exception ex)
            {
                lblStatus.Text = "Dinleyici açılamadı: " + ex.Message;
                MessageBox.Show("Dinleyici açılamadı: " + ex.Message + "\n\nMuhtemelen güvenlik duvarı engelliyor.\nAna pencerede 'Güvenlik Duvarına Ekle' düğmesini kullanın.");
            }
        }

        private void AcceptLoop()
        {
            while (on)
            {
                TcpClient c = null;
                try
                {
                    c = listener.AcceptTcpClient(); SocketLifetime.Private(c.Client);
                    c.NoDelay = true;
                    c.SendTimeout = 1500;
                    // Her istemci kendi iş parçacığında: yarı açık bağlantılar kabulü kilitlemesin
                    TcpClient cc = c;
                    Thread t = new Thread(() => ServeClient(cc));
                    t.IsBackground = true;
                    t.Start();
                }
                catch
                {
                    try { if (c != null) c.Close(); } catch { }
                    if (on) Thread.Sleep(300);
                }
            }
        }

        private void ServeClient(TcpClient c)
        {
            string ip = "?";
            try { ip = ((IPEndPoint)c.Client.RemoteEndPoint).Address.ToString(); } catch { }
            // PIN el sıkışması: doğru PIN gelmeden pencere bile açılmaz, kare okunmaz
            NetworkStream ns = null;
            try
            {
                ns = c.GetStream();
                c.ReceiveTimeout = 5000;
                string hello = ReadHello(ns);
                string pin = "";
                foreach (string part in hello.Split(' '))
                {
                    string[] kv = part.Split('=');
                    if (kv.Length == 2 && kv[0] == "pin") pin = kv[1];
                }
                if (!Pairing.IsValid(pin))
                {
                    if (VideoServer.logRef != null) VideoServer.logRef("Telefon Ekranı: PIN reddi (" + ip + ")");
                    return;
                }
                c.ReceiveTimeout = 0;
            }
            catch
            {
                if (VideoServer.logRef != null) VideoServer.logRef("Telefon Ekranı: el sıkışma başarısız (" + ip + ")");
                try { if (ns != null) ns.Dispose(); } catch { }
                try { c.Close(); } catch { }
                return;
            }
            try
            {
                BeginInvoke((MethodInvoker)delegate
                {
                    Show();
                    WindowState = FormWindowState.Normal;
                    Activate();
                });
            }
            catch { }
            lock (controlGate)
            {
                if (controlClient != null) { try { controlClient.Close(); } catch { } }
                controlClient = c;
            }
            SetNavigationEnabled(true);
            SetStatus("Telefon bağlandı (" + ip + ")");
            if (VideoServer.logRef != null) VideoServer.logRef("Telefon Ekranı: bağlantı (" + ip + ")");
            try
            {
                while (on)
                {
                    byte[] head = ReadExact(ns, 4);
                    int len = (head[0] << 24) | (head[1] << 16) | (head[2] << 8) | head[3];
                    if (len == -13) { SetNavigationEnabled(false); SetStatus("Yansıtma canlı — bu sürümde telefon kontrolü kapalı"); continue; }
                    if (len == -10) { SetStatus("Telefon komutu uygulandı"); continue; }
                    if (len == -11) { SetStatus("Telefonda Erişilebilirlik > PC Kumanda — Telefon tuşları hizmetini açın"); continue; }
                    if (len == -14) { SetStatus("Telefonda Ekran yönü iznini açın"); continue; }
                    if (len == -12) { SetStatus("Telefon komutu şu anda uygulanamadı"); continue; }
                    if (len <= 0 || len > 8 * 1024 * 1024) throw new IOException("kare hatali");
                    byte[] jpg = ReadExact(ns, len);
                    Bitmap bmp;
                    using (MemoryStream ms = new MemoryStream(jpg))
                    {
                        bmp = new Bitmap(ms);
                    }
                    try
                    {
                        BeginInvoke((MethodInvoker)delegate
                        {
                            Image old = pb.Image;
                            pb.Image = bmp;
                            if (old != null) old.Dispose();
                        });
                    }
                    catch { }
                }
            }
            catch
            {
                lock (controlGate)
                {
                    if (ReferenceEquals(controlClient, c))
                    {
                        controlClient = null;
                        SetNavigationEnabled(false);
                        SetStatus("Bağlantı koptu — telefon yeniden bağlanır");
                    }
                }
                if (VideoServer.logRef != null) VideoServer.logRef("Telefon Ekranı: bağlantı koptu (" + ip + ")");
            }
            finally
            {
                try { if (ns != null) ns.Dispose(); } catch { }
                try { c.Close(); } catch { }
            }
        }

        private void SetStatus(string t)
        {
            try
            {
                BeginInvoke((MethodInvoker)delegate
                {
                    lblStatus.Text = t;
                    Text = "Telefon Ekranı — " + t;
                });
            }
            catch { }
        }

        private byte[] ReadExact(NetworkStream ns, int count)
        {
            byte[] buf = new byte[count];
            int off = 0;
            while (off < count)
            {
                int n = ns.Read(buf, off, count - off);
                if (n <= 0) throw new IOException("kopdu");
                off += n;
            }
            return buf;
        }

        // PIN el sıkışma satırı (en fazla 128 bayt, 5 sn sınırı)
        private string ReadHello(NetworkStream ns)
        {
            StringBuilder sb = new StringBuilder();
            DateTime deadline = DateTime.UtcNow.AddSeconds(5);
            while (sb.Length < 128)
            {
                int b = ns.ReadByte();
                if (b < 0) throw new IOException("kopdu");
                if (b == '\n') break;
                if (b != '\r') sb.Append((char)b);
                if ((DateTime.UtcNow - deadline).TotalMilliseconds > 0) throw new IOException("el sıkışma zaman aşımı");
            }
            return sb.ToString();
        }
    }

    // ------------------------- Telefon mikrofonu → PC -------------------------
    // Telefon PCM sesi (48000 Hz / 16 bit / mono) TCP 40556'ya akıtır,
    // sunucu bunu seçilen ses çıkışına (hoparlör veya VB-CABLE "CABLE Input") çalar.
    internal static class MicServer
    {
        private static TcpListener listener;
        private static readonly object qGate = new object();
        private static readonly Queue<byte[]> fifo = new Queue<byte[]>();
        private static byte[] pinnedA, pinnedB;
        private static GCHandle pinA, pinB;
        private static IntPtr hWave = IntPtr.Zero;
        private static int openDeviceId = int.MinValue;
        private static bool toggleA;
        public static Action<string> Status;
        private static int reopenRequested;
        public static volatile int SelectedDevice = -1; // -1 = varsayılan çıktı

        [StructLayout(LayoutKind.Sequential)]
        private struct WAVEFORMATEX
        {
            public ushort wFormatTag; public ushort nChannels; public uint nSamplesPerSec;
            public uint nAvgBytesPerSec; public ushort nBlockAlign; public ushort wBitsPerSample; public ushort cbSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WAVEHDR
        {
            public IntPtr lpData; public uint dwBufferLength; public uint dwBytesRecorded;
            public IntPtr dwUser; public uint dwFlags; public uint dwLoops; public IntPtr lpNext; public IntPtr reserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WAVEOUTCAPSW
        {
            public ushort wMid, wPid; public uint vDriverVersion;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szPname;
            public uint dwFormats, wChannels, wSupport;
        }

        [DllImport("winmm.dll")] private static extern uint waveOutOpen(out IntPtr h, uint devId, ref WAVEFORMATEX fmt, IntPtr cb, IntPtr inst, uint flags);
        [DllImport("winmm.dll")] private static extern uint waveOutPrepareHeader(IntPtr h, IntPtr hdr, uint size);
        [DllImport("winmm.dll")] private static extern uint waveOutUnprepareHeader(IntPtr h, IntPtr hdr, uint size);
        [DllImport("winmm.dll")] private static extern uint waveOutWrite(IntPtr h, IntPtr hdr, uint size);
        [DllImport("winmm.dll")] private static extern uint waveOutClose(IntPtr h);
        [DllImport("winmm.dll")] private static extern uint waveOutGetNumDevs();
        [DllImport("winmm.dll")] private static extern uint waveOutGetDevCapsW(uint devId, ref WAVEOUTCAPSW caps, uint size);

        private const uint WHDR_DONE = 0x1;
        private static readonly uint WaveMapper = uint.MaxValue;
        private const int ChunkBytes = 4800; // 50 ms (48000 Hz × 2 bayt × mono)

        public static void Start()
        {
            listener = new TcpListener(IPAddress.Any, 40556);
            SocketLifetime.Private(listener.Server);
            listener.Start();
            Thread a = new Thread(AcceptLoop); a.IsBackground = true; a.Start();
            Thread p = new Thread(PlayLoop); p.IsBackground = true; p.Start();
            Notify("hazır");
        }

        public static string[] ListDevices()
        {
            List<string> list = new List<string>();
            try
            {
                uint n = waveOutGetNumDevs();
                for (uint i = 0; i < n; i++)
                {
                    WAVEOUTCAPSW caps = new WAVEOUTCAPSW();
                    if (waveOutGetDevCapsW(i, ref caps, (uint)Marshal.SizeOf(typeof(WAVEOUTCAPSW))) == 0)
                        list.Add(caps.szPname);
                    else list.Add("Cihaz " + i);
                }
            }
            catch { }
            return list.ToArray();
        }

        public static void ReopenWave() { Interlocked.Exchange(ref reopenRequested, 1); }

        private static void CloseWave()
        {
            if (hWave != IntPtr.Zero) { waveOutClose(hWave); hWave = IntPtr.Zero; }
            if (pinA.IsAllocated) pinA.Free();
            if (pinB.IsAllocated) pinB.Free();
            openDeviceId = int.MinValue;
        }

        private static void Notify(string s)
        {
            if (Status != null) Status(s);
        }

        // El sıkışma satırı (en fazla 128 bayt) — duran istemciler burada takılır kalmaz
        private static string ReadHello(NetworkStream ns)
        {
            StringBuilder sb = new StringBuilder();
            DateTime deadline = DateTime.UtcNow.AddSeconds(5);
            while (sb.Length < 128)
            {
                int b = ns.ReadByte();
                if (b < 0) throw new IOException("kopdu");
                if (b == '\n') break;
                if (b != '\r') sb.Append((char)b);
                if ((DateTime.UtcNow - deadline).TotalMilliseconds > 0) throw new IOException("el sıkışma zaman aşımı");
            }
            return sb.ToString();
        }

        private static void AcceptLoop()
        {
            while (true)
            {
                TcpClient c = null;
                NetworkStream ns = null;
                try
                {
                    c = listener.AcceptTcpClient(); SocketLifetime.Private(c.Client);
                    c.NoDelay = true;
                    c.ReceiveTimeout = 5000; // el sıkışma için
                    ns = c.GetStream();
                    string hello = ReadHello(ns);
                    string pin = "";
                    foreach (string part in hello.Split(' '))
                    {
                        string[] kv = part.Split('=');
                        if (kv.Length == 2 && kv[0] == "pin") pin = kv[1];
                    }
                    if (!Pairing.IsValid(pin))
                    {
                        Notify("mikrofon: PIN reddi — bağlantı kapatıldı");
                        throw new IOException("pin reddi");
                    }
                    c.ReceiveTimeout = 0; // akış modu
                    Notify("telefon bağlı — akış sürüyor");
                    byte[] buf = new byte[ChunkBytes];
                    while (true)
                    {
                        int off = 0;
                        while (off < buf.Length)
                        {
                            int n = ns.Read(buf, off, buf.Length - off);
                            if (n <= 0) throw new IOException("kopdu");
                            off += n;
                        }
                        byte[] chunk = new byte[buf.Length];
                        Array.Copy(buf, chunk, buf.Length);
                        lock (qGate)
                        {
                            fifo.Enqueue(chunk);
                            while (fifo.Count > 4) fifo.Dequeue(); // gecikme birikmesin
                        }
                    }
                }
                catch
                {
                    Notify("mikrofon bekleniyor");
                }
                finally
                {
                    try { if (ns != null) ns.Dispose(); } catch { }
                    try { if (c != null) c.Close(); } catch { }
                    lock (qGate) { fifo.Clear(); }
                }
            }
        }

        private static void EnsureWave()
        {
            if (hWave != IntPtr.Zero && openDeviceId == SelectedDevice) return;
            CloseWave();
            WAVEFORMATEX fmt = new WAVEFORMATEX();
            fmt.wFormatTag = 1; // PCM
            fmt.nChannels = 1;
            fmt.nSamplesPerSec = 48000;
            fmt.wBitsPerSample = 16;
            fmt.nBlockAlign = 2;
            fmt.nAvgBytesPerSec = 96000;
            fmt.cbSize = 0;
            uint dev = SelectedDevice < 0 ? WaveMapper : (uint)SelectedDevice;
            uint hr = waveOutOpen(out hWave, dev, ref fmt, IntPtr.Zero, IntPtr.Zero, 0);
            if (hr != 0) { hWave = IntPtr.Zero; Notify("ses cihazı açılamadı (hr=" + hr + ")"); return; }
            openDeviceId = SelectedDevice;
            pinnedA = new byte[ChunkBytes];
            pinnedB = new byte[ChunkBytes];
            pinA = GCHandle.Alloc(pinnedA, GCHandleType.Pinned);
            pinB = GCHandle.Alloc(pinnedB, GCHandleType.Pinned);
        }

        private static void PlayLoop()
        {
            while (true)
            {
                byte[] chunk = null;
                lock (qGate)
                {
                    if (fifo.Count > 0)
                    {
                        chunk = fifo.Dequeue();
                        while (fifo.Count > 2) fifo.Dequeue();
                    }
                }
                if (chunk == null) { Thread.Sleep(15); continue; }
                if (Interlocked.Exchange(ref reopenRequested, 0) != 0) CloseWave();
                EnsureWave();
                if (hWave == IntPtr.Zero) continue;

                toggleA = !toggleA;
                byte[] target = toggleA ? pinnedA : pinnedB;
                GCHandle pin = toggleA ? pinA : pinB;
                Array.Copy(chunk, target, Math.Min(chunk.Length, target.Length));
                WAVEHDR hdr = new WAVEHDR();
                hdr.lpData = pin.AddrOfPinnedObject();
                hdr.dwBufferLength = (uint)chunk.Length;
                IntPtr hp = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WAVEHDR)));
                try
                {
                    Marshal.StructureToPtr(hdr, hp, false);
                    waveOutPrepareHeader(hWave, hp, (uint)Marshal.SizeOf(typeof(WAVEHDR)));
                    waveOutWrite(hWave, hp, (uint)Marshal.SizeOf(typeof(WAVEHDR)));
                    int waited = 0;
                    while ((hdr.dwFlags & WHDR_DONE) == 0)
                    {
                        hdr = (WAVEHDR)Marshal.PtrToStructure(hp, typeof(WAVEHDR));
                        if ((hdr.dwFlags & WHDR_DONE) != 0) break;
                        Thread.Sleep(5);
                        waited += 5;
                        if (waited > 1000) break;
                    }
                    waveOutUnprepareHeader(hWave, hp, (uint)Marshal.SizeOf(typeof(WAVEHDR)));
                }
                finally
                {
                    Marshal.FreeHGlobal(hp);
                }
            }
        }
    }

    // ------------------------- Ağ sunucusu -------------------------

    internal static class NetServer
    {
        private static Config cfg;
        private static Action<string> log;
        private static JavaScriptSerializer json = new JavaScriptSerializer();
        public const int UdpPort = 40555;

        // UI (STA) işlemleri: pano erişimi ve tepsi balonu MainForm tarafından doldurulur
        public static Func<string> ClipGet;
        public static Action<string> ClipSet;
        public static Action<string, string> BalloonShow;

        // Cihaz izinleri: "Sürekli izin ver" denilen cihazlar burada kalıcı saklanır
        public delegate int AuthorizeDelegate(string devKey, string devName);
        private static AuthorizeDelegate authorize;
        private static HashSet<string> allowedDevices = new HashSet<string>();
        private static object devGate = new object();

        private static string DevicesPath
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PCKumanda", "devices.txt"); }
        }

        private static void LoadDevices()
        {
            try
            {
                if (File.Exists(DevicesPath))
                    foreach (string l in File.ReadAllLines(DevicesPath))
                        if (l.Trim().Length > 0) allowedDevices.Add(l.Trim());
            }
            catch { }
        }

        public static bool IsDeviceAllowed(string devKey)
        {
            lock (devGate) { return allowedDevices.Contains(devKey); }
        }

        private static void SaveDevices()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(DevicesPath));
                lock (devGate)
                {
                    File.WriteAllLines(DevicesPath, new List<string>(allowedDevices).ToArray());
                }
            }
            catch { }
        }

        // Bu makinenin IP'leri + localhost (Host basligi dogrulamasi ve /pair yerel kontrolu icin)
        private static HashSet<string> localIps;

        private static void InitLocalIps()
        {
            HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            set.Add("127.0.0.1");
            set.Add("localhost");
            set.Add("::1");
            try { set.Add(Environment.MachineName); } catch { }
            try
            {
                foreach (IPAddress a in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
                    if (a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a)) set.Add(a.ToString());
            }
            catch { }
            localIps = set;
        }

        public static bool IsLocalIp(string ip)
        {
            return localIps != null && !string.IsNullOrEmpty(ip) && localIps.Contains(ip);
        }

        // "192.168.1.20:40555" / "localhost:40555" / "[::1]:40555" bicimlerini cozer
        public static bool IsLocalHostHeader(string host)
        {
            if (localIps == null || string.IsNullOrEmpty(host)) return false;
            string h = host.Trim();
            if (h.Length == 0) return false;
            if (h[0] == '[')
            {
                int cb = h.IndexOf(']');
                if (cb <= 0) return false;
                h = h.Substring(1, cb - 1);
            }
            else
            {
                int c = h.IndexOf(':');
                if (c > 0 && h.IndexOf(':', c + 1) < 0) h = h.Substring(0, c); // IPv4:port
            }
            return h.Length > 0 && localIps.Contains(h);
        }

        public static void Start(Config config, Action<string> logger, AuthorizeDelegate authorizer)
        {
            cfg = config;
            log = logger;
            authorize = authorizer;
            InitLocalIps();
            LoadDevices();
            Thread tcp = new Thread(TcpLoop);
            tcp.IsBackground = true;
            tcp.Start();
            Thread udp = new Thread(UdpLoop);
            udp.IsBackground = true;
            udp.Start();
        }

        private static void TcpLoop()
        {
            try { System.IO.File.AppendAllText(Path.Combine(Path.GetTempPath(), "pckumanda-tcp.log"),
                DateTime.Now.ToString("HH:mm:ss.fff ") + "TcpLoop basliyor port=" + cfg.Port + Environment.NewLine); } catch { }
            TcpListener l = null;
            while (true)
            {
                try
                {
                    if (l == null)
                    {
                        l = new TcpListener(IPAddress.Any, cfg.Port);
                        try { SocketLifetime.Private(l.Server); } catch { } // best-effort: child-process'a devri engelle, başarısızsa da dinle
                        l.Start();
                        try { System.IO.File.AppendAllText(Path.Combine(Path.GetTempPath(), "pckumanda-tcp.log"),
                            DateTime.Now.ToString("HH:mm:ss.fff ") + "LISTENING " + ((IPEndPoint)l.LocalEndpoint).Port + Environment.NewLine); } catch { }
                    }
                    TcpClient c = l.AcceptTcpClient(); SocketLifetime.Private(c.Client);
                    ThreadPool.QueueUserWorkItem(delegate { try { HandleClient(c); } catch { } try { c.Close(); } catch { } });
                }
                catch (Exception tcpEx)
                {
                    // Accept hatası (ör. istemcinin yarida kesilmesi) dinleyiciyi oluldurmasin:
                    // soketi kapatalim, kisa bekleyip ayni portta yeniden açalim.
                    try { System.IO.File.AppendAllText(Path.Combine(Path.GetTempPath(), "pckumanda-tcp.log"),
                        DateTime.Now.ToString("HH:mm:ss.fff ") + tcpEx.GetType().Name + ": " + tcpEx.Message + Environment.NewLine); } catch { }
                    try { if (l != null) l.Server.Close(); } catch { }
                    l = null;
                    Thread.Sleep(500);
                }
            }
        }

        private static void UdpLoop()
        {
            while (true)
            {
                try
                {
                    UdpClient u = new UdpClient(UdpPort);
                    SocketLifetime.Private(u.Client);
                    while (true)
                    {
                        IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                        byte[] data = u.Receive(ref ep);
                        string s = Encoding.UTF8.GetString(data);
                        if (s == "PCREMOTE_DISCOVER")
                        {
                            string reply = "{\"app\":\"pc-remote\",\"name\":\"" + JsonEsc(Environment.MachineName) + "\",\"tcp\":" + cfg.Port + ",\"mac\":\"" + JsonEsc(GetMac()) + "\"}";
                            byte[] rb = Encoding.UTF8.GetBytes(reply);
                            u.Send(rb, rb.Length, ep);
                            continue;
                        }
                        // PIN dogrulamasi: komutlar "komut|PIN" biciminde gelir (GP'nin kendi | ayraclarindan
                        // ayirmak icin SON | segmenti PIN olarak okunur). Yanlis/eksik PIN -> sessizce dusur.
                        int pinSep = s.LastIndexOf('|');
                        if (pinSep <= 0 || !Pairing.IsValid(s.Substring(pinSep + 1))) continue;
                        s = s.Substring(0, pinSep);
                        if (s.Length == 0 || s[0] != 'M' && s[0] != 'G') continue;
                        if (s.StartsWith("M")) Input.WakeScreen();
                        if (s.StartsWith("MM:")) // Bağıl hareket: MM:dx,dy
                        {
                            string[] p = s.Substring(3).Split(',');
                            int dx, dy;
                            if (p.Length >= 2 && int.TryParse(p[0], out dx) && int.TryParse(p[1], out dy))
                                Input.Move(dx, dy);
                        }
                        else if (s.StartsWith("MP:")) // Mutlak imleç konumu (0-1): MP:nx,ny
                        {
                            string[] p = s.Substring(3).Split(',');
                            double nx, ny;
                            if (p.Length >= 2 &&
                                double.TryParse(p[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out nx) &&
                                double.TryParse(p[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out ny))
                            {
                                if (nx < 0) nx = 0; if (nx > 1) nx = 1;
                                if (ny < 0) ny = 0; if (ny > 1) ny = 1;
                                Rectangle vs = DesktopFeatures.Bounds;
                                Input.SetPos(vs.X + (int)(nx * vs.Width), vs.Y + (int)(ny * vs.Height));
                            }
                        }
                        else if (s.StartsWith("MC:")) // Tıklama: MC:button,count
                        {
                            string[] p = s.Substring(3).Split(',');
                            int btn, cnt;
                            if (p.Length >= 2 && int.TryParse(p[0], out btn) && int.TryParse(p[1], out cnt))
                                Input.Click(btn, cnt);
                        }
                        else if (s.StartsWith("MD:")) // Buton bas/bırak: MD:button,down
                        {
                            string[] p = s.Substring(3).Split(',');
                            int btn, down;
                            if (p.Length >= 2 && int.TryParse(p[0], out btn) && int.TryParse(p[1], out down))
                                Input.Button(btn, down == 1);
                        }
                        else if (s.StartsWith("MS:")) // Kaydırma: MS:dy,dx
                        {
                            string[] p = s.Substring(3).Split(',');
                            float dy, dx;
                            if (p.Length >= 2 &&
                                float.TryParse(p[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out dy) &&
                                float.TryParse(p[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out dx))
                                Input.Scroll(dy, dx);
                        }
                        else if (s.StartsWith("MA:")) // Mutlak tıklama: MA:nx,ny,button,count
                        {
                            string[] p = s.Substring(3).Split(',');
                            double nx, ny;
                            int btn, cnt;
                            if (p.Length >= 4 &&
                                double.TryParse(p[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out nx) &&
                                double.TryParse(p[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out ny) &&
                                int.TryParse(p[2], out btn) && int.TryParse(p[3], out cnt))
                            {
                                Input.AbsClick(nx, ny, btn, cnt);
                            }
                        }
                        else if (s.StartsWith("GP:")) // Gamepad: GP:session|keys|dx,dy|fire
                        {
                            Input.WakeScreen();
                            try
                            {
                                string[] parts = s.Substring(3).Split('|');
                                if (parts.Length >= 4)
                                {
                                    string session = parts[0];
                                    string keys = parts[1];
                                    string[] deltas = parts[2].Split(',');
                                    double dx = 0, dy = 0;
                                    if (deltas.Length >= 2)
                                    {
                                        double.TryParse(deltas[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out dx);
                                        double.TryParse(deltas[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out dy);
                                    }
                                    bool fire = (parts[3] == "1");
                                    GameInput.Update(session, keys, dx, dy, fire, false);
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (log != null) log("UDP keşif hatası: " + ex.Message + " (2 sn sonra tekrar)");
                    Thread.Sleep(2000);
                }
            }
        }

        private static string QueryVal(string path, string key)
        {
            int i = path.IndexOf(key + "=");
            if (i < 0) return "";
            string v = path.Substring(i + key.Length + 1).Split('&')[0];
            try { return Uri.UnescapeDataString(v.Replace("+", " ")); } catch { return v; }
        }

        private static readonly string[] AllowedRoots = { "Desktop", "Downloads", "Documents", "Pictures", "Music", "Videos" };
        private const string SharedRoot = "Paylaşılan klasörler";

        private static Dictionary<string, string> GetSharedFolders()
        {
            var shares = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            using (var search = new System.Management.ManagementObjectSearcher(
                "SELECT Name, Path, Type FROM Win32_Share WHERE Type = 0"))
            using (var results = search.Get())
            {
                foreach (System.Management.ManagementObject share in results)
                using (share)
                {
                    string name = Convert.ToString(share["Name"]);
                    string path = Convert.ToString(share["Path"]);
                    if (!string.IsNullOrEmpty(name) && !name.EndsWith("$") && Directory.Exists(path))
                        shares[name] = path;
                }
            }
            return shares;
        }

        private static bool TryResolveFile(string rel, out string full)
        {
            full = null;
            rel = (rel ?? "").Replace('/', '\\');
            if (Path.IsPathRooted(rel)) return false;
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] parts = rel.Split('\\');
            if (parts.Length == 0 || parts[0].Trim().Length == 0) return false;
            foreach (string part in parts)
                if (part == "." || part == ".." || part.Contains(":")) return false;
            string rootFull;
            string suffix;
            if (string.Equals(parts[0], SharedRoot, StringComparison.OrdinalIgnoreCase))
            {
                string sharedPath;
                if (parts.Length < 2 || !GetSharedFolders().TryGetValue(parts[1], out sharedPath)) return false;
                rootFull = Path.GetFullPath(sharedPath);
                suffix = string.Join("\\", parts, 2, parts.Length - 2);
            }
            else
            {
            bool rootOk = false;
            foreach (string r in AllowedRoots)
                if (string.Equals(parts[0], r, StringComparison.OrdinalIgnoreCase)) { rootOk = true; break; }
            if (!rootOk) return false;
                rootFull = Path.GetFullPath(Path.Combine(profile, parts[0]));
                suffix = string.Join("\\", parts, 1, parts.Length - 1);
            }
            rootFull = rootFull.TrimEnd('\\');
            full = Path.GetFullPath(Path.Combine(rootFull + "\\", suffix));
            if (!string.Equals(full.TrimEnd('\\'), rootFull, StringComparison.OrdinalIgnoreCase) &&
                !full.StartsWith(rootFull + "\\", StringComparison.OrdinalIgnoreCase)) return false;
            // A child junction must not expose files outside the selected root.
            string current = rootFull + "\\";
            foreach (string part in suffix.Split('\\'))
            {
                if (part.Length == 0) continue;
                current = Path.Combine(current, part);
                if ((File.Exists(current) || Directory.Exists(current)) &&
                    (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return false;
            }
            return true;
        }

        private static string FileListJson(string rel)
        {
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            StringBuilder sb = new StringBuilder("{\"ok\":true,\"items\":[");
            if ((rel ?? "").Trim().Length == 0)
            {
                sb.Append("{\"n\":\"" + JsonEsc(SharedRoot) + "\",\"d\":true,\"s\":0},");
                foreach (string r in AllowedRoots)
                {
                    string p = Path.Combine(profile, r);
                    if (Directory.Exists(p)) sb.Append("{\"n\":\"" + JsonEsc(r) + "\",\"d\":true,\"s\":0},");
                }
            }
            else if (string.Equals(rel, SharedRoot, StringComparison.OrdinalIgnoreCase))
            {
                foreach (string name in GetSharedFolders().Keys)
                    sb.Append("{\"n\":\"" + JsonEsc(name) + "\",\"d\":true,\"s\":0},");
            }
            else
            {
                string full;
                if (TryResolveFile(rel, out full) && Directory.Exists(full))
                {
                    foreach (string d in Directory.GetDirectories(full))
                        sb.Append("{\"n\":\"" + JsonEsc(Path.GetFileName(d)) + "\",\"d\":true,\"s\":0},");
                    foreach (string fp in Directory.GetFiles(full))
                        sb.Append("{\"n\":\"" + JsonEsc(Path.GetFileName(fp)) + "\",\"d\":false,\"s\":" + new FileInfo(fp).Length + "},");
                }
                else return "{\"ok\":false,\"error\":\"Klasör bulunamadı veya erişime kapalı\"}";
            }
            if (sb.ToString().EndsWith(",")) sb.Remove(sb.Length - 1, 1);
            sb.Append("]}");
            return sb.ToString();
        }

        private static string JsonEsc(string s)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char ch in s)
            {
                if (ch == '"' || ch == '\\') { sb.Append('\\'); sb.Append(ch); }
                else if (ch < 32) sb.AppendFormat("\\u{0:x4}", (int)ch);
                else sb.Append(ch);
            }
            return sb.ToString();
        }

        // WoL için aktif ağ bağdaştırıcısının MAC adresi
        public static string GetMac()
        {
            try
            {
                foreach (System.Net.NetworkInformation.NetworkInterface nic in
                    System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                    System.Net.NetworkInformation.NetworkInterfaceType t = nic.NetworkInterfaceType;
                    if (t != System.Net.NetworkInformation.NetworkInterfaceType.Ethernet &&
                        t != System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211) continue;
                    byte[] a = nic.GetPhysicalAddress().GetAddressBytes();
                    if (a.Length == 6)
                    {
                        string[] parts = Array.ConvertAll(a, delegate(byte x) { return x.ToString("X2"); });
                        return string.Join("-", parts);
                    }
                }
            }
            catch { }
            return "";
        }

        private static int ReadByte(Stream s)
        {
            try { return s.ReadByte(); }
            catch { return -1; }
        }

        private static string ReadLine(Stream s)
        {
            StringBuilder sb = new StringBuilder();
            int b;
            while ((b = ReadByte(s)) >= 0)
            {
                if (b == '\n') break;
                if (b != '\r') sb.Append((char)b);
                if (sb.Length > 8192) break;
            }
            return (b < 0 && sb.Length == 0) ? null : sb.ToString();
        }

        private static byte[] ReadExact(Stream s, int count)
        {
            byte[] buf = new byte[count];
            int off = 0;
            while (off < count)
            {
                int n = s.Read(buf, off, count - off);
                if (n <= 0) throw new IOException("govde yarida koptu");
                off += n;
            }
            return buf;
        }

        private static void HandleClient(TcpClient client)
        {
            client.ReceiveTimeout = 30000;
            client.SendTimeout = 8000;
            NetworkStream ns = client.GetStream();

            // Keep-alive: fare hareketi gibi sık istekler için aynı bağlantı yeniden kullanılır.
            for (int served = 0; served < 100000; served++)
            {
                string reqLine = ReadLine(ns);
                if (string.IsNullOrEmpty(reqLine)) return;
                string[] parts = reqLine.Split(' ');
                if (parts.Length < 2) { WriteResp(ns, 400, "Bad Request", "text/plain", "bad"); return; }
                string method = parts[0];
                string path = parts[1];

                int contentLength = 0;
                bool badContentLength = false;
                Dictionary<string, string> headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                string line;
                while ((line = ReadLine(ns)) != null && line.Length > 0)
                {
                    int idx = line.IndexOf(':');
                    if (idx > 0)
                    {
                        string k = line.Substring(0, idx).Trim();
                        string v = line.Substring(idx + 1).Trim();
                        headers[k] = v;
                        if (k.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) && !int.TryParse(v, out contentLength))
                            badContentLength = true;
                    }
                    if (headers.Count > 60) break;
                }
                // Dosya yüklemeye büyük gövde izni ver, diğer istekler küçük kalır
                int bodyCap = (path.StartsWith("/upload") || path.StartsWith("/sync/file")) ? 600 * 1024 * 1024 : 1024 * 512;
                if (badContentLength) { WriteResp(ns, 400, "Bad Request", "application/json", "{\"ok\":false,\"error\":\"gecersiz govde uzunlugu\"}"); return; }
                if (contentLength < 0 || contentLength > bodyCap) { WriteResp(ns, 413, "Too Large", "application/json", "{\"ok\":false,\"error\":\"govde cok buyuk\"}"); return; }

                string connVal;
                bool clientWantsClose = headers.TryGetValue("Connection", out connVal) &&
                    connVal.IndexOf("close", StringComparison.OrdinalIgnoreCase) >= 0;

                // ---- Host dogrulamasi: baska alan adlari (DNS rebinding) reddedilir ----
                string hostH;
                headers.TryGetValue("Host", out hostH);
                if (string.IsNullOrEmpty(hostH) || !IsLocalHostHeader(hostH))
                {
                    WriteResp(ns, 403, "Forbidden", "text/plain", "host reddedildi");
                    return;
                }

                string clientIp = "?";
                try { clientIp = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString(); } catch { }
                bool localRequest = IsLocalIp(clientIp);

                // ---- PIN kapisi: yanlis/eksik PIN onay penceresi hic acilmadan 403 ----
                // (kotu niyetli web sitelerinin ve agdaki yabancilarin onay diyalogunu spamlemesini engeller)
                string pinH;
                bool pinOk = headers.TryGetValue("X-Pin", out pinH) && Pairing.IsValid(pinH.Trim());
                if (!pinOk && localRequest && method == "GET" && (path == "/pair" || path.StartsWith("/pair?")))
                    pinOk = true; // bu bilgisayardan acilan QR sayfasina izin (QR icinde PIN vardir)

                if (!pinOk)
                {
                    if (!Pairing.IsLockedOut(clientIp)) Pairing.RecordFail(clientIp);
                    bool locked = Pairing.IsLockedOut(clientIp);
                    if (log != null) log("PIN reddi: " + clientIp + (locked ? " (5 dk kilitli)" : ""));
                    WriteResp(ns, 403, "Forbidden", "application/json", "{\"ok\":false,\"error\":\"pin gerekli\"}");
                    return;
                }
                Pairing.Reset(clientIp);

                // ---- Cihaz izni: PIN dogruysa ve cihaz bilinmiyorsa PC'de onay penceresi cikar ----
                // (bkz. MainForm.AuthorizeDevice). Bu makinenin kendi istekleri onaysiz gecer.
                string devKey;
                string devName;
                string dvH, dnH;
                if (headers.TryGetValue("X-Device", out dvH) && dvH.Trim().Length > 0) devKey = dvH.Trim();
                else devKey = "web-" + clientIp;
                if (headers.TryGetValue("X-DevName", out dnH) && dnH.Trim().Length > 0) devName = dnH.Trim();
                else devName = "Tarayıcı (" + clientIp + ")";

                bool deviceAllowed = false;
                lock (devGate) { deviceAllowed = allowedDevices.Contains(devKey); }
                if (!deviceAllowed && !localRequest)
                {
                    int decision = authorize != null ? authorize(devKey, devName) : 2;
                    if (decision == 2)
                    {
                        lock (devGate) { allowedDevices.Add(devKey); }
                        SaveDevices();
                        if (log != null) log("CİHAZ KALICI İZİN: " + devName);
                    }
                    else if (decision == 1)
                    {
                        if (log != null) log("cihaz bu istek için izinli: " + devName);
                    }
                    else
                    {
                        if (log != null) log("CİHAZ REDDEDİLDİ: " + devName);
                        WriteResp(ns, 403, "Forbidden", "application/json", "{\"ok\":false,\"error\":\"cihaz reddedildi\"}");
                        return;
                    }
                }

                if (method == "GET" && (path == "/" || path.StartsWith("/index")))
                {
                    WriteResp(ns, 200, "OK", "text/html; charset=utf-8", Encoding.UTF8.GetBytes(WebUi.Html));
                }
                else if (method == "GET" && path == "/pair")
                {
                    WriteResp(ns, 200, "OK", "text/html; charset=utf-8", Encoding.UTF8.GetBytes(DesktopFeatures.PairPage(cfg.Port)));
                }
                else if (method == "GET" && path.StartsWith("/favicon"))
                {
                    WriteResp(ns, 404, "Not Found", "text/plain", "no icon");
                }
                else if (method == "GET" && path.StartsWith("/screen"))
                {
                    int w = 1920, q = 90;
                    int qi = path.IndexOf("w=");
                    if (qi >= 0) { int t; if (int.TryParse(path.Substring(qi + 2).Split('&')[0], out t)) w = t; }
                    qi = path.IndexOf("q=");
                    if (qi >= 0) { int t; if (int.TryParse(path.Substring(qi + 2).Split('&')[0], out t)) q = t; }
                    if (w < 120) w = 120; if (w > 1920) w = 1920;
                    if (q < 10) q = 10; if (q > 90) q = 90;
                    byte[] jpg = ScreenCapture.Jpeg(w, q);
                    if (jpg == null) WriteResp(ns, 500, "Err", "text/plain", "capture fail");
                    else WriteResp(ns, 200, "OK", "image/jpeg", jpg);
                }
                else if (method == "GET" && path.StartsWith("/files"))
                {
                    string rel = QueryVal(path, "d");
                    string listing;
                    try { listing = FileListJson(rel); }
                    catch (Exception ex) { listing = "{\"ok\":false,\"error\":\"" + JsonEsc(ex.Message) + "\"}"; }
                    WriteResp(ns, 200, "OK", "application/json", Encoding.UTF8.GetBytes(listing));
                }
                else if (path.StartsWith("/sync/"))
                {
                    try {
                        string root;
                        if (!TryResolveFile(QueryVal(path,"root"),out root)) throw new ArgumentException("Seçili PC yolu izinli değil");
                        bool folder = QueryVal(path,"folder") == "1";
                        if (method == "GET" && path.StartsWith("/sync/manifest?")) {
                            WriteResp(ns,200,"OK","application/json",SyncFiles.Manifest(root,folder));
                        } else if (path.StartsWith("/sync/file?")) {
                            string relative = QueryVal(path,"path");
                            string expected = QueryVal(path,"expected");
                            if (method == "GET") {
                                using (FileStream file=SyncFiles.OpenRead(SyncFiles.Resolve(root,folder,relative),expected)) {
                                    WriteRespHead(ns,200,"OK","application/octet-stream",file.Length);
                                    file.CopyTo(ns);ns.Flush();
                                }
                            } else if (method == "POST") {
                                string response=SyncFiles.Write(root,folder,relative,ns,contentLength,expected,QueryVal(path,"hash"));
                                WriteResp(ns,200,"OK","application/json",response);
                            } else throw new ArgumentException("Geçersiz istek");
                        } else throw new ArgumentException("Geçersiz senkronizasyon adresi");
                    } catch(SyncConflictException error) {
                        WriteResp(ns,409,"Conflict","application/json", "{\"ok\":false,\"error\":\""+JsonEsc(error.Message)+"\"}");
                        return;
                    } catch(Exception error) {
                        WriteResp(ns,400,"Bad Request","application/json", "{\"ok\":false,\"error\":\""+JsonEsc(error.Message)+"\"}");
                        return;
                    }
                }
                else if (method == "GET" && path.StartsWith("/download"))
                {
                    string rel = QueryVal(path, "d");
                    string full;
                    if (!TryResolveFile(rel, out full))
                        WriteResp(ns, 403, "Forbidden", "application/json", "{\"ok\":false,\"error\":\"yol izinli degil\"}");
                    else if (!File.Exists(full))
                        WriteResp(ns, 404, "Not Found", "application/json", "{\"ok\":false,\"error\":\"dosya yok\"}");
                    else
                    {
                        FileInfo fi = new FileInfo(full);
                        WriteRespHead(ns, 200, "OK", "application/octet-stream", fi.Length);
                        using (FileStream fs = fi.OpenRead())
                        {
                            byte[] b = new byte[65536];
                            int n;
                            while ((n = fs.Read(b, 0, b.Length)) > 0) ns.Write(b, 0, n);
                        }
                        ns.Flush();
                        if (log != null) log("dosya gönderildi: " + fi.Name + " (" + fi.Length + " bayt)");
                    }
                }
                else if (method != "POST" || !(path.StartsWith("/api") || path.StartsWith("/upload")))
                {
                    WriteResp(ns, 404, "Not Found", "application/json", "{\"ok\":false,\"error\":\"not found\"}");
                    return; // govde tüketilmedi — keep-alive bayt kaymasına izin verme
                }
                else if (path.StartsWith("/upload"))
                {
                    string name = "dosya";
                    int ni = path.IndexOf("name=");
                    if (ni >= 0)
                    {
                        string nn = path.Substring(ni + 5).Split('&')[0];
                        try { nn = Uri.UnescapeDataString(nn); } catch { }
                        if (nn.Trim().Length > 0) name = nn.Trim();
                    }
                    foreach (char bad in Path.GetInvalidFileNameChars()) name = name.Replace(bad, '_');
                    if (name.Length > 120) name = name.Substring(name.Length - 120);
                    string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                    string dest = "";
                    try
                    {
                        Directory.CreateDirectory(dir);
                        dest = Path.Combine(dir, DateTime.Now.ToString("yyyyMMdd_HHmmss_") + name);
                        long remain = contentLength;
                        using (FileStream fs = new FileStream(dest, FileMode.Create, FileAccess.Write))
                        {
                            byte[] buf = new byte[64 * 1024];
                            while (remain > 0)
                            {
                                int n = ns.Read(buf, 0, (int)Math.Min(buf.Length, remain));
                                if (n <= 0) break;
                                fs.Write(buf, 0, n);
                                remain -= n;
                            }
                        }
                        if (log != null) log("DOSYA alındı: " + name + " (" + contentLength + " bayt)");
                    }
                    catch (Exception ex)
                    {
                        WriteResp(ns, 500, "Err", "application/json", "{\"ok\":false,\"error\":\"" + JsonEsc(ex.Message) + "\"}");
                        return;
                    }
                    WriteResp(ns, 200, "OK", "application/json", "{\"ok\":true,\"saved\":\"" + JsonEsc(dest) + "\"}");
                }
                else
                {
                    byte[] body = contentLength > 0 ? ReadExact(ns, contentLength) : new byte[0];
                    string bodyStr = Encoding.UTF8.GetString(body);

                    string resp;
                    try { resp = HandleApi(bodyStr); }
                    catch (Exception ex)
                    {
                        resp = "{\"ok\":false,\"error\":\"" + JsonEsc(ex.Message) + "\"}";
                    }
                    WriteResp(ns, 200, "OK", "application/json", resp);
                    if (log != null) log("istek: " + clientIp);
                }

                if (clientWantsClose) return;
            }
        }

        private static string HandleApi(string body)
        {
            Dictionary<string, object> req;
            try { req = json.Deserialize<Dictionary<string, object>>(body); }
            catch { return "{\"ok\":false,\"error\":\"json hatali\"}"; }
            if (req == null || !req.ContainsKey("action"))
                return "{\"ok\":false,\"error\":\"action yok\"}";
            string action = (string)req["action"];
            bool dry = false;
            object dObj;
            if (req.TryGetValue("dry", out dObj)) dry = Convert.ToBoolean(dObj);

            string r = null;
            // Girdi komutlarında ekran koruyucuyu/monitörü uyandır (sentetik girdi koruyucuyu kapatamaz)
            if (action == "mouse_move" || action == "mouse_click" || action == "mouse_down" ||
                action == "mouse_up" || action == "mouse_abs_click" || action == "scroll" ||
                action == "key_text" || action == "key_combo")
                Input.WakeScreen();
            switch (action)
            {
                case "ping":
                    if (!dry) Input.WakeScreen();
                    r = Base(true, "name", Environment.MachineName);
                    break;
                case "wake_screen":
                    if (!dry) Input.WakeScreen();
                    r = "{\"ok\":true}";
                    break;
                case "system_stats":
                    r = DesktopFeatures.Stats(); break;
                case "process_list":
                    r = DesktopFeatures.ProcessList();
                    break;
                case "process_kill":
                    int killPid = (int)GetNum(req, "pid", -1);
                    r = DesktopFeatures.ProcessKill(killPid);
                    break;
                case "monitors":
                    r = DesktopFeatures.Monitors(); break;
                case "monitor_select":
                    int monitor = (int)GetNum(req, "monitor", -1);
                    if (monitor < -1 || monitor >= Screen.AllScreens.Length) throw new ArgumentException("Ekran bulunamadı");
                    if (!dry) DesktopFeatures.Monitor = monitor;
                    r = "{\"ok\":true}"; break;
                case "game_state":
                    r = GameInput.Update(GetStr(req,"session",""), GetStr(req,"keys",""), GetNum(req,"dx",0), GetNum(req,"dy",0), GetNum(req,"fire",0)!=0, dry); break;
                case "volume_get":
                    r = "{\"ok\":true,\"volume\":" + Audio.GetLevel() + ",\"muted\":" + (Audio.GetMute() ? "true" : "false") + "}";
                    break;
                case "volume_up":
                    Audio.Step(2);
                    r = VolResp();
                    break;
                case "volume_down":
                    Audio.Step(-2);
                    r = VolResp();
                    break;
                case "volume_set":
                    Audio.SetLevel((int)GetNum(req, "level", 50));
                    r = VolResp();
                    break;
                case "volume_mute":
                    bool m = true;
                    object mo;
                    if (req.TryGetValue("mute", out mo)) m = Convert.ToBoolean(mo);
                    else m = !Audio.GetMute();
                    Audio.SetMute(m);
                    r = VolResp();
                    break;
                case "mouse_move":
                    Input.Move((int)GetNum(req, "dx", 0), (int)GetNum(req, "dy", 0));
                    r = "{\"ok\":true}";
                    break;
                case "mouse_click":
                    Input.Click((int)GetNum(req, "button", 0), (int)GetNum(req, "count", 1));
                    r = "{\"ok\":true}";
                    break;
                case "mouse_down":
                case "mouse_up":
                    Input.Button((int)GetNum(req, "button", 0), action == "mouse_down");
                    r = "{\"ok\":true}";
                    break;
                case "scroll":
                    Input.Scroll((float)GetNum(req, "dy", 0), (float)GetNum(req, "dx", 0));
                    r = "{\"ok\":true}";
                    break;
                case "key_text":
                    int typed = Input.KeyText(GetStr(req, "text", ""));
                    r = "{\"ok\":" + (typed > 0 ? "true" : "false") + ",\"typed\":" + (typed / 2) + "}";
                    break;
                case "key_combo":
                {
                    object ko;
                    req.TryGetValue("keys", out ko);
                    List<string> names = new List<string>();
                    System.Collections.IEnumerable en = ko as System.Collections.IEnumerable;
                    if (en != null)
                        foreach (object o in en) names.Add(o == null ? "" : o.ToString());
                    else names.Add(GetStr(req, "key", ""));
                    int kc = Input.KeyCombo(names.ToArray());
                    r = "{\"ok\":" + (kc > 0 ? "true" : "false") + ",\"keys\":" + kc + "}";
                    break;
                }
                case "mouse_abs_click":
                {
                    if (dry) { r = "{\"ok\":true,\"dry\":true}"; break; }
                    Input.AbsClick(GetNum(req, "x", 0.5), GetNum(req, "y", 0.5),
                        (int)GetNum(req, "button", 0), (int)GetNum(req, "count", 1));
                    r = "{\"ok\":true}";
                    break;
                }
                case "mouse_zoom":
                    Input.CtrlWheel((float)GetNum(req, "dy", 0));
                    r = "{\"ok\":true}";
                    break;
                case "run_app":
                {
                    if (dry) { r = "{\"ok\":true,\"dry\":true}"; break; }
                    Power.RunApp(GetStr(req, "name", ""), GetStr(req, "path", ""));
                    r = "{\"ok\":true}";
                    break;
                }
                case "power_timer":
                {
                    double secs = GetNum(req, "seconds", 0);
                    string tmode = GetStr(req, "mode", "shutdown");
                    if (secs < 10) secs = 10;
                    if (secs > 21600) secs = 21600;
                    if (!dry) Power.StartTimer((int)secs, tmode);
                    r = "{\"ok\":true,\"seconds\":" + (int)secs + "}";
                    break;
                }
                case "power_timer_cancel":
                    if (!dry) Power.CancelTimer();
                    r = "{\"ok\":true}";
                    break;
                case "info_mac":
                    r = "{\"ok\":true,\"mac\":\"" + JsonEsc(GetMac()) + "\"}";
                    break;
                case "clip_set":
                {
                    string t = GetStr(req, "text", "");
                    if (ClipSet != null) { ClipSet(t); r = "{\"ok\":true}"; }
                    else r = "{\"ok\":false}";
                    break;
                }
                case "clip_get":
                {
                    string t = ClipGet != null ? ClipGet() : "";
                    r = "{\"ok\":true,\"text\":\"" + JsonEsc(t) + "\"}";
                    break;
                }
                case "open_url":
                {
                    string u = GetStr(req, "url", "").Replace("\"", "").Trim();
                    if (dry) { r = "{\"ok\":true,\"dry\":true}"; break; }
                    if (u.StartsWith("http://") || u.StartsWith("https://"))
                    {
                        // ShellExecute: URL dogrudan varsayilan tarayiciya gider, kabuk devrede degil
                        Power.ShellStart(u);
                        r = "{\"ok\":true}";
                    }
                    else r = "{\"ok\":false,\"error\":\"gecerli url degil\"}";
                    break;
                }
                case "notify":
                {
                    string nt = GetStr(req, "title", "Telefon");
                    string nm = GetStr(req, "msg", "");
                    if (BalloonShow != null) BalloonShow(nt.Length > 60 ? nt.Substring(0, 60) : nt, nm.Length > 200 ? nm.Substring(0, 200) : nm);
                    r = "{\"ok\":true}";
                    break;
                }
                case "media_play":
                    Audio.MediaKey(0xB3); r = "{\"ok\":true}"; break;
                case "media_next":
                    Audio.MediaKey(0xB0); r = "{\"ok\":true}"; break;
                case "media_prev":
                    Audio.MediaKey(0xB1); r = "{\"ok\":true}"; break;
                case "power_shutdown":
                    if (dry) r = "{\"ok\":true,\"dry\":true}";
                    else { Power.Shutdown(); r = "{\"ok\":true,\"message\":\"5 sn icinde kapatilacak\"}"; }
                    break;
                case "power_restart":
                    if (dry) r = "{\"ok\":true,\"dry\":true}";
                    else { Power.Restart(); r = "{\"ok\":true,\"message\":\"5 sn icinde yeniden baslayacak\"}"; }
                    break;
                case "power_abort":
                    Power.Abort(); r = "{\"ok\":true,\"message\":\"iptal edildi\"}";
                    break;
                case "power_lock":
                    if (!dry) Input.Lock();
                    r = "{\"ok\":true}"; break;
                case "power_sleep":
                    if (!dry) Input.Sleep();
                    r = "{\"ok\":true}"; break;
                case "power_monitor_off":
                    if (!dry) Input.MonitorOff();
                    r = "{\"ok\":true}"; break;
                default:
                    r = "{\"ok\":false,\"error\":\"bilinmeyen action: " + JsonEsc(action) + "\"}";
                    break;
            }
            if (log != null) log(action + (dry ? " (deneme)" : ""));
            return r;
        }

        private static double GetNum(Dictionary<string, object> d, string key, double def)
        {
            object o;
            if (!d.TryGetValue(key, out o) || o == null) return def;
            try { return Convert.ToDouble(o); }
            catch { return def; }
        }

        private static string GetStr(Dictionary<string, object> d, string key, string def)
        {
            object o;
            if (!d.TryGetValue(key, out o) || o == null) return def;
            return o.ToString();
        }

        private static string Base(bool ok, string k, string v)
        {
            return "{\"ok\":" + (ok ? "true" : "false") + ",\"" + k + "\":\"" + JsonEsc(v) + "\"}";
        }

        private static string VolResp()
        {
            return "{\"ok\":true,\"volume\":" + Audio.GetLevel() + ",\"muted\":" + (Audio.GetMute() ? "true" : "false") + "}";
        }

        private static void WriteRespHead(Stream ns, int code, string status, string ctype, long len)
        {
            StringBuilder head = new StringBuilder();
            head.Append("HTTP/1.1 ").Append(code).Append(' ').Append(status).Append("\r\n");
            head.Append("Content-Type: ").Append(ctype).Append("\r\n");
            head.Append("Content-Length: ").Append(len).Append("\r\n");
            head.Append("Connection: keep-alive\r\n\r\n");
            byte[] hb = Encoding.UTF8.GetBytes(head.ToString());
            ns.Write(hb, 0, hb.Length);
            ns.Flush();
        }

        private static void WriteResp(Stream ns, int code, string status, string ctype, string text)
        {
            WriteResp(ns, code, status, ctype, Encoding.UTF8.GetBytes(text));
        }

        private static void WriteResp(Stream ns, int code, string status, string ctype, byte[] data)
        {
            StringBuilder head = new StringBuilder();
            head.Append("HTTP/1.1 ").Append(code).Append(' ').Append(status).Append("\r\n");
            head.Append("Content-Type: ").Append(ctype).Append("\r\n");
            head.Append("Content-Length: ").Append(data.Length).Append("\r\n");
            head.Append("Connection: keep-alive\r\n\r\n");
            byte[] hb = Encoding.UTF8.GetBytes(head.ToString());
            ns.Write(hb, 0, hb.Length);
            ns.Write(data, 0, data.Length);
            ns.Flush();
        }
    }

    // ------------------------- Tarayıcı için web arayüzü -------------------------

    internal static class WebUi
    {
        public const string Html =
@"<!DOCTYPE html>
<html lang='tr'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1, user-scalable=no'>
<title>PC Kumanda</title>
<style>
 *{box-sizing:border-box;-webkit-tap-highlight-color:transparent;user-select:none}
 body{font-family:sans-serif;background:#10151d;color:#e8ecf1;margin:0;padding:12px}
 h3{margin:8px 0}
 #login{max-width:360px;margin:40px auto;background:#1a2230;padding:18px;border-radius:12px}
 input{width:100%;padding:10px;margin:6px 0;font-size:16px;border-radius:8px;border:1px solid #334;border-radius:8px;background:#0d1118;color:#fff}
 button{padding:10px 14px;font-size:15px;border:0;border-radius:8px;background:#2a3550;color:#fff}
 .pri{background:#1d7a46!important}
 .row{display:flex;gap:8px;margin:8px 0}
 .row button{flex:1;padding:14px 6px}
 .big{background:#8a2b2b!important}
 #pad{touch-action:none;background:#1a2230;border:1px solid #334;border-radius:12px;height:46vh;margin:8px 0;text-align:center;color:#5a6a80;display:flex;align-items:center;justify-content:center}
 #vol{display:flex;gap:8px;align-items:center}
 #vol button{flex:0 0 56px;padding:14px 0}
 #vslider{flex:1}
 .stat{font-size:12px;color:#8fa0b5;min-height:16px;margin:4px 0}
</style>
</head>
<body>
<div id='login'>
 <h3>&#128187; PC Kumanda</h3>
 <input id='pin' type='password' inputmode='numeric' maxlength='6' placeholder='Eşleme PIN kodu (PC ekranında yazar)'>
 <div class='stat' id='lstat'></div>
 <button class='pri' style='width:100%' onclick='doLogin()'>Bağlan</button>
</div>
<div id='app' style='display:none'>
 <div class='stat' id='stat'></div>
 <div id='pad'>Dokunmatik alan<br>(tek parmak: fare &middot; iki parmak: kaydırma<br>iki parmak dokun: sağ tık)</div>
 <div id='vol'>
  <button onclick='vol(-2)'>&#8722;</button>
  <input id='vslider' type='range' min='0' max='100' value='0' oninput='volSet(this.value)'>
  <button onclick='vol(2)'>&#43;</button>
  <button id='mbtn' onclick='muteToggle()'>&#128263;</button>
 </div>
 <div class='row'>
  <button onclick='med(0)'>&#9198;</button>
  <button onclick='med(1)'>&#9199;</button>
  <button onclick='med(2)'>&#9197;</button>
 </div>
 <h3>Güç</h3>
 <div class='row'>
  <button onclick='act(""power_lock"")'>Kilitle</button>
  <button onclick='act(""power_sleep"")'>Uyku</button>
 </div>
 <div class='row'>
  <button onclick='power(0)' class='big'>Yeniden Başlat</button>
  <button onclick='power(1)' class='big'>Kapat</button>
 </div>
</div>
<script>
var busy=false;
function pin(){return document.getElementById('pin').value;}
function api(obj,cb){
 fetch('/api',{method:'POST',headers:{'Content-Type':'application/json','X-Pin':pin()},body:JSON.stringify(obj)})
 .then(function(r){return r.json()})
 .then(function(j){if(cb)cb(j);stat(j.ok?'':'Hata: '+(j.error||''));})
 .catch(function(e){stat('Bağlantı yok');});
}
function stat(s){document.getElementById('stat').textContent=s;}
function doLogin(){
 api({action:'ping'},function(j){
  if(j&&j.ok){
   document.getElementById('login').style.display='none';
   document.getElementById('app').style.display='block';
   api({action:'volume_get'},function(v){if(v&&v.ok)document.getElementById('vslider').value=v.volume;});
  }else document.getElementById('lstat').textContent='PIN hatalı veya bağlanılamadı';
 });
}
function vol(d){api({action:d>0?'volume_up':'volume_down'},function(j){if(j&&j.ok&&j.volume>=0)document.getElementById('vslider').value=j.volume;});}
function volSet(v){if(busy)return;busy=true;setTimeout(function(){busy=false;},120);api({action:'volume_set',level:+v});}
function muteToggle(){api({action:'volume_mute'},function(j){});}
function med(i){api({action:['media_prev','media_play','media_next'][i]});}
function act(a){api({action:a});}
function power(i){
 var msg=i?'Bilgisayar 5 saniye içinde KAPANACAK. Emin misiniz?':'Bilgisayar 5 saniye içinde YENİDEN BAŞLAYACAK. Emin misiniz?';
 if(!confirm(msg))return;
 api({action:i?'power_shutdown':'power_restart'},function(j){
  if(j&&j.ok&&confirm('İptal etmek ister misiniz? (5 sn içinde geçerli)'))api({action:'power_abort'});
 });
}
(function(){
 var pad=document.getElementById('pad'),lx=0,ly=0,px=[],py=[],moved=0,dt=0,taps=0,lastTap=0,timer=null;
 function send(o){api(o);}
 pad.addEventListener('touchstart',function(e){
  e.preventDefault();
  if(e.touches.length==1){lx=e.touches[0].clientX;ly=e.touches[0].clientY;moved=0;dt=Date.now();
   if(Date.now()-lastTap<300){/* olası çift tık */}
  }else if(e.touches.length==2){lx=(e.touches[0].clientX+e.touches[1].clientX)/2;ly=(e.touches[0].clientY+e.touches[1].clientY)/2;moved=0;dt=Date.now();}
 },{passive:false});
 pad.addEventListener('touchmove',function(e){
  e.preventDefault();
  if(e.touches.length==2){
   var nx=(e.touches[0].clientX+e.touches[1].clientX)/2,ny=(e.touches[0].clientY+e.touches[1].clientY)/2;
   send({action:'scroll',dy:(ny-ly)/70,dx:(nx-lx)/70});lx=nx;ly=ny;moved+=1;
  }else if(e.touches.length==1){
   var dx=e.touches[0].clientX-lx,dy=e.touches[0].clientY-ly;
   lx=e.touches[0].clientX;ly=e.touches[0].clientY;moved+=Math.abs(dx)+Math.abs(dy);
   if(dx||dy)send({action:'mouse_move',dx:Math.round(dx*2),dy:Math.round(dy*2)});
  }
 },{passive:false});
 pad.addEventListener('touchend',function(e){
  e.preventDefault();
  if(e.touches.length>0)return;
  var dur=Date.now()-dt;
  if(dur<250&&moved<14){
   if(timer){clearTimeout(timer);timer=null;send({action:'mouse_click',button:0,count:2});}
   else timer=setTimeout(function(){timer=null;send({action:'mouse_click',button:0,count:1});},230);
   lastTap=Date.now();
  }
 },{passive:false});
})();
</script>
</body>
</html>";
    }
}
