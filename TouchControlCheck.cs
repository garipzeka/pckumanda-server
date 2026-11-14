using System;
using System.Drawing;
using System.Reflection;
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;
class TouchControlCheck {
    static void Check(bool ok, string message) { if (!ok) throw new Exception(message); }
    [STAThread] static void Main() {
        Type type = Assembly.LoadFrom(@"C:\pc remote\dist\PCKumandaServer-auto.exe").GetType("PCKumanda.ScreenViewerForm");
        BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        using (Form form = (Form)Activator.CreateInstance(type, true)) {
            PictureBox picture = (PictureBox)type.GetField("pb", flags).GetValue(form);
            picture.Dock = DockStyle.None;
            picture.ClientSize = new Size(300, 600);
            using (Bitmap bitmap = new Bitmap(100, 100)) {
                picture.Image = bitmap;
                MethodInfo map = type.GetMethod("TryPhonePoint", flags);
                object[] center = { new Point(150, 300), Point.Empty };
                Check((bool)map.Invoke(form, center), "Center rejected");
                Check((Point)center[1] == new Point(32767, 32767), "Center mapping incorrect");
                object[] border = { new Point(150, 20), Point.Empty };
                Check(!(bool)map.Invoke(form, border), "Letterbox accepted");
                TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                using (TcpClient sender = new TcpClient()) {
                    sender.Connect((IPEndPoint)listener.LocalEndpoint);
                    using (TcpClient receiver = listener.AcceptTcpClient()) {
                        receiver.ReceiveTimeout = 2000;
                        type.GetField("controlClient", flags).SetValue(form, sender);
                        type.GetMethod("SendTouch", flags).Invoke(form, new object[] { new Point(0, 65535), new Point(32767, 12345), 750 });
                        byte[] data = new byte[11]; int count = 0;
                        while (count < data.Length) { int n = receiver.GetStream().Read(data, count, data.Length - count); Check(n > 0, "Incomplete packet"); count += n; }
                        Check(data[0] == (byte)'T', "Wrong touch opcode");
                        int[] expected = { 0, 65535, 32767, 12345, 750 };
                        for (int i = 0; i < expected.Length; i++) Check((data[1+i*2] << 8 | data[2+i*2]) == expected[i], "Packet field mismatch");
                    }
                }
                listener.Stop();
                picture.Image = null;
            }
        }
        Console.WriteLine("PASS: center mapping, letterbox rejection, touch packet round trip");
    }
}
