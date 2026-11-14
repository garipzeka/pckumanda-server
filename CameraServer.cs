using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace PCKumanda
{
    internal static class CameraServer
    {
        private static byte[] latest;
        private static long receivedAt;
        private static TcpClient current;
        private static readonly object gate = new object();
        private static byte[] placeholder;
        public static Action<string> Status;
        private static void Notify(string text) { if (Status != null) Status(text); }
        public static void Start()
        {
            using (Bitmap bitmap = new Bitmap(1280, 720))
            using (Graphics graphics = Graphics.FromImage(bitmap))
            using (Font font = new Font("Segoe UI", 30))
            using (MemoryStream stream = new MemoryStream())
            {
                graphics.Clear(Color.FromArgb(16, 20, 30));
                graphics.DrawString("PC Kumanda\nTelefonda Webcam'i Baslat'a basin", font, Brushes.White, 70, 280);
                bitmap.Save(stream, ImageFormat.Jpeg);
                placeholder = stream.ToArray();
            }
            TcpListener input = new TcpListener(IPAddress.Any, 40559);
            SocketLifetime.Private(input.Server);
            input.Start();
            new Thread(delegate()
            {
                while (true)
                {
                    TcpClient client;
                    try { client = input.AcceptTcpClient(); SocketLifetime.Private(client.Client); } catch { break; }
                    lock (gate)
                    {
                        if (current != null) try { current.Close(); } catch { }
                        current = client;
                    }
                    TcpClient captured = client;
                    new Thread(delegate() { Receive(captured); }) { IsBackground = true }.Start();
                }
            }) { IsBackground = true }.Start();
            // OBS and previews can read frames only on this PC.
            TcpListener web = new TcpListener(IPAddress.Loopback, 40560);
            SocketLifetime.Private(web.Server);
            web.Start();
            new Thread(delegate()
            {
                while (true)
                {
                    TcpClient client;
                    try { client = web.AcceptTcpClient(); SocketLifetime.Private(client.Client); } catch { break; }
                    TcpClient captured = client;
                    ThreadPool.QueueUserWorkItem(delegate { Serve(captured); });
                }
            }) { IsBackground = true }.Start();
        }
        private static byte[] ReadExact(Stream stream, int count)
        {
            byte[] data = new byte[count];
            for (int offset = 0; offset < count; )
            {
                int n = stream.Read(data, offset, count - offset);
                if (n <= 0) throw new EndOfStreamException();
                offset += n;
            }
            return data;
        }
        private static void Receive(TcpClient client)
        {
            try
            {
                client.NoDelay = true;
                client.ReceiveTimeout = 5000;
                NetworkStream stream = client.GetStream();
                // PIN el sıkışması: ilk satır "pin=xxxxxx" olmalı
                StringBuilder hello = new StringBuilder();
                while (hello.Length < 128)
                {
                    int b = stream.ReadByte();
                    if (b < 0) throw new EndOfStreamException();
                    if (b == '\n') break;
                    if (b != '\r') hello.Append((char)b);
                }
                string pin = "";
                foreach (string part in hello.ToString().Split(' '))
                {
                    string[] kv = part.Split('=');
                    if (kv.Length == 2 && kv[0] == "pin") pin = kv[1];
                }
                if (!Pairing.IsValid(pin))
                {
                    Notify("kamera: PIN reddi — bağlantı kapatıldı");
                    return;
                }
                client.ReceiveTimeout = 15000;
                bool first = true;
                while (true)
                {
                    byte[] header = ReadExact(stream, 4);
                    int size = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
                    if (size < 4 || size > 8 * 1024 * 1024) throw new IOException("Kamera kare boyutu hatalı");
                    byte[] jpeg = ReadExact(stream, size);
                    if (jpeg[0] != 255 || jpeg[1] != 216) throw new IOException("JPEG bekleniyor");
                    lock (gate)
                    {
                        if (!ReferenceEquals(current, client)) break;
                        latest = jpeg;
                        receivedAt = DateTime.UtcNow.Ticks;
                    }
                    if (first) { Notify("Telefon kamerası canlı"); first = false; }
                }
            }
            catch { }
            finally
            {
                lock (gate)
                {
                    if (ReferenceEquals(current, client))
                    {
                        current = null; latest = null;
                        Notify("Telefon kamerası bekleniyor");
                    }
                }
                client.Close();
            }
        }
        private static void Serve(TcpClient client)
        {
            using (client)
            {
                try
                {
                    client.ReceiveTimeout = client.SendTimeout = 3000;
                    NetworkStream stream = client.GetStream();
                    StringBuilder request = new StringBuilder();
                    int previous = 0;
                    while (request.Length < 8192)
                    {
                        int c = stream.ReadByte();
                        if (c < 0) return;
                        request.Append((char)c);
                        if (previous == '\r' && c == '\n' && request.ToString().EndsWith("\r\n\r\n")) break;
                        previous = c;
                    }
                    string line = request.ToString().Split('\n')[0];
                    bool image = line.StartsWith("GET /frame.jpg ") || line.StartsWith("GET /frame.jpg?");
                    byte[] body;
                    if (image)
                    {
                        lock (gate) body = latest != null && DateTime.UtcNow.Ticks - receivedAt < TimeSpan.FromSeconds(3).Ticks ? latest : placeholder;
                    }
                    else
                    {
                        body = Encoding.UTF8.GetBytes("<!doctype html><html><head><meta charset='utf-8'><title>PC Kumanda Webcam</title><style>html,body{margin:0;width:100%;height:100%;background:#10141e;overflow:hidden}img{width:100%;height:100%;object-fit:contain}</style></head><body><img id='camera' alt='Telefon kamerası'><script>const img=document.getElementById('camera');function next(){setTimeout(()=>{img.src='/frame.jpg?t='+Date.now()},80)}img.onload=next;img.onerror=()=>setTimeout(next,500);img.src='/frame.jpg';</script></body></html>");
                    }
                    byte[] head = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: " + (image ? "image/jpeg" : "text/html; charset=utf-8") + "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n");
                    stream.Write(head, 0, head.Length);
                    stream.Write(body, 0, body.Length);
                }
                catch { }
            }
        }
    }
}
