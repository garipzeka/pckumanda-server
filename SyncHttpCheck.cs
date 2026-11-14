using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Collections.Generic;
using System.Threading;
using System.Security.Cryptography;
class SyncHttpCheck {
 static int Deny(string id,string name){return 0;}
 static void Check(bool ok,string message){if(!ok)throw new Exception(message);}
 static string Hash(string value){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(value))).Replace("-","").ToLowerInvariant();}
 static string Request(int port,string method,string path,string data,string device,out int code){var request=(HttpWebRequest)WebRequest.Create("http://127.0.0.1:"+port+path);request.Method=method;request.KeepAlive=false;request.Timeout=5000;request.Headers["X-Device"]=device;if(data!=null){byte[] bytes=Encoding.UTF8.GetBytes(data);request.ContentLength=bytes.Length;using(var stream=request.GetRequestStream())stream.Write(bytes,0,bytes.Length);}HttpWebResponse response;try{response=(HttpWebResponse)request.GetResponse();}catch(WebException e){response=(HttpWebResponse)e.Response;if(response==null)throw;}using(response){code=(int)response.StatusCode;using(var reader=new StreamReader(response.GetResponseStream(),Encoding.UTF8))return reader.ReadToEnd();}}
 static void Main(){var assembly=Assembly.LoadFrom(@"C:\pc remote\server\dist\PCKumandaServer.exe");var type=assembly.GetType("PCKumanda.NetServer");var flags=BindingFlags.NonPublic|BindingFlags.Static;var auth=type.GetField("authorize",flags);auth.SetValue(null,Delegate.CreateDelegate(auth.FieldType,typeof(SyncHttpCheck).GetMethod("Deny",BindingFlags.NonPublic|BindingFlags.Static)));((HashSet<string>)type.GetField("allowedDevices",flags).GetValue(null)).Add("sync-qa-only");var handle=type.GetMethod("HandleClient",flags);
  string name="PCKumanda-sync-qa-"+Guid.NewGuid().ToString("N"),fixture=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),"Downloads",name);Directory.CreateDirectory(fixture);var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;bool active=true;
  var loop=new Thread(()=>{while(active){TcpClient client;try{client=listener.AcceptTcpClient();}catch{break;}ThreadPool.QueueUserWorkItem(delegate{try{handle.Invoke(null,new object[]{client});}catch{}finally{client.Close();}});}});loop.IsBackground=true;loop.Start();
  try{string root=Uri.EscapeDataString("Downloads/"+name),file="/sync/file?root="+root+"&folder=1&path="+Uri.EscapeDataString("Türkçe/rapor.txt");int code;
   Request(port,"POST",file+"&expected=missing&hash="+Hash("telefon"),"telefon","sync-qa-only",out code);Check(code==200,"HTTP upload failed");
   string manifest=Request(port,"GET","/sync/manifest?root="+root+"&folder=1",null,"sync-qa-only",out code);Check(code==200&&manifest.Contains(Hash("telefon")),"Manifest missing uploaded file");
   File.WriteAllText(Path.Combine(fixture,"Türkçe","rapor.txt"),"PC değişikliği",new UTF8Encoding(false));
   string read=Request(port,"GET",file+"&expected="+Hash("PC değişikliği"),null,"sync-qa-only",out code);Check(code==200&&read=="PC değişikliği","HTTP verified download failed");
   Request(port,"POST",file+"&expected="+Hash("telefon")+"&hash="+Hash("stale"),"stale","sync-qa-only",out code);Check(code==409,"Concurrent edit did not return conflict");Check(File.ReadAllText(Path.Combine(fixture,"Türkçe","rapor.txt"))=="PC değişikliği","Concurrent edit overwritten");
   Request(port,"GET","/sync/manifest?root="+root+"&folder=1",null,"unknown-test-device",out code);Check(code==403,"Device authorization bypassed");
   Request(port,"GET","/sync/manifest?root="+Uri.EscapeDataString("Downloads/../Windows")+"&folder=1",null,"sync-qa-only",out code);Check(code==400,"Root traversal accepted");
   Console.WriteLine("PASS: real HTTP upload, Unicode paths, manifest, PC-to-client verified download, 409 conflict, device authorization and root path validation.");
  }finally{active=false;listener.Stop();loop.Join(1000);string resolved=Path.GetFullPath(fixture),prefix=Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),"Downloads"))+Path.DirectorySeparatorChar;Check(resolved.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)&&Path.GetFileName(resolved)==name,"Unsafe fixture cleanup");Directory.Delete(resolved,true);}
 }
}
