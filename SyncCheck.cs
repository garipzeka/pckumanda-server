using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Security.Cryptography;
class SyncCheck {
 static Type sync;static object Call(string method,params object[] args){return sync.GetMethod(method).Invoke(null,args);}
 static void Check(bool good,string why){if(!good)throw new Exception(why);}
 static string Hash(string value){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(value))).Replace("-","").ToLowerInvariant();}
 static void Write(string root,bool folder,string rel,string value,string expected){byte[] data=Encoding.UTF8.GetBytes(value);using(var stream=new MemoryStream(data))Call("Write",root,folder,rel,stream,data.Length,expected,Hash(value));}
 static void Reject(Action action,string why){bool rejected=false;try{action();}catch(TargetInvocationException){rejected=true;}Check(rejected,why);}
 static void Main(){sync=Assembly.LoadFrom(@"C:\pc remote\server\dist\PCKumandaServer.exe").GetType("PCKumanda.SyncFiles");string root=Path.Combine(@"C:\pc remote\server","sync-test-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
  try {
   Write(root,true,"rapor.txt","ilk","missing");Check(File.ReadAllText(Path.Combine(root,"rapor.txt"))=="ilk","Initial write failed");
   Write(root,true,"rapor.txt","ikinci",Hash("ilk"));Check(File.ReadAllText(Path.Combine(root,"rapor.txt"))=="ikinci","Replacement failed");
   Check(Directory.GetFiles(root,".pck-backup-*").Length==1,"Previous version not preserved");
   Reject(()=>Write(root,true,"rapor.txt","stale",Hash("ilk")),"Stale write accepted");Check(File.ReadAllText(Path.Combine(root,"rapor.txt"))=="ikinci","Conflict overwrote file");
   byte[] bytes=Encoding.UTF8.GetBytes("broken");Reject(()=>{using(var input=new MemoryStream(bytes))Call("Write",root,true,"rapor.txt",input,bytes.Length+50,Hash("ikinci"),Hash("broken"));},"Partial transfer accepted");
   Reject(()=>{using(var input=new MemoryStream(bytes))Call("Write",root,true,"rapor.txt",input,bytes.Length,Hash("ikinci"),new string('0',64));},"Bad digest accepted");Check(File.ReadAllText(Path.Combine(root,"rapor.txt"))=="ikinci","Failed transfer changed original");
   foreach(string path in new[]{"../escape.txt","/absolute.txt","a/../../escape","CON.txt","name.","dir/.pck-stage-user"})Reject(()=>Call("Resolve",root,true,path),"Invalid path accepted: "+path);
   Write(root,true,"Türkçe/yeni.txt","yeni dosya","missing");Check(File.Exists(Path.Combine(root,"Türkçe","yeni.txt")),"Nested Unicode transfer failed");
   string file=Path.Combine(root,"rapor.txt");Check((string)Call("Resolve",file,false,"RAPOR.TXT")!=null,"Case-insensitive file path failed");Reject(()=>Call("Resolve",file,false,"other.txt"),"Single-file scope escaped");
   Write(file,false,"rapor.pck-conflict-test.txt","telefon sürümü","missing");Check(File.Exists(Path.Combine(root,"rapor.pck-conflict-test.txt")),"Conflict copy missing");
   string manifest=(string)Call("Manifest",root,true);Check(!manifest.Contains(".pck-backup-")&&!manifest.Contains(".pck-stage-"),"Internal files leaked into manifest");
   using(var read=(FileStream)Call("OpenRead",file,Hash("ikinci")))Check(read.Length>0,"Snapshot read failed");Reject(()=>Call("OpenRead",file,Hash("ilk")),"Stale download accepted");
   Check(Directory.GetFiles(root,".pck-stage-*").Length==0,"Temporary files not cleaned");
   Console.WriteLine("PASS: new/update file, previous-version backup, stale-write protection, partial/hash-failed transfers, path validation, single-file scope, Unicode subfolders, conflict copies and verified downloads.");
  }finally{string resolved=Path.GetFullPath(root);if(resolved.StartsWith(@"C:\pc remote\server\sync-test-",StringComparison.OrdinalIgnoreCase))Directory.Delete(resolved,true);}
 }
}
