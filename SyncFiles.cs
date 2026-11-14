using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace PCKumanda {
    internal static class SyncFiles {
        public const long MaxFile = 200L * 1024 * 1024;
        private static readonly object gate = new object();
        public static string Hash(Stream stream) {
            using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }
        public static string HashFile(string path) {
            if (!File.Exists(path)) return "missing";
            using (FileStream file = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite | FileShare.Delete)) return Hash(file);
        }
        private static void SafeName(string name) {
            if (string.IsNullOrEmpty(name) || name == "." || name == ".." || name.StartsWith(".pck-",StringComparison.OrdinalIgnoreCase)
                || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name.EndsWith(".") || name.EndsWith(" ")
                || Regex.IsMatch(name,@"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)",RegexOptions.IgnoreCase))
                throw new ArgumentException("Geçersiz senkronizasyon dosya adı");
        }
        public static string Resolve(string root,bool folder,string relative) {
            root=Path.GetFullPath(root);
            string[] parts=(relative??"").Replace('\\','/').Split('/');
            foreach(string part in parts) SafeName(part);
            string parent=folder?root:Path.GetDirectoryName(root);
            if (!folder) {
                string original=Path.GetFileName(root);
                // Single-file pairs can also keep uniquely named sibling conflict copies.
                if(parts.Length!=1 || (!string.Equals(parts[0],original,StringComparison.OrdinalIgnoreCase) && !parts[0].StartsWith(Path.GetFileNameWithoutExtension(original)+".pck-conflict-",StringComparison.Ordinal)))
                    throw new ArgumentException("Dosya seçimi dışındaki yola erişilemiyor");
            }
            if (!Directory.Exists(parent)) throw new DirectoryNotFoundException("Seçili PC klasörü bulunamadı");
            string current=parent;
            foreach(string part in parts) {
                current=Path.Combine(current,part);
                if ((File.Exists(current)||Directory.Exists(current)) && (File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0)
                    throw new ArgumentException("Bağlantılı dosya veya klasör senkronize edilemez");
            }
            string full=Path.GetFullPath(current);
            if (!full.StartsWith(parent.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("Yol seçili klasörün dışında");
            return full;
        }
        public static string Manifest(string root,bool folder) {
            var entries=new List<object>();
            if (folder) Walk(root,"",entries,0);
            else if (File.Exists(root)) Add(root,Path.GetFileName(root),entries);
            return new JavaScriptSerializer {MaxJsonLength=8*1024*1024}.Serialize(new {ok=true,files=entries});
        }
        private static void Add(string full,string relative,List<object> entries) {
            if(entries.Count>=5000) throw new IOException("Bir seçim en fazla 5000 dosya içerebilir");
            FileInfo info=new FileInfo(full);if(info.Length>MaxFile) throw new IOException("Senkronizasyon dosya sınırı 200 MB: "+relative);
            entries.Add(new {path=relative,hash=HashFile(full),size=info.Length});
        }
        private static void Walk(string root,string relative,List<object> entries,int depth) {
            if(depth>32)throw new IOException("Klasör derinliği sınırı aşıldı");
            string here=relative.Length==0?root:Resolve(root,true,relative);
            if(!Directory.Exists(here))throw new DirectoryNotFoundException("Seçili PC klasörü bulunamadı");
            foreach(string path in Directory.GetFiles(here)) {
                string name=Path.GetFileName(path);if(name.StartsWith(".pck-",StringComparison.OrdinalIgnoreCase))continue;
                if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)continue;
                SafeName(name);Add(path,relative.Length==0?name:relative+"/"+name,entries);
            }
            foreach(string path in Directory.GetDirectories(here)) {
                string name=Path.GetFileName(path);if(name.StartsWith(".pck-",StringComparison.OrdinalIgnoreCase))continue;
                if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)continue;
                SafeName(name);Walk(root,relative.Length==0?name:relative+"/"+name,entries,depth+1);
            }
        }
        public static FileStream OpenRead(string full,string expected) {
            string temp=Path.Combine(Path.GetTempPath(),"pck-sync-read-"+Guid.NewGuid().ToString("N"));
            FileStream snapshot=new FileStream(temp,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None,65536,FileOptions.DeleteOnClose);
            try {
                using(FileStream source=new FileStream(full,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)) {
                    if(source.Length>MaxFile)throw new IOException("Dosya 200 MB sınırını aşıyor");
                    byte[] buffer=new byte[65536];long total=0;int count;
                    while((count=source.Read(buffer,0,buffer.Length))>0){total+=count;if(total>MaxFile)throw new IOException("Dosya büyüdü; tekrar denenecek");snapshot.Write(buffer,0,count);}
                }
                snapshot.Position=0;if(Hash(snapshot)!=expected)throw new SyncConflictException();snapshot.Position=0;return snapshot;
            }catch{snapshot.Dispose();throw;}
        }
        public static string Write(string root,bool folder,string relative,Stream input,int length,string expected,string contentHash) {
            if(length<0 || length>MaxFile || !Regex.IsMatch(contentHash??"","^[a-f0-9]{64}$")
                || (expected!="missing"&&!Regex.IsMatch(expected??"","^[a-f0-9]{64}$")))throw new ArgumentException("Geçersiz aktarım bilgisi");
            string destination=Resolve(root,folder,relative);
            string parent=Path.GetDirectoryName(destination);
            Directory.CreateDirectory(parent);
            string temp=Path.Combine(parent,".pck-stage-"+Guid.NewGuid().ToString("N"));
            try {
                using(FileStream output=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
                    byte[] buffer=new byte[65536];int remain=length;
                    while(remain>0){int count=input.Read(buffer,0,Math.Min(remain,buffer.Length));if(count<=0)throw new EndOfStreamException("Aktarım yarım kaldı");output.Write(buffer,0,count);remain-=count;}
                    output.Flush(true);
                }
                if(HashFile(temp)!=contentHash)throw new IOException("Aktarım özeti eşleşmiyor");
                lock(gate) {
                    destination=Resolve(root,folder,relative);
                    if(HashFile(destination)!=expected)throw new SyncConflictException();
                    if(File.Exists(destination)) {
                        string backup=Path.Combine(parent,".pck-backup-"+Guid.NewGuid().ToString("N"));
                        File.Replace(temp,destination,backup,true);
                    } else File.Move(temp,destination);
                }
                return "{\"ok\":true,\"hash\":\""+contentHash+"\"}";
            } finally {if(File.Exists(temp))File.Delete(temp);}
        }
    }
    internal class SyncConflictException:IOException {public SyncConflictException():base("Dosya aktarım sırasında değişti; sonraki turda yeniden denenecek"){} }
}
