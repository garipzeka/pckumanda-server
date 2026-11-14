using System;
using System.Collections.Generic;
using System.Reflection;
using System.Web.Script.Serialization;
class SharedFoldersCheck {
    static void Main() {
        var assembly = Assembly.LoadFrom(@"C:\pc remote\dist\PCKumandaServer-new.exe");
        var type = assembly.GetType("PCKumanda.NetServer");
        var flags = BindingFlags.NonPublic | BindingFlags.Static;
        var list = type.GetMethod("FileListJson", flags);
        var resolve = type.GetMethod("TryResolveFile", flags);
        var decode = type.GetMethod("QueryVal", flags);
        var json = new JavaScriptSerializer();
        string root = (string)list.Invoke(null, new object[] { "" });
        if (!root.Contains("Paylaşılan klasörler")) throw new Exception("Missing shared root");
        string shares = (string)list.Invoke(null, new object[] { "Paylaşılan klasörler" });
        var result = json.Deserialize<Dictionary<string, object>>(shares);
        if (!(bool)result["ok"]) throw new Exception("Share enumeration failed");
        foreach (string invalid in new [] { "Desktop/../Windows", "Paylaşılan klasörler/../Windows", "C:/Windows", "Desktop/a:b" }) {
            object[] args = { invalid, null };
            if ((bool)resolve.Invoke(null, args)) throw new Exception("Accepted invalid path");
        }
        string decoded = (string)decode.Invoke(null, new object[] { "/files?d=Payla%C5%9F%C4%B1lan+klas%C3%B6rler", "d" });
        if (decoded != "Paylaşılan klasörler") throw new Exception("Space/Unicode decoding failed");
        Console.WriteLine("PASS: root listing, Windows share enumeration, path rejection, Unicode/space decoding");
        Console.WriteLine(shares);
    }
}
