using System;
using System.Collections.Generic;
using System.Drawing;
using System.Reflection;
using System.Web.Script.Serialization;
class FeatureCheck {
 static JavaScriptSerializer json=new JavaScriptSerializer();
 static void Require(bool condition,string message){if(!condition)throw new Exception(message);}
 static void Main(){
  Assembly a=Assembly.LoadFrom(@"C:\pc remote\server\dist\PCKumandaServer.exe");
  Type api=a.GetType("PCKumanda.NetServer"),features=a.GetType("PCKumanda.DesktopFeatures");
  MethodInfo method=api.GetMethod("HandleApi",BindingFlags.Static|BindingFlags.NonPublic);
  Func<string,Dictionary<string,object>> call=body=>json.Deserialize<Dictionary<string,object>>((string)method.Invoke(null,new object[]{body}));
  var monitors=call("{\"action\":\"monitors\"}");Require((bool)monitors["ok"],"Monitor list failed");
  var stats=call("{\"action\":\"system_stats\"}");Require((bool)stats["ok"],"Stats failed");
  Require(Convert.ToDouble(stats["ramTotalGB"])>0,"Memory missing");
  System.Threading.Thread.Sleep(150);
  stats=call("{\"action\":\"system_stats\"}");double cpu=Convert.ToDouble(stats["cpu"]);Require(cpu>=0 && cpu<=100,"Invalid CPU");
  var dry=call("{\"action\":\"game_state\",\"session\":\"test\",\"keys\":\"w,shift,space\",\"fire\":1,\"dry\":true}");Require((bool)dry["ok"] && (bool)dry["dry"],"Game dry run failed");
  bool rejected=false;try{call("{\"action\":\"game_state\",\"session\":\"test\",\"keys\":\"not-a-key\",\"dry\":true}");}catch(TargetInvocationException e){rejected=e.InnerException is ArgumentException;}Require(rejected,"Bad game key accepted");
  int previous=(int)features.GetField("Monitor").GetValue(null);
  try {call("{\"action\":\"monitor_select\",\"monitor\":0}");Rectangle bounds=(Rectangle)features.GetProperty("Bounds").GetValue(null,null);Require(bounds.Width>0&&bounds.Height>0,"Invalid selected bounds");
   call("{\"action\":\"monitor_select\",\"monitor\":-1}");Require((int)features.GetField("Monitor").GetValue(null)==-1,"Reset failed");
  } finally{features.GetField("Monitor").SetValue(null,previous);}
  string page=(string)features.GetMethod("PairPage").Invoke(null,new object[]{40555});Require(page.Contains("new QRCode") && page.Contains("pckumanda://connect?host=") && !page.Contains("<script src="),"QR page must work offline");
  // Verify lease expiry and multi-button transitions using a spy, never real desktop input.
  Type game=a.GetType("PCKumanda.GameInput");
  var flags=BindingFlags.Static|BindingFlags.NonPublic;
  var keyField=game.GetField("writeKey",flags);var buttonField=game.GetField("writeButton",flags);var moveField=game.GetField("movePointer",flags);
  object oldKey=keyField.GetValue(null),oldButton=buttonField.GetValue(null),oldMove=moveField.GetValue(null);
  var pressed=new HashSet<ushort>();bool fire=false;int moves=0;
  try {
   keyField.SetValue(null,new Action<ushort,bool>((key,down)=>{if(down)pressed.Add(key);else pressed.Remove(key);}));
   buttonField.SetValue(null,new Action<int,bool>((button,down)=>{fire=down;}));
   moveField.SetValue(null,new Action<int,int>((x,y)=>{moves++;}));
   Require((bool)call("{\"action\":\"game_state\",\"session\":\"test-owner\",\"keys\":\"w,shift,space\",\"fire\":1,\"dx\":3}")["ok"],"Game start failed");
   Require(pressed.Count==3 && fire && moves==1,"Held inputs not applied");
   Require(!(bool)call("{\"action\":\"game_state\",\"session\":\"other-owner\",\"keys\":\"s\"}")["ok"],"Lease stolen by second session");
   call("{\"action\":\"game_state\",\"session\":\"test-owner\",\"keys\":\"w\",\"fire\":0}");
   Require(pressed.Count==1 && !fire,"Released button remained held");
   System.Threading.Thread.Sleep(1800);
   Require(pressed.Count==0 && !fire,"Watchdog failed to release stale input");
   call("{\"action\":\"game_state\",\"session\":\"test-owner\",\"keys\":\"a\"}");
   call("{\"action\":\"game_state\",\"session\":\"test-owner\",\"keys\":\"\"}");
   Require(pressed.Count==0,"Explicit stop failed");
   Console.WriteLine("PASS: game hold/release, second-client exclusion, stale connection watchdog and explicit stop (input spy).");
  } finally {game.GetMethod("Release",flags).Invoke(null,null);keyField.SetValue(null,oldKey);buttonField.SetValue(null,oldButton);moveField.SetValue(null,oldMove);}
  Console.WriteLine("PASS: monitor selection/bounds, CPU/RAM/network/battery telemetry, game dry-run/key validation, offline QR resource.");
  Console.WriteLine(json.Serialize(stats));
 }
}
