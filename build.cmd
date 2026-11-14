@echo off
rem PC Kumanda Sunucu derleme komutu (.NET Framework ile birlikte gelir)
if not exist dist mkdir dist
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:winexe /optimize+ /win32icon:app.ico /out:dist\PCKumandaServer.exe /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.Management.dll /resource:vendor\qrcode.min.js,qrcode.js Server.cs CameraServer.cs DesktopFeatures.cs SyncFiles.cs
if errorlevel 1 (echo DERLEME BASARISIZ & exit /b 1)
copy /y dist\PCKumandaServer.exe ..\dist\PCKumandaServer.exe >nul 2>nul
powershell -NoProfile -Command "$c = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -like '*PC Kumanda*' } | Select-Object -First 1; if ($c) { Set-AuthenticodeSignature -FilePath 'dist\PCKumandaServer.exe' -Certificate $c >$null; Set-AuthenticodeSignature -FilePath '..\dist\PCKumandaServer.exe' -Certificate $c >$null }" 2>nul
echo OK: dist\PCKumandaServer.exe
