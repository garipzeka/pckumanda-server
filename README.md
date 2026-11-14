# PC Kumanda Sunucu (Windows)

Telefondan bilgisayarı yönetmenizi sağlayan **PC Kumanda** uygulamasının Windows tarafındaki sunucusu.
Aynı Wi-Fi ağındaki Android telefondan: dokunmatik fare, ekran yansıtma + tıklama, klavye, ses/medya,
güç yönetimi, dosya gönderme/çekme, pano paylaşımı ve Wake-on-LAN.

> 📱 Android uygulaması: **Google Play** (yayına hazırlanıyor)

## İndir

| Dosya | Açıklama |
|---|---|
| [`PCKumandaServer.exe`](https://github.com/garipzeka/pckumanda-server/releases/latest) | Kurulum gerektirmez, tek dosya — indirip çift tıklayın |

**Gereksinimler:** Windows 10 / 11 (gömülü .NET Framework ile çalışır, ek kurulum gerekmez).

## Kurulum (30 saniye)

1. `PCKumandaServer.exe`'yi indirin, istediğiniz klasöre koyup çift tıklayın.
2. Windows güvenlik duvarı sorarsa **"İzin ver"** seçin ("Özel ağlar" işaretli kalsın).
3. Pencerede bilgisayarın **IP adresi** ve **6 haneli Eşleme PIN'i** görünür.
4. Telefonda **PC Kumanda → "QR ile bağlan"** ile PC ekranındaki QR'ı okutun (IP + PIN otomatik gelir)
   ya da IP + PIN'i elle girip **Bağlan** deyin. İlk bağlantıda PC'den onaylayın.

## Güvenlik

- Tüm istekler (HTTP, UDP ve ekran/mikrofon/kamera akışları) **Eşleme PIN'i** doğrulamasından geçer.
- PIN'siz veya yanlış PIN'li istekler cevapsız reddedilir; onay penceresi açılmaz.
- Yanlış PIN denemeleri IP başına sınırlıdır (8 deneme sonrası 5 dakika kilit).
- Web sitesi saldırılarına (CSRF/DNS-rebinding) karşı Host başlığı doğrulanır.
- Cihaz onayı: bilinmeyen bir telefon PIN'i doğru girse bile PC'de onay penceresiyle onaylanır.
- PIN'i PC penceresindeki **"PIN'i Yenile"** düğmesiyle her an değiştirebilirsiniz.

> **Not:** İmzasız bir EXE'yi ilk kez çalıştırırken Windows SmartScreen uyarısı çıkabilir;
> **"Daha fazla bilgi → Yine de çalıştır"** ile çalıştırabilirsiniz.

## Kaynaktan derleme

Ek bağımlılık yok — Windows ile gelen C# derleyicisi yeterli:

```cmd
build.cmd
```

- Kaynak: `Server.cs` (HTTP+UDP sunucu, girdi, güç, mikrofon), `CameraServer.cs` (telefon kamerası → PC webcam),
  `DesktopFeatures.cs` (sistem bilgisi, ekranlar, işlem yönetimi, QR sayfası), `SyncFiles.cs` (dosya senkronizasyonu)
- Çıktı: `dist\PCKumandaServer.exe`
- QR sayfası için gömülü kaynak: `vendor\qrcode.min.js` ([MIT lisanslı qrcodejs](vendor/qrcode-LICENSE.txt))

## Sorun giderme

| Sorun | Çözüm |
|---|---|
| Telefon bağlanmıyor | PC ve telefon aynı Wi-Fi'da mı? PIN doğru mu? Güvenlik duvarı kuralı eklendi mi? |
| Ekran yansıtmıyor | "Telefon Ekranı" penceresi açık olmalı; telefonda "Yansıtmayı Başlat" onaylayın |
| Mikrofon sesi Zoom'a gitmiyor | Ücretsiz **VB-CABLE** kurun; çıktı olarak "CABLE Input" seçin |
| Kapalı PC açılmıyor | BIOS'ta Wake-on-LAN açık olmalı |
