# OmaBlock - Omarchy Linux İçin Sıfır Gecikmeli Reklam Engelleyici ve Gizlilik Kalkanı

[![Omarchy Verified Plugin](https://img.shields.io/badge/Omarchy-Verified_Plugin-22c55e?style=for-the-badge&logo=omarchy)](https://github.com/ozdil)

[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-Support_Development-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ozdil)

![OmaBlock Preview](preview.png)

> **Omarchy Linux için sistem genelinde, sıfır gecikmeli reklam ve takipçi engelleyici.**

OmaBlock; tarayıcı eklentilerine bağımlı kalmadan tüm sistem genelinde reklam, telemetri, kötü amaçlı yazılım ve takipçileri engeller. Yapay zeka destekli DGA / phishing tespiti, isteğe bağlı nftables kuralları ve kullanıcı alanında yüksek güvenlikli Rust motoru (`omablock-engine`) ile çalışır.

---

## 1.5.0 ile Gelen Yenilikler

- Doğru çekirdek kuralları: nftables tabloları doğru yazılıyor ve ayrıcalıklı yardımcı üzerinden uygulanıyor.
- Daha güvenli `/etc/hosts` senkronu: dosyanın izinlerini ve sahibini koruyan atomik yazma, her kuralın önce alan adı olarak doğrulanması.
- Duraklatma süresi dolunca kendiliğinden biter. `omablock --restore-hosts` orijinal `/etc/hosts` dosyasını geri yükler.
- Doğru durum bilgisi: panel gerçek aktif kural sayısını ve her çıkış kodu için anlaşılır bir mesaj gösterir.
- Türkçe ve İngilizce Chrome / Chromium eklentisi: sekme başına rozet, sayfa açılırken reklam görünmez.
- Her değişiklikte uçtan uca, Rust ve QML testleri CI'da çalışır.

Tüm liste: [CHANGELOG.md](CHANGELOG.md)

---

## Yetenekler ve Özellikler

- **Sistem Düzeyinde Sıfır Gecikme:**
  - Engellenen alan adları `/etc/hosts` dosyasına `0.0.0.0` olarak yazılır. Sistem çözümleyicisi (glibc NSS, kullanıcı alanında) bunları yerelde yanıtlar, araya proxy girmez.
- **Yapay Zeka Destekli DGA ve Oltalama Koruması:**
  - Shannon entropisi ve sezgisel algoritmalar ile sahte/üretilmiş alan adlarını tespit eder.
- **Kategori Bazlı Seçici Filtreleme:**
  - Reklamlar, Telemetri, Kötü Amaçlı Yazılımlar, Sosyal Takipçiler ve Açılır Pencereler (Pop-ups) bağımsız yönetilebilir.
- **OmaBlock Shield Bridge (Chrome & Chromium Köprüsü):**
  - hosts tabanlı korumayı tarayıcı içi kurallarla tamamlayan Manifest V3 uzantısı (Türkçe ve İngilizce arayüz). DonanımHaber, Haberler.com gibi sitelerdeki first-party gömülü bannerları ve DOM içi reklam alanlarını sıfır gecikmeyle yok eder.
- **İsteğe Bağlı Çekirdek Koruması ve Blackout (`nftables` gerekir):**
  - Çekirdek koruması, bilinen genel çözümleyicilere (Cloudflare, Google, Quad9) giden DoH (443), DoT (853) ve UDP DNS (53) trafiğini reddeden `inet omablock` tablosunu ekler. Panik Blackout, siz ağı geri açana kadar loopback dışındaki tüm DNS trafiğini (53 ve 853) keser.
- **USB Zırhı (deneysel):**
  - Şimdilik yalnızca arayüzde gösterilen bir bayrağı saklar, USB aygıtlarını engellemez.
- **Klavye Kısayolları ve Ergonomi:**
  - Space/Enter (aç/kapat), r (yenile), t (canlı test çalıştır), u (kuralları güncelle), a (künye overlay).
- **Omarchy Tema Entegrasyonu:**
  - `JetBrainsMono Nerd Font` tipografi standardı ve dinamik sistem renkleri.

---

## Kurulum ve Yapılandırma

### Omarchy Eklentisini Ekleme
```bash
omarchy plugin add https://github.com/ozdil/omarchy-omablock.git
```

### Motoru Kaynaktan Derleme
```bash
cd ~/.config/omarchy/plugins/ozdil.omablock
cargo build --release
install -m 755 target/release/omablock-engine ./omablock-engine
```

### Sistem Yardımcısını Kurma (İsteğe Bağlı)
`/etc/hosts` ve Polkit entegrasyonu için paketi kurun. Değişiklikler Polkit üzerinden bir kez parola ister (`auth_admin_keep`) ve yetki birkaç dakika saklanır:
```bash
makepkg -si
```

### Komut Satırı
```bash
omablock --set-level standard|aggressive|ultimate
omablock --pause 15          # systemd kullanıcı zamanlayıcısı ile kendiliğinden devam eder
omablock --resume
omablock --panic-blackout    # acil ağ kesme (nftables gerekir)
omablock --resume-network
omablock --restore-hosts     # /etc/hosts dosyasını ilk değişiklikten önceki yedeğe döndürür
omablock verify-integrity    # 0 = OK, 1 = MISMATCH, 3 = UNKNOWN
```
Çıkış kodları: `0` başarılı, `1` ayar kaydedildi ama sisteme uygulanamadı, `2` geçersiz alan adı, kategori veya seçenek, `4` ayar kaydedildi ama sistem yardımcısı (`omablock-hosts-sync`) kurulu değil.

### Omarchy Shell Yapılandırması
`~/.config/omarchy/shell.json` dosyasında `bar.layout.right` altına ekleyin:
```json
{
  "id": "ozdil.omablock"
}
```

Kabuğu yeniden başlatın:
```bash
omarchy-restart-shell
```

---

## Güvenlik Standartları

- Tamamen kullanıcı alanında 0600 dosya ve 0700 dizin izinleri ile atomik veri yönetimi.
- Subprocess süreç izolasyonu, 16 ile 32 KiB arası çıktı sınırı ve monotonic deadline koruması.
- Eşzamanlı değişikliklere karşı yapılandırma ve yardımcı süreç kilitleri.
- Sıfır emoji politikası ve kurumsal sıfır güven mimarisi.

---

## Lisans

MIT Lisansı. Ayrıntılar için [LICENSE](LICENSE) dosyasına bakınız.
