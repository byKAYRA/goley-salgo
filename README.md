#  Goley Salgo (Özel Sunucu Emülatörü & Ağ Protokol Çekirdeği) [oyuncu kartları bloke]

> [!NOTE]
> **Bağımsız Proje Bildirimi:** Bu proje, **tamamen bağımsız (standalone)** bir sunucu emülatörüdür (`byKAYRA/goley-salgo`). Kendi ayrı deposunda barındırılır, bağımsız olarak derlenir ve istemci kaynak kodlarına hiçbir bağımlılığı yoktur. Yerel ağda, uzak sunucuda (VDS/VPS) veya konteyner içinde tek başına barındırılabilir.

Bu proje, **Goley (TR)** istemcisinin (`Projeye dahil değildir. Ayrı kurulum gerektirir`) ihtiyaç duyduğu tüm ağ servislerini (Kimlik Doğrulama, Giriş Yönlendirme, Lobi ve Yama Dağıtımı) simüle eden, modern **Rust** ve asenkron **Tokio** çalışma zamanı kullanılarak temiz oda tersine mühendislik prensipleriyle sıfırdan geliştirilmiş bağımsız sunucu emülatörüdür.

---

##  Projenin Amacı

1. **Bağımsız Sunucu Altyapısı:** Orijinal sunucuların kapanmasından sonra Goley istemcisinin yerel veya özel ağlarda kesintisiz oynanabilmesini sağlamak.
2. **Özel Ağ Protokollerini Uygulama:**
   * **AniPark Auth Protocol (Port 8000):** Tescilli çok katmanlı XOR algoritması ve dinamik dummy bayt ekleme/kaldırma motoru.
   * **ProudNet Entry Server (Port 2270):** 2048-bit RSA anahtar değişimi (PKCS#1 DER) ve AES-128 OAEP şifreli oturum anahtarı müzakeresi.
   * **Lobby & Match Server (Port 2271):** Lobi yönetimi, oyuncu veritabanı, takım bilgileri ve maç öncesi hazırlık.
3. **Masaüstü Sunucu Arayüzü:** Sunucu hizmetlerini tek tıkla başlatıp durdurabilen, durum kontrolü sağlayan hafif masaüstü aracı.

---

##  Dizin ve Dosya Yapısı

```
goley-salgo/
├── .cargo/
│   └── config.toml               # Derleme ayarları (target-dir = "APP")
├── APP/
│   └── CALENTON/
│       └── release/              # Derlenmiş Sunucu Çıktıları (64-bit x86_64)
│           ├── server-launcher.exe <-- [Özel İkonlu Sunucu Masaüstü GUI]
│           ├── goley-server.exe    <-- [Auth, Entry & Lobby Çekirdek Sunucusu]
│           ├── patchd.exe          <-- [HTTP Yama & İndirme Sunucusu]
│           ├── gly-extract.exe     <-- [Protokol Paket Çıkarıcı CLI]
│           └── gly-cov.exe         <-- [Protokol Kapsam & Conformance Aracı]
├── crates/
│   ├── server-gui/               # Win32 GUI Sunucu Başlatıcı
│   │   ├── src/main.rs           # GUI döngüsü, süreç yaşam döngüsü yönetimi
│   │   ├── build.rs              # İkon derleme betiği
│   │   └── app.ico               # Masaüstü uygulama ikonu
│   ├── server/                   # Auth (8000), Entry (2270), Lobby (2271) ana sunucu motoru
│   ├── proudnet/                 # Nettention ProudNet RMI protokol serileştiricisi
│   ├── patchd/                   # HTTP statik dosya yama servisi
│   ├── volante/                  # Goley VLD/VLH varlık şifreleme/çözme motoru
│   ├── domain/                   # Oyuncu, takım, eşya ve maç veri modelleri
│   ├── persistence/              # SQLite / Veri saklama katmanı
│   ├── glyproto/                 # Protokol paket tanımları ve mesaj yapıları
│   ├── glyproto-schema/          # Protokol şema üretici (IDL)
│   ├── trace/                    # Paket loglama ve izleme katmanı
│   └── conformance/              # Protokol doğrulama ve entegrasyon testleri
├── tools/
│   ├── gly-extract/              # Paket dökümlerinden protokol çıkarma aracı
│   └── gly-cov/                  # Ağ trafiği kapsama alanı analizörü
├── docs/                         # Mimari dökümanlar, paket şemaları, kanıtlar
├── bigpickle.md                  # Kapsamlı Tersine Mühendislik & Durum Raporu
├── build.bat                     # Sunucu projelerini derleyen betik
├── start.ps1                     # Sunucuyu CLI üzerinden başlatan PowerShell betiği
├── Cargo.toml                    # Rust Workspace manifest dosyası
├── LICENSE                       # MIT Lisansı
├── Goley_Emulator_Mimari.md      # Detaylı mimari analiz dokümanı
└── README.md                     # Bu dosya
```

---

##  Dokümantasyon ve Araştırma Raporları

* **`docs/`**: Sunucu mimari şemaları, paket el sıkışma dökümleri, RMI IDL tanımları ve ağ yakalama loglarını barındırır.
* **`Goley_Emulator_Mimari.md`**: Sunucunun Auth, Entry ve Lobby katmanlarının çalışma prensiplerini ve paket analizlerini içeren teknik mimari dokümanıdır.
* **`bigpickle.md`**: Goley protokollerinin çözümlenmesi, bellek içi veri yapıları ve takım oluşturma akışının teknik detaylarını içeren kapsamlı durum raporudur.

---

##  Ağ Servisleri ve Port Yapılandırması

| Servis Adı | Port | Protokol | Açıklama |
|---|---|---|---|
| **AniPark Auth** | `8000` | TCP / Custom AniPark XOR | İlk istemci kimlik doğrulaması ve oturum açılışı |
| **Entry Server** | `2270` | TCP / ProudNet + RSA-2048 | Güvenli oturum anahtarı değişimi ve sunucuya giriş |
| **Lobby Server** | `2271` | TCP / ProudNet RMI | Lobi, takım yönetimi, envanter ve maç eşleşmesi |
| **Patch HTTP** | `8080` | HTTP | İstemci güncelleme kontrolü ve dosya dağıtımı |

---

##  Derleme ve Çalıştırma

### Gereksinimler
* [Rust Toolchain](https://www.rust-lang.org/) (x86_64-pc-windows-msvc)
* Visual Studio C++ Build Tools

### Derleme
Sunucuyu derlemek için proje ana dizinindeki **`build.bat`** dosyasını çalıştırmanız yeterlidir:
```cmd
build.bat
```
Tüm derlenmiş çıktılar otomatik olarak **`APP\CALENTON\release\`** klasöründe toplanır.

### Çalıştırma

#### Seçenek 1: Masaüstü GUI Başlatıcı (Önerilen)
`APP\CALENTON\release\server-launcher.exe` uygulamasını çift tıklayarak açın ve **"SUNUCUYU BAŞLAT"** butonuna basın.

#### Seçenek 2: Komut Satırı (CLI)
Doğrudan `goley-server.exe` çalıştırılabilir:
```powershell
.\APP\CALENTON\release\goley-server.exe
```
Veya PowerShell betiği ile:
```powershell
.\start.ps1
```

---

##  Teşekkürler (Special Thanks)

Bu projenin gelişimine katkıda bulunan ve destek veren değerli topluluk üyelerine teşekkür ederiz:

* [**@uintptr**](https://github.com/0x1-1) — Verdiğiniz ilham ve topluluğa sunduğunuz işler için...
* [**@Özkan Çırak**](https://github.com/ozkancirak) — Proje altyapısı, genel plan ve kesilen iletişim için...
* [**@WlayerX**](https://github.com/WlayerX/goley-server-tools) — Eski projeleri arşivlediğiniz ve dağıttınız için, Teşekkürler.
* Ayrıca bu misyonla bitirilmiş bir proje zaten var. [**Revival Projesi**](https://playrevival.co)'ni inceleyin.
