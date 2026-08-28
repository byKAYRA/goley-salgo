# Goley Emülatörü — Mimari Tasarım

**15 Ağustos 2026** · Hedef: mevcut girişimlerden daha ileri, açık kaynak, yeniden kullanılabilir

---

## 0. Önce şunu netleştirelim

"Daha temiz mimari" tek başına bir fark değil. Play Revival'ın çalışan bir sunucusu var; senin daha
iyi katmanlanmış ama çalışmayan sunucun onun yanında bir şey ifade etmez.

Bu belgedeki tez şu: **farkın mimarinin estetiği değil, ürettiğin yeniden kullanılabilir artefaktlar
olsun.** Aşağıdaki tasarımın her parçası, Goley çalışmasa bile başkasının işine yarayacak bir şey
üretiyor. Fark buradan gelir.

---

## 1. Durum tespiti — problem sandığın yerde değil

Aslında **dört bağımsız problem** var ve bunlar birbirini beklemek zorunda değil:

| Katman | Ne | Durum | Kimde var | Lisans |
|---|---|---|---|---|
| **A. Taşıma** | ProudNet (Nettention) | **%90 çözülmüş** | `aizuon/nexum` (C#) | **MIT** ✅ |
| **B. Varlık** | VLD/VLH — "Volante" cipher | **Anahtar biliniyor** | `WlayerX/goley-server-tools` | **MIT** ✅ |
| **C. Oyun** | Goley'in kendi RMI'ları | **Katalog var, gövde yok** | kısmen goley-server-tools | MIT ✅ |
| **D. Çalıştırma** | Themida + GameGuard | **Tıkalı** | herkes burada tıkalı | — |

Bu tablo, bu projenin en önemli bulgusu. Herkes D'de tıkandığı için A, B ve C'nin ne kadar açık
olduğu fark edilmemiş.

### A — ProudNet: sanılandan çok daha hazır

Goley özel bir protokol kullanmıyor. **ProudNet** kullanıyor — Nettention'ın (sonra Pearl Abyss)
ticari ağ middleware'i. S4 League, Vindictus, Ragnarok Online 2, Seven Knights de aynısını kullanıyor.

Bunun anlamı: taşıma katmanının tamamı zaten çözülmüş durumda, iki bağımsız çalışan implementasyon var.

```
TCP frame:  [0..1] uint16 LE magic = 0x5713
            [2]    scalar prefix (1 | 2 | 4)
            [3..]  payload uzunluğu (prefix'e göre u8/i16/i32 LE)
            [...]  payload
            — frame seviyesinde checksum YOK

Core mesaj: [ProudCoreOpCode: 1 byte] + gövde
            Rmi(1) → [RMI id: uint16 LE] + parametreler
            EncryptedReliable(36) → [EncryptMode:1] + struct(ciphertext)
            Compressed(38) → scalar(compLen) + scalar(decompLen) + zlib

Şifreleme:  Secure(1) = AES-ECB, PaddingMode.None
            Fast(2)   = RC4
            Değişim   = RSA-2048/OAEP → AES session key
            Secure plaintext bloğu:
              [padding_len:1][CRC32:4 LE][counter:2 LE (sadece reliable)][data][zero pad]

Handshake:  1. TCP connect
            2. S→C NotifyServerConnectionHint(4)   + NetConfigDto + RSA public key (DER)
            3. C→S NotifyCSEncryptedSessionKey(5)  RSA/OAEP ile şifreli AES anahtarı
            4. S→C NotifyCSSessionKeySuccess(6)
            5. C→S NotifyServerConnectionRequestData(7)  UserData, Version GUID, InternalNetVersion
            6. S→C NotifyServerConnectSuccess(10)  HostId, Version, UserData, IPEndPoint
```

**En kritik mimari cevap — maç simülasyonu:** ProudNet'te sunucu maçı simüle *etmez*. Sunucu
orkestralı P2P mesh var: grup yaşam döngüsünü sunucu yönetir, client'lar birbirine bağlanır,
holepunch başarısızsa sunucu relay'e düşer.

Ve şu muhteşem detay: **P2P grup AES anahtarını sunucu üretip üyelere dağıtıyor.** Yani emülatör
tüm peer-to-peer trafiği deşifre edebilir. Maç protokolünü çözmek için man-in-the-middle kurmana
gerek yok — zaten anahtarın sahibisin.

ProudNet'te **host migration primitifi yok**. Varsa Goley'in kendi RMI katmanındadır.

### B — Varlık katmanı: anahtar zaten açık

`goley-server-tools` (MIT) şunu belgelemiş:

```
Master key = MD5("VolanteEncryptKey_84106141")
Cipher     = Anipark özel (TEA delta sabitleri + Blowfish tarzı S-box, 16 byte blok, sonra zlib)
Akış       = VLH içindeki 16 byte gömülü anahtar → MD5 → VLD anahtarı → path bazlı zlib akışları
Fonksiyonlar: anahtar üretimi @0x4194c0, 16-byte blok çözme @0x4185f0
Yöntem     : cipher yeniden yazılmamış, orijinal fonksiyonlar Unicorn x86 ile emüle ediliyor
```

Bizim bağımsız gözlemimiz bunu doğruluyor: `Character.VLH` ve `Character.VLPH`'in 0x18 offsetinde
**birebir aynı 16 byte** var (`5694 02AD 1771 2FEF C59F 994F A718 E87C`). Tarif edilen "gömülü
anahtar" tam olarak bu. (AES-ECB ile denedim, tutmadı — beklendiği gibi özel cipher.)

"Volante" muhtemelen Anipark'ın kendi framework/paketleme katmanının adı — VLD = **V**o**L**ante
**D**ata, VLH = **V**o**L**ante **H**eader. Gamebryo 2.3 ise 3D motor (geliştirme müdürü Yang
Wan-seok'un röportajından). İkisi çelişmiyor: Gamebryo render, Volante paketleme.

**Sonuç:** VLD/VLH okuyucusu yazmak artık araştırma değil, mühendislik. Ve kimse yayınlamamış —
Xentax, ZenHAX, QuickBMS, GitHub'da tek bir unpacker yok.

### C — Oyun katmanı: asıl iş burada

RMI ID kataloğu (goley-server-tools'tan, client'tan çıkarılmış):

```
Entry  C2S 1500+   S2C 2000+
Lobby  C2S 3000+   S2C 4000+
Battle C2S 5000+   S2C 6000+   C2C 7000+

RequestLogin=1510        RequestFirstLogon=1503    RequestHeroSlots=1504
RequestSelectHero=1505   NotifyLoginOk=2030        GotoLobby=2032
Chat=3003                RequestCreateGameRoom=3004 RequestJoinGameRoom=3005
GotoGameRoom=4020
```

Bu aralıklar ProudNet'in PIDL kuralıyla tam uyumlu (kullanıcı RMI aralığı 1300–60000, ProudNet'in
kendi dahili RMI'ları 64001+). Bağımsız bir doğrulama.

**Elde olmayan:** parametre şemaları. ID'ler ve isimler var, gövdeler yok. İşin büyük kısmı bu.

### D — Çalıştırma: herkesin tıkandığı yer

```
Themida 2.x    → kısmi bypass var (IFEO + DLL inject + MinHook, statik patch RVA'ları belgeli)
nProtect GameGuard → TIKALI. Client splash'ta ("ChaguChagu V31927") donuyor,
                     GameMon ready event'i hiç sinyallenmiyor.
                     94 aday WaitForSingleObject çağrısı ayıklanamamış.
```

Themida tespitini biz de bağımsız doğruladık: `BinaryTr.bin`'in import tablosu **iki DLL'den toplam
iki fonksiyon** (`kernel32.lstrcpy`, `comctl32.InitCommonControls`) — Themida imzası. TLS dizini var.
Entry point kendi başlangıç baytına breakpoint konulup konulmadığını kontrol ediyor
(`E8 01 00 00 00 / CC / 58 ... 80 3B CC`). Launcher'da da aynı iki import.

---

## 2. Stratejik konumlanma — asıl fark burada

Araştırmanın en değerli çıktısı şu tek cümle:

> **Rust, Go, C++ veya Python'da açık kaynak ProudNet implementasyonu yok. Sadece C# var.**

GitHub'ın `proudnet` topic'inde iki repo var. `grep.app`'te `ProudFrameDecoder` için sıfır sonuç.

Yani `proudnet-rs` yazarsan, Goley hiç çalışmasa bile **S4 League, Vindictus, Ragnarok Online 2,
Seven Knights ve 250+ lisanslı oyunun topluluğuna** hitap eden bir crate üretmiş olursun. Bu,
"daha temiz mimari"den bambaşka bir fark — kimsenin yapmadığı bir şeyi yapmış olursun.

**Bu yüzden mimarinin birinci kararı: ProudNet katmanını Goley'den tamamen ayrı, bağımsız
yayınlanabilir bir crate olarak yaz.** NetspherePirates bunu doğru yapmış (`src/ProudNet/` oyundan
tamamen bağımsız) — ondan öğren, ama Rust'ta ve kendi başına yayınlanabilir olarak.

⚠️ **Lisans notu:** `nexum` **MIT** — kullanabilirsin. `NetspherePirates`'in GitHub aynasında
**LICENSE dosyası yok**, yani varsayılan "all rights reserved" — kodunu kopyalama, **spesifikasyon
olarak oku**. `goley-server-tools` MIT.

---

## 3. Mimarinin dört taşıyıcı kararı

### Karar 1 — Client tek gerçek kaynak. O yüzden merkez sunucu değil, uygunluk koşumu.

Değiştiremeyeceğin bir binary'ye karşı yazıyorsun. Her byte önemli, ve doğru olup olmadığını
söyleyecek tek makam client'ın kendisi. Bu yüzden mimarinin ağırlık merkezi **conformance harness**
olmalı, sunucu değil.

Somut: sanal makinede gerçek client'ı otomatik başlatan, senaryo koşturan ve tepkisini assert eden
bir koşum. Emülatör dünyasında bunu yapan neredeyse tek proje `node-minecraft-protocol` —
TrinityCore'da yok, AzerothCore'da yok, Sapphire'de yok, NetspherePirates'te yok.

**Bunu yaparsan bu alanda ikinci olursun.**

### Karar 2 — Protokol kod değil, veri.

`gtker/wow_messages` modeli. Paket tanımları bir IDL'de yaşar; ondan üretilir:

```
protocol/*.gly  ──┬──▶ Rust codec (Read/Write impl)
                  ├──▶ mdBook protokol dokümantasyonu
                  ├──▶ Wireshark Lua dissector        ← bu alanda kimsede yok
                  ├──▶ JSON IR (başka diller için)
                  └──▶ kapsam raporu
```

Neden bu kadar önemli: NetspherePirates'te paket tanımı C# attribute'ları içinde gömülü. Bundan
doküman üretemiyorsun, dissector üretemiyorsun, başka dile taşıyamıyorsun. Üstelik opcode↔tip
eşlemesi **ayrı bir elle listede** (`MessageFactory`, ~300 satır) — sessizce kayabilen ikinci bir
gerçek kaynak.

Wireshark dissector'ı özellikle vurguluyorum: ProudNet için hiçbir yerde yok ve senin kendi RE
işini de hızlandırır. Tek kaynaktan bedava geliyor.

### Karar 3 — Bilinmezlik birinci sınıf bir tip.

Protokolü henüz bilmiyorsun. Mimari bunu bir eksiklik değil, **modellenmiş bir durum** olarak
taşımalı.

```
message RequestLogin = 1510 {
    string   account;
    string   token;
    unknown  tail { size = 8, hypothesis = "client build + region?" };
    status   = partial;
}
```

- `unknown` alanları runtime'da **gözlemlenen değer histogramı** biriktirir
- Decode sonrası artakalan byte varsa uyarı + metrik (Valence'in "missed N bytes" fikri)
- CI her build'de rapor basar: *"312/1180 mesaj doğrulanmış, 91 mesajda 214 bilinmeyen alan"*

TrinityCore'un `STATUS_UNHANDLED`'ı bu fikrin en olgun hali: 1011 client opcode'unun 395'i açıkça
"uygulanmadı" olarak işaretli. Kapsam tek `grep` ile ölçülebiliyor. NetspherePirates'in `Unk1`,
`Unk2` konvansiyonu ise sorgulanamıyor — kaç alanın bilinmediğini kimse söyleyemiyor.

**Bu karar, RE'yi kahramanlıktan ölçülebilir bir boru hattına çevirir.** Projenin en yenilikçi
parçası bu.

### Karar 4 — Her şey kaydedilir, her şey replay edilir.

Goley'in hiçbir pcap kaydı yok, hiç olmayacak da. O yüzden **corpus'u kendin üretirsin.**

- Her oturum ikili trace olarak diske yazılır
- Trace'ler ayrı bir repoda test corpus'u olur (`minecraft-packets` modeli)
- CI'daki tek değişmez: **`encode(decode(bytes)) == bytes`**
- Deterministik replay = regresyon takımı + hata ayıklama + "hiç sahip olmadığımız pcap"

Bu, sıfır anlamsal bilgi gerektirmeden protokol katmanının tamamını doğruluyor. Bir mesajın ne
anlama geldiğini bilmesen bile, byte'larını doğru okuyup doğru yazdığını kanıtlıyorsun.

---

## 4. Katman yapısı

Tek repo, çok crate. **Process ayrımı yapma** — NetspherePirates 4 process + Redis'e bölünmüş,
aralarındaki iletişim tipsiz pub/sub ve elle korelasyon; Redis düşünce dördü birden anlamsızlaşıyor.
Sınırları crate düzeyinde çiz, process ayrımını gerçekten ölçekleme gerektiren yerde (relay) yap.

```
goley/
├── crates/
│   ├── proudnet/            ← BAĞIMSIZ YAYINLANIR. Goley'i hiç bilmez.
│   │   ├── frame            magic 0x5713, scalar codec
│   │   ├── crypt            RSA-OAEP, AES-ECB+CRC32+counter, RC4
│   │   ├── core             opcode 1–49, handshake durum makinesi
│   │   ├── rmi              RMI dispatch, PIDL parametre kodlaması
│   │   ├── p2p              grup yaşam döngüsü, holepunch, relay fallback
│   │   └── udp              reliable UDP, MTU discovery, fragmentation
│   │
│   ├── glyproto/            protokol IDL'i + kod üreteci (build.rs)
│   ├── glyproto-schema/     .gly dosyaları — protokolün TEK gerçek kaynağı
│   │
│   ├── volante/             VLD/VLH/VLPD/VLPH okuyucu. Bağımsız yayınlanır.
│   │   ├── cipher           Anipark cipher (önce Unicorn, sonra native port)
│   │   ├── archive          index + veri akışları
│   │   └── patch            VLP katmanının base üstüne bindirilmesi
│   │
│   ├── domain/              oyun mantığı. Ağ tipi görmez, saf.
│   │   ├── account, hero, room, match, inventory
│   │
│   ├── server/              entry(2270) + lobby(2271) + battle(2272) TEK binary
│   ├── patchd/              patch(80) + launcher(8080) HTTP
│   │
│   ├── persistence/         sqlx, compile-time doğrulanan sorgular
│   ├── trace/               kayıt/replay altyapısı
│   └── conformance/         gerçek client'ı sürüp assert eden koşum
│
├── tools/
│   ├── gly-extract/         client binary'sinden RMI tablosu → JSON (ground truth)
│   ├── gly-dissect/         üretilen Wireshark Lua dissector'ı
│   └── gly-cov/             kapsam raporu
│
├── corpus/                  (submodule) yakalanmış paket trace'leri
└── docs/                    IDL'den üretilen protokol kitabı
```

**Neden `domain` ağ tipi görmez:** oyun mantığını protokolden ayırırsan, protokol değiştiğinde
(ki sürekli değişecek, çünkü öğrenerek ilerliyorsun) oyun mantığı bozulmaz. NetspherePirates'te
handler'lar doğrudan LINQ yazıyor ve mesaj tipleriyle iç içe — refactor riskli.

---

## 5. Protokol IDL'i

Kendi dilini yaz — büyük iş değil, `pest` ile bir öğleden sonra. Alternatif olarak TOML/KDL da olur,
ama sürüm etiketleri ve `unknown` blokları özel dilde çok daha okunur.

```
// glyproto-schema/entry.gly

service Entry { c2s_base = 1500; s2c_base = 2000; }

message RequestLogin = 1510 {
    string   account;                       // UTF-16LE, uint32 char-count önekli
    string   password_hash;
    u32      client_build;                  // "V31927"?
    unknown  tail { size = 8, hypothesis = "region kodu + platform" };

    status = partial;
    since  = "2016-03-18";
}

message NotifyLoginOk = 2030 {
    u32      account_id;
    string   nickname;
    u8       hero_slot_count;
    status = unverified;
}

test RequestLogin {
    account = "test";
    password_hash = "…";
} [
    0x0a, 0x00, 0x00, 0x00, /* char count */
    …                       /* corpus'tan alınmış gerçek byte'lar */
]
```

`test` blokları `wow_messages`'ın fikri: byte vektörünü şemanın içine gömüyorsun, üretilen kod
otomatik test oluyor.

`status` alanı Karar 3'ün somutu: `unverified | partial | verified`. CI bu alanları sayıp kapsam
raporu basar.

**Sürüm etiketlerini ilk günden koy.** NetspherePirates tek client sürümüne çivilenmiş
(`options.Version = new Guid("{beb92241-…}")`), ikinci sürüm için tek yol fork'lamak — nitekim
`NeoNetspherePirates` diye bir fork var. Sende iki build zaten var (2015-09-22 ve 2016-03-18);
sürüm boyutunu şemaya sonradan eklemek her mesajı elden geçirmek demek.

---

## 6. Test ve CI stratejisi

Dört katman, artan maliyet sırasıyla:

**1. Corpus round-trip (saniyeler)**
`encode(decode(bytes)) == bytes`. Anlamsal bilgi gerektirmez. Protokol katmanının tamamını korur.

**2. Handler testleri (saniyeler)**
Bellek içi transport üzerinde, gerçek socket olmadan. `domain` saf olduğu için oyun mantığı ayrıca
ve hızlıca test edilir.

**3. Headless client (dakikalar)**
`proudnet` crate'i hem sunucu hem client tarafını implement etsin (nexum böyle yapıyor). Kendi
client'ınla kendi sunucuna bağlanıp senaryo koştur. Gerçek client olmadan CI'da çalışır.

**4. Gerçek client döngüde (dakikalar, nightly)**
Windows VM'de gerçek `Goley_.exe`, scriptlenmiş: login → lobby → oda → maç. Ekran görüntüsü ve
paket trace'i artefakt olarak saklanır. **Bu, projenin imza özelliği olur.**

Ek olarak, Dolphin'in FifoCI'sından ödünç: her build'de trace replay'i çalıştır, önceki sürümün
çıktısıyla diff'le, farkı web arayüzünde göster.

---

## 7. Teknoloji seçimleri

| Katman | Seçim | Gerekçe |
|---|---|---|
| Dil | **Rust** | Binary protokol modellemede tip sistemi gerçekten kazandırıyor; codegen için proc-macro; oyun sunucusu için eşzamanlılık güvenliği. Ayrıca boş bir niş (Rust ProudNet yok). |
| Async | **tokio** | Rakipsiz. |
| Buffer | **bytes** (`Bytes`/`BytesMut`) | Referans sayımlı, zero-copy; broadcast'te payload çoğaltmıyorsun. |
| Framing | **tokio-util** `Framed` | Uzunluk önekli protokoller için hazır. |
| Binary parse | **kendi codegen'in** | `binrw`/`deku`'ya bağlanma — IDL'den doğrudan `Read`/`Write` impl üret. `wow_messages` böyle yapıyor ve haklı. |
| Oyun durumu | **düz struct + kanal** | ECS'e atlama. Bevy ekibi kendi uyarıyor: async entegrasyonu doğal değil, ECS sabit tick varsayıyor. Oyun P2P olduğu için sunucuda ağır simülasyon yok — ECS'in çözdüğü problem sende yok. |
| Gözlemlenebilirlik | **tracing** + `tokio-console` | Span'ler oturum/oda/maç korelasyonu için birebir. |
| DB | **sqlx** offline mode | Compile-time sorgu doğrulaması, CI'da DB gerekmiyor. |
| Config | **figment** veya düz TOML + serde | Hjson provider'ı elle yazma (NetspherePirates yazmış, gereksiz iş). |
| Codegen | `build.rs` + **syn/quote** | Valence kalıbı: JSON/IDL oku → `TokenStream` üret. |

**Nerede zeki olma:** oyun durumu için ECS, mesajlaşma için aktör framework'ü, erken microservice.
Bunların hiçbiri senin probleminde bir şey çözmüyor, sadece karmaşıklık ekliyor.

---

## 8. Yol haritası

Her aşamanın **ölçülebilir çıkış kriteri** var ve her biri kendi başına yayınlanabilir bir değer üretiyor.

### M0 — İskelet ve disiplin (1 hafta)
Repo, crate düzeni, CI, `docs/`, corpus submodule'ü, `.gitignore`'da client uzantıları.
**Çıkış:** boş ama derlenen ağaç + yeşil CI.

### M1 — `volante` crate'i: VLD/VLH okuyucu ⭐ **önce bunu yap**
Anahtar biliniyor, cipher fonksiyon RVA'ları biliniyor, Unicorn yaklaşımı belgeli.
Client'ı hiç çalıştırmadan, sadece elindeki dosyalarla yapılabilir. Ve **kimsede yok**.
**Çıkış:** `gly-extract vld Data/Character.VLD --out ./extracted` çalışıyor; iki build'in
arşivleri açılıp diff'lenebiliyor.
**Yayın değeri:** ilk açık VLD/VLH unpacker'ı. Tek başına projeyi referans yapar.

### M2 — `proudnet` crate'i ⭐ **ikinci en yüksek getiri**
`nexum`'u (MIT) spesifikasyon olarak oku, Rust'ta sıfırdan yaz. Hem sunucu hem client tarafı.
**Çıkış:** kendi client'ın kendi sunucuna handshake yapıp RMI alışverişi yapıyor; corpus
round-trip testleri geçiyor.
**Yayın değeri:** ilk açık kaynak Rust ProudNet. Goley'den bağımsız bir kitle.

### M3 — IDL ve kod üretimi
`.gly` dili, üreteç, Wireshark dissector çıktısı, kapsam raporu.
**Çıkış:** `cargo gen && cargo test` yeşil; `docs/` protokol kitabı üretiliyor; dissector Wireshark'ta yükleniyor.

### M4 — Client'ı konuşturmak (asıl duvar)
Themida + GameGuard. goley-server-tools'un statik patch RVA'ları ve IFEO+inject iskeleti başlangıç.
Tıkandıkları yer: GameMon ready event'i.
**Çıkış:** client giriş ekranına gelip senin entry sunucuna TCP açıyor.
**Not:** M1–M3 bunu beklemeden yapılabilir. Bu yüzden bu sırayla.

### M5 — Entry: login
İlk gerçek handshake. `NetVersion` ve `Version` GUID'i client'tan çıkarılacak.
**Çıkış:** client login olup hero slot ekranını görüyor.

### M6 — Lobby: oda listesi ve oda kurma
**Çıkış:** iki client aynı odada.

### M7 — Battle: P2P grup
Sunucu grubu kurar, anahtarı dağıtır, holepunch'ı yönetir, gerekirse relay'e düşer.
Anahtar sende olduğu için tüm P2P trafiğini kaydedip C2C protokolünü çözebilirsin.
**Çıkış:** maç başlıyor.

---

## 9. Repo hijyeni ve lisans

- **Lisans: MIT veya Apache-2.0.** `proudnet` ve `volante` crate'lerinin yeniden kullanılabilir
  olmasını istiyorsan permissive olmalı. GPL bu niş için yanlış.
- Repo **client dosyası, asset, packed binary, memory dump barındırmaz.** `.gitignore`'a
  `*.vld *.vlh *.vlpd *.vlph *.bin *.exe` baştan koy.
  (goley-server-tools `goley_real_code.bin` diye 1.7 MB'lık client dump'ı commit'lemiş — hukuken
  gri, taklit etme.)
- README'de client'ı **tarif et, dağıtma**:
  ```
  ## Required client
  goley.exe — 1,057,544,728 bytes
  SHA-256 d555b49982061cd32f27bcec4de54642e28946790281911d96af86a6cf47ea1e
  Not distributed here.
  ```
- Arşiv item'ını (archive.org) emülatör reposuna bağlama. İki riski ayrı tut.
- `NetspherePirates` kodunu kopyalama — lisansı yok. Oku, anla, kendin yaz.

---

## 10. Bilinen değerler — hızlı başvuru

```
PORTLAR
  entry   2270/TCP    login, hero slot
  lobby   2271/TCP    oda listesi, oda kurma, chat
  battle  2272/TCP+UDP  maç kurma, P2P holepunch, relay
  patch     80/HTTP   HashV2.VLL, PatchInfo.bin
  launcher8080/HTTP   MSHTML launcher
  DNS: cdn.joygamedl.com, joygame.com → hosts ile 127.0.0.1
  Orijinal: login 213.74.179.12:2270, oyun :20260

RMI ARALIKLARI
  Entry  C2S 1500 / S2C 2000     Lobby C2S 3000 / S2C 4000
  Battle C2S 5000 / S2C 6000 / C2C 7000
  ProudNet dahili: C2S 64001+, S2C 64501+

PIDL KODLAMA
  int32/int64 LE · bool = 1 byte · string = uint32 char-count + UTF-16LE

LAUNCHER IPC (NMRunParamDLL.dll — tamamen çözülmüş)
  3DES-EDE3 CBC · anahtar 24 byte ASCII, NUL-terminate, kısa ise SPACE-pad
  IV = anahtarın ilk 8 byte'ı · padding = 8'e tamamlayan count-byte (tam katsa yok)
  Zarf: K1=V1;<<grp=>>;K2=V2; → 3DES → HEX
  Bölge kodları: NM / KR / TR / ID / VN / GL
  Cmdline: "<exe>" <Region>Auth <KEY24>

VARLIK ŞİFRELEME
  Master: MD5("VolanteEncryptKey_84106141")
  Anahtar üretimi @0x4194c0 · 16-byte blok çözme @0x4185f0 (image base 0x400000)
  VLH 0x18'de 16 byte gömülü anahtar (VLH ve VLPH'de aynı)

KORUMA (bizim ölçümümüz)
  BinaryTr.bin 8,311,504 byte · PE timestamp 2015-12-10 · EP 0x157F000
  import: kernel32.lstrcpy + comctl32.InitCommonControls (Themida imzası)
  TLS dizini var · EP'de INT3 self-check
  Launcher Goley.exe 2,691,792 byte · aynı iki import
  Client sürüm string'i: "ChaguChagu V31927"

VERİ YAPISI (bizim ölçümümüz)
  Base VLD/VLH arşivleri 2015-09-22 ve 2016-03-18 build'lerinde BYTE BYTE AYNI
  Tüm güncellemeler VLPD/VLPH patch katmanı olarak binmiş
```

---

## 11. Açık sorular

1. **ProudNet sürümü.** `NetVersion` S4L'de 196977, nexum'da 196980. Goley 2013 → farklı olacak.
   Client'tan çıkarılmalı; yanlışsa `NotifyProtocolVersionMismatch` yersin.
2. **`NetConfigDto` alan düzeni.** Alan 8 (`FastEncryptedMessageKeyLength`) 2013 sürümünde var mı?
   Varsa sonraki tüm offsetler kayar. **En yüksek riskli belirsizlik.**
3. **Oyuna özgü `Version` GUID'i.** `NotifyServerConnectionRequestData` içinde.
4. **Host migration Goley'de var mı?** ProudNet seviyesinde yok; varsa C2C 7000+ RMI'larında.
5. **Volante ile Gamebryo ilişkisi.** Volante muhtemelen Anipark'ın Gamebryo üstündeki kendi
   katmanı — ama doğrulanmadı.
6. **Maç ne kadar client-authoritative?** P2P olduğu için sunucu neyi doğrulayabilir, netleşmeli.

---

## Kaynaklar

- ProudNet resmî dokümanı: https://docs.proudnet.com/proudnet.eng — LLM indeksi: `/llms.txt`
- `aizuon/nexum` (MIT, en tam ProudNet reimplementasyonu): https://github.com/aizuon/nexum
- `wtfblub/NetspherePirates` (lisanssız — spec olarak oku): https://github.com/wtfblub/NetspherePirates
- `WlayerX/goley-server-tools` (MIT): https://github.com/WlayerX/goley-server-tools
- `gtker/wow_messages` (protokol-as-data referansı): https://github.com/gtker/wow_messages
- `PrismarineJS/minecraft-packets` (corpus modeli): https://github.com/PrismarineJS/minecraft-packets
- `valence-rs/valence` (Rust sunucu, ground-truth extraction): https://github.com/valence-rs/valence
- TrinityCore Opcodes.cpp (kapsam takibi): https://github.com/TrinityCore/TrinityCore/blob/master/src/server/game/Server/Protocol/Opcodes.cpp
- Sapphire opcode pipeline retrospektifi: https://sapphireserver.github.io/dev/2019/12/23/fixing-opcodes.html
- Techolay Goley RE konusu: https://techolay.net/sosyal/konu/8-yil-sonra-goley-uzerinden-kendi-private-serverimi-yaziyorum.196434/
