# Goley RE — Araç ve MCP Kılavuzu

**15 Ağustos 2026** · Themida 2.x + nProtect GameGuard + ProudNet + Volante VLD/VLH

---

## Önce üç sert gerçek — araç seçimini bunlar belirliyor

1. **Themida 2.x = dinamik iş.** Ghidra/Binary Ninja gibi statik araçlar ancak binary'yi
   unpack ETTİKTEN sonra işe yarar. Asıl unpack'i bir debugger (x64dbg / IDA debugger) yapar.

2. **GameGuard = kernel-mode anti-debug.** x64dbg, Frida ve tüm user-mode araçları tespit edip
   bloklar. MCP bunu değiştirmez. Ve muhtemelen senin donma probleminin gerçek sebebi bu:
   GameMon'un imzasız/eski kernel driver'ı modern Windows'ta **DSE (Driver Signature Enforcement)**
   yüzünden yüklenemiyor → client'ın beklediği ready-event hiç sinyallenmiyor → sonsuz splash.
   Sorun senin tarafında değil, GameMon'un modern OS'te ölmesinde.

3. **ProudNet = şifreli protokol.** Wireshark payload'ı çözemez, sadece TCP stream + hex döker.
   Gerçek çözüm: kripto fonksiyonlarını binary'de hook'lamak. **Yani "ağ analizi" görevi bile
   aslında bir binary-RE görevi.** Ağ araçları ikincil.

**Sonuç:** MCP'ler işi kolaylaştırır ama duvarı kaldırmaz. GameGuard duvarı bir MCP sorunu değil,
bir OS/driver sorunu. Önce onu çöz (aşağıda 3 yaklaşım), sonra MCP'ler hızlandırır.

---

## MCP sunucuları — dört tanesi gerçekten değerli

MCP'ler Claude connector registry'sinde YOK. Hepsi GitHub'dan kendin host ettiğin, bir RE aracına
bağlanan köprüler. Claude Code / Cowork'e kendin eklersin.

### 1. IDA Pro MCP — `mrexodia/ida-pro-mcp` ⭐ (IDA lisansın varsa 1 numara)
```
Repo    github.com/mrexodia/ida-pro-mcp   ~8.7k★   ekosistemin referansı, aktif
Araç    IDA Pro 8.3+ (IDA Free DESTEKLENMİYOR → ticari lisans şart)
İşlev   decompile, disasm, xref, rename, assembly patch, memory read
        + TAM DEBUGGER: breakpoint, step, register, memory r/w
Kurulum claude plugin install ida-pro-mcp@mrexodia
```
**Değeri en yüksek** çünkü tek araçta hem statik (ProudNet kriptosunu, VLD loader'ını decompile) hem
dinamik (Themida'yı OEP'e kadar sür, dump al). Bu proje için ideal — ama IDA Pro pahalı.

### 2. x64dbg MCP — `SetsunaYukiOvO/x64dbg-mcp` ⭐ (ücretsiz, Themida'ya özel)
```
Repo    github.com/SetsunaYukiOvO/x64dbg-mcp   ~337★   MIT   79 tool
Araç    x64dbg (ÜCRETSIZ)
İşlev   exec control, memory r/w/search, tüm breakpoint tipleri,
        PACKER DETECTION + OEP DETECTION, memory dump, patch yönetimi
```
**OEP + packer detection = birebir Themida unpack iş akışı.** IDA lisansın yoksa dinamik tarafın 1
numarası. Alternatifler: `Wasdubya/x64dbgMCP` (~404★, en çok yıldız), script'lenebilir unpack için
`dariushoule/x64dbg-automate`.

### 3. Ghidra MCP — `LaurieWired/GhidraMCP` (ücretsiz statik omurga)
```
Repo    github.com/LaurieWired/GhidraMCP   ~9.8k★   Apache-2.0   en çok yıldızlı RE MCP
Araç    Ghidra (ÜCRETSIZ)
İşlev   decompile, auto-rename, xref, comment, listeleme — SADECE STATİK
```
Unpack'lenmiş client'ı decompile edip ProudNet mesaj yapılarını ve VLD parse mantığını okumak için.
Themida'yı kendisi açamaz (statik). IDA'nın ücretsiz alternatifi.

### 4. Frida MCP — `dnakov/frida-mcp` (güçlü ama GameGuard'a karşı riskli)
```
Repo    github.com/dnakov/frida-mcp   ~364★   MIT   DENEYSEL (~5 commit)
Araç    Frida 16+
İşlev   attach/spawn, JS REPL, fonksiyon hook, console yakalama
```
**Teoride mükemmel:** ProudNet'in encrypt/decrypt fonksiyonunu hook'layıp **plaintext paket + canlı
AES anahtarını** dökebilirsin — RSA handshake'i hiç tersine çevirmeden. **Pratikte:** GameGuard
Frida'yı en agresif tespit eden araçtır. Ancak GameGuard'ı devre dışı bıraktıktan sonra değerli olur.

### Atla
- **Wireshark MCP'leri** (WireMCP, SharkMCP...) — ProudNet şifreli, payload'ı çözemezler. Sadece
  framing/timing doğrulaması için destekleyici. Ana araç yapma.
- **Binary Ninja MCP'leri** — sadece zaten BN sahibiysen; yoksa IDA/Ghidra ile örtüşür.
- **Dedike angr MCP** — yok (sadece Arkana içinde gömülü). Symbolic execution bu projede fazla ağır.

---

## MCP olmayan araçlar — asıl işi bunlar yapıyor

MCP'ler köprü; gerçek işi yapan araçlar bunlar. Çoğu MCP'siz kullanılıyor.

### Themida 2.x unpacking

| Araç | Ne | Not |
|---|---|---|
| **ergrelet/unlicense** ⭐ | ~1.4k★, Frida tabanlı, Themida/WinLicense **2.x + 3.x** için amaca özel tek olgun araç | Otomatik OEP + IAT reconstruction. 32-bit Themida 2.x'te import çözümü yavaş ama çalışır. Dumplar çoğu zaman tek başına runnable değil → **analiz için mükemmel** |
| **Hendi48/Magicmida** | ~644★, aktif, tek-tık Themida unpacker | İlk denenecek. `/unpack <file>` CLI. VM anti-dump'ları düzeltmez |
| **x64dbg/Scylla** | IAT reconstruction standardı | Themida v2.180 IAT düzeltmeleri var. Senin iki-fonksiyona inmiş import tablonu toparlamak için |
| **x64dbg "Themida v2.x OEP Finder"** | Ücretsiz script, **2.4.6.0'da test** (tam senin sürüm ailen) | ScyllaHide ŞART, yoksa çalışmaz |

**Bizim ölçümümüzle uyumu:** `BinaryTr.bin` import tablosu iki fonksiyona inmiş (`kernel32.lstrcpy`,
`comctl32.InitCommonControls`), TLS callback var, EP'de INT3 self-check — bu araçların hedeflediği
tam senaryo.

### Anti-anti-debug (Themida'nın debugger check'lerini geçmek için — zorunlu)

| Araç | Ne |
|---|---|
| **x64dbg/ScyllaHide** ⭐ | User-mode anti-anti-debug standardı. OEP script'i bunsuz çalışmaz |
| **mrexodia/TitanHide** | Kernel-seviye. ScyllaHide'ın yakalayamadığı check'leri kapatır |
| **Vicshann/GhostDbg** | VEH + hardware breakpoint tabanlı gizli debugging |

### GameGuard atlatma (donma probleminin çözümü)

| Kaynak | Ne |
|---|---|
| **LSFDC/KRNprotectBypass** | Lost Saga (aynı nProtect ailesi) — senin durumuna en yakın analog. DLL inject + detour hook |
| **NetspherePirates / NeoNetsphere / FagNet** | S4 League (GameGuard'lı Kore oyunu) private server'ları — **izlenecek model** |
| **Zuan's blog** (john0312.wordpress.com) | GameGuard iç yapısı — en teknik açık kaynak: GameMon inject, SSDT hook, kernel CRC self-check |
| **gmh5225/awesome-game-security** | Anticheat/antidebug curated koleksiyon — her şey burada toplu |

**Kilit ders (S4 League topluluğundan):** Bu ekipler GameGuard'ı kriptografik olarak "kırmıyor".
Server enforcement olmadığı için, client'ı anti-cheat'i **hiç başlatmayacak/beklemeyecek** şekilde
patch'liyorlar. Senin izleyeceğin model tam bu.

### VLD/VLH cipher çözme

| Araç | Ne | Rust? |
|---|---|---|
| **Unicorn Engine** ⭐ | CPU emülatörü. Volante decrypt rutinini binary'den lift edip çalıştır — cipher'ı yeniden yazmadan | **Evet**, `unicorn-engine` crate. goley-server-tools da bunu kullanıyor |
| **Qiling** | Unicorn + tam OS katmanı. Rutin Win32/CRT çağırıyorsa (malloc, CryptoAPI) elle stub gerekmez | Python |
| **ImHex** ⭐ | Ücretsiz hex editor + pattern language. VLH header tanımla, entropi ile zlib-vs-şifreli ayır, decrypt node'larıyla prototiple | — |
| **binwalk v3** | Entropi + zlib stream auto-extract | **Evet**, %99 Rust, crate olarak gömülebilir |

**Yöntem:** Cipher'ı yeniden yazma — riskli. Unicorn ile orijinal fonksiyonu (anahtar üretimi
@0x4194c0, blok çözme @0x4185f0) çalıştır. Deterministik, hatasız, hepsi Rust'ta.

### ProudNet paket analizi

| Aşama | Araç |
|---|---|
| Yakalama | Wireshark; raw TCP için tcpflow; canlı müdahale için mitmproxy raw-TCP mode |
| **İçeriği açma (şart)** | **Frida** — client'ın AES encrypt/decrypt'ini hook'la, session key + plaintext dump. RSA'yı hiç tersine çevirmezsin |
| Dissect | **Wireshark Lua dissector** (magic 0x5713 + length + RMI id + CRC32). Lua ile başla |
| Rust'ta modelle | **deku** (bit-level header) veya **binrw** (seekable gövde) |
| Emülatör doğrulama | **boofuzz** (gerçek client'a karşı); kendi Rust kodun için AFL++ |

### Protokol-as-data (mimarideki IDL kararı için)

**`gtker/wow_messages`** — tam senin emsalin. `.wowm` IDL'inden tek kaynaktan **Rust encode/decode +
Wireshark dissector + doküman + JSON IR** üretiyor. Read+write (Kaitai'nin aksine — o sadece okur,
emülatör yazamaz). ProudNet RMI mesajlarını modellemek için taklit edilecek mimari.

Daha hafif orta yol: ayrı IDL istemezsen **deku/binrw derive struct'larını** tek doğruluk kaynağı yap
(proc-macro codegen, read+write bedava). Bedeli: Wireshark/çok-dilli çıktı yok.

---

## Önerilen uçtan uca iş akışı

```
1. GAMEGUARD DUVARI (önce bu — MCP değil, OS sorunu)
   En robüst: client'a dokunmadan fake ready-event stub.
   ScyllaHide açıkken x64dbg + API Monitor ile client'ın beklediği named event/mutex adını bul,
   sonra kendi process'inle OpenEvent+SetEvent ile sinyalle. Themida'yı hiç kırmana gerek kalmaz.
   Alternatif: IFEO ile client spawn anında x64dbg auto-attach → WaitForSingleObject'i bul → hook.

2. THEMIDA UNPACK (statik analiz gerekiyorsa)
   Magicmida (tek-tık) → olmazsa unlicense (Frida) → manuel gerekirse
   x64dbg + ScyllaHide + OEP Finder script → Scylla ile IAT rebuild
   MCP: SetsunaYukiOvO/x64dbg-mcp (OEP detection) veya ida-pro-mcp

3. STATİK ANALİZ (unpack sonrası)
   Ghidra MCP veya IDA MCP ile decompile → ProudNet kripto fonksiyonunu, RMI stub'larını,
   VLD loader'ını (@0x4194c0 / @0x4185f0) bul

4. CANLI ANAHTAR/PLAINTEXT (GameGuard atlatıldıysa)
   Frida ile encrypt/decrypt hook → AES session key + plaintext paket dump

5. VLD/VLH ÇÖZ (client çalışmadan da yapılabilir)
   Unicorn ile decrypt rutinini çalıştır → ImHex ile format doğrula → Rust volante crate

6. PROTOKOL MODELLE
   Wireshark Lua dissector → .gly IDL → Rust codec (wow_messages modeli)
```

**Not:** 5 (VLD/VLH) adımı 1-4'ü beklemiyor. Client'ı hiç çalıştırmadan, elindeki dosyalarla ve
Unicorn ile yapılabilir. Mimari belgesinde M1 olmasının sebebi bu — en erken kazanç, en az bağımlılık.

---

## Minimum başlangıç seti

Her şeyi kurma. Bu proje için gereken çekirdek:

**Ücretsiz yol (IDA yoksa):**
- x64dbg + ScyllaHide + TitanHide + Scylla → unpack & dinamik
- `SetsunaYukiOvO/x64dbg-mcp` → agent entegrasyonu
- Ghidra + `LaurieWired/GhidraMCP` → statik decompile
- ImHex → VLD/VLH format keşfi
- Unicorn (`unicorn-engine` Rust crate) → cipher çalıştırma
- Wireshark + Lua → paket dissector

**IDA lisansın varsa:** yukarıdaki x64dbg+Ghidra ikilisini tek `ida-pro-mcp` ile değiştir, gerisi aynı.

**Frida'yı** en son ekle — GameGuard'ı çözene kadar seni yakalar, çözünce en değerli aracın olur.

---

## Kaynaklar

- Awesome RE-MCP: https://github.com/crowdere/Awesome-RE-MCP
- ida-pro-mcp: https://github.com/mrexodia/ida-pro-mcp
- x64dbg-mcp: https://github.com/SetsunaYukiOvO/x64dbg-mcp
- GhidraMCP: https://github.com/LaurieWired/GhidraMCP
- frida-mcp: https://github.com/dnakov/frida-mcp
- unlicense (Themida 2.x): https://github.com/ergrelet/unlicense
- Magicmida: https://github.com/Hendi48/Magicmida
- ScyllaHide: https://github.com/x64dbg/ScyllaHide
- awesome-game-security: https://github.com/gmh5225/awesome-game-security
- GameGuard internals: https://john0312.wordpress.com/category/gameguard-related/
- unicorn-engine (Rust): https://github.com/unicorn-engine/unicorn-engine-rs
- ImHex: https://github.com/WerWolv/ImHex
- wow_messages: https://github.com/gtker/wow_messages
- NetspherePirates (S4L, GameGuard modeli): https://github.com/wtfblub/NetspherePirates
