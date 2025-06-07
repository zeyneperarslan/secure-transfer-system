# 🔐 Gelişmiş Güvenli Dosya Transfer Sistemi

> AES/RSA Şifreleme · SHA-256 Bütünlük Doğrulama · IP Header Manipülasyonu · MITM Simülasyonu · Ağ Performans Testi

Bu proje, dosya transfer süreçlerinde güvenliği artırmak amacıyla AES ve RSA şifreleme algoritmalarını, SHA-256 bütünlük kontrolünü ve düşük seviyeli IP manipülasyon tekniklerini birleştiren gelişmiş bir güvenli dosya aktarım sistemidir. Ek olarak, ağ saldırılarına karşı farkındalık sağlayan bir MITM (Man-in-the-Middle) simülasyonu içerir.

---

## 🧩 Proje Özeti

Bu sistemin temel amacı; bir dosyanın hem **gizliliğini**, hem de **bütünlüğünü** sağlayarak güvenli bir şekilde karşı tarafa iletilmesidir. Ayrıca veri iletim sürecinde:
- IP başlık alanları üzerinde **TTL** ve **Fragmentation** gibi parametreler üzerinde değişiklik yapılabilir.
- **iperf3** aracıyla bant genişliği testleri yapılır.
- Tüm olaylar detaylı bir şekilde `log.txt` dosyasına yazılır.
- **Tkinter GUI** arayüzü sayesinde işlemler kullanıcı dostu bir ortamda gerçekleştirilir.

---

## 🛠 Özellikler

| Özellik                        | Açıklama |
|-------------------------------|----------|
| 🔐 AES-256 Şifreleme          | Simetrik anahtar ile hızlı ve güçlü veri şifreleme |
| 🗝️ RSA-2048 Anahtar Yönetimi  | Asimetrik şifreleme ile anahtar değişimi ve güvenlik |
| 🧾 SHA-256 Bütünlük Kontrolü  | Dosyanın bozulup bozulmadığını kontrol eder |
| 🌐 IP Başlık Manipülasyonu    | `Scapy` ile manuel TTL, fragment işlemleri |
| 🧪 MITM Saldırısı Simülasyonu | Gerçek saldırı değil; imza kontrolü ile simülasyon |
| 📊 Ağ Performans Testi        | `iperf3` aracıyla veri iletim hızı ölçümü |
| 🪟 GUI Arayüz                 | `Tkinter` ile tüm işlemler butonlarla yapılabilir |
| 📁 Loglama                    | Tüm işlemler `log.txt` içinde detaylı şekilde tutulur |

---

## 📂 Dosya Yapısı

```
main3.py               # Tüm sistemi çalıştıran ana dosya
README.md              # Bu doküman
log.txt                # Oluşturulan log kayıtları (çalışma sırasında oluşur)
```

---

## 💻 Kurulum

### Gereksinimler:
- Python 3.8+
- pip ile aşağıdaki kütüphaneleri yükleyin:

```bash
pip install scapy pycryptodome iperf3
```

`iperf3` için ayrıca sistemde kurulu olması gerekir:

- **macOS**:
  ```bash
  brew install iperf3
  ```

- **Ubuntu/Debian**:
  ```bash
  sudo apt install iperf3
  ```

---

## 🚀 Kullanım

1. `main3.py` dosyasını çalıştır:

```bash
python3 main3.py
```

2. Açılan GUI üzerinden:
   - Şifreli dosya gönderimi başlatılabilir.
   - Ağ performans testi yapılabilir.
   - IP başlığı ayarları değiştirilebilir.
   - MITM simülasyonu başlatılabilir.

3. **Log kayıtları**, `log.txt` dosyasında tutulur.

---

## 🔍 MITM Simülasyonu

Sistem, gerçek bir MITM saldırısı yapmaz. Bunun yerine, simülasyon modu aktif hale getirildiğinde gelen paketlerde şu imzalar aranır:

- `malware`
- `trojan`
- `attack`
- `exploit`

Bu terimler tespit edilirse, kullanıcıya uyarı verilir ve log dosyasına işlenir.

---

## 📈 Bant Genişliği Testi

Kullanıcı `iperf3` ile hız testi başlatabilir. Sonuçlar açılır pencere ile gösterilir ve sistem log dosyasına kaydedilir.

---

## 🔐 IP Paket Manipülasyonu

`Scapy` kütüphanesi ile doğrudan IP katmanında:
- `TTL` değeri değiştirilebilir
- `flags="MF"` kullanılarak fragmentasyon yapılabilir
- Örnek kod:
```python
pkt = IP(dst="192.168.1.5", ttl=1, flags="MF") / b"Test"
send(pkt)
```

---

## 🧪 Test Senaryoları

| Test | Açıklama |
|------|----------|
| ✔ Dosya şifrelemesi ve şifre çözme test edildi |
| ✔ SHA-256 checksum doğru çalışıyor |
| ✔ TTL ve Fragment değerleri elle ayarlandı ve gönderim yapıldı |
| ✔ iperf3 ile ağ hızı testi başarıyla yapıldı |
| ✔ MITM simülasyonu tehditleri doğru şekilde tespit etti |

---

## 🧾 Lisans

MIT License. Proje tamamen açık kaynaklıdır.

---

## 📬 İletişim

Geliştirici: [Zeynep Erarslan](mailto:zeyneperarslan03@gmail.com)  
GitHub: [github.com/zeyneperarslan](https://github.com/zeyneperarslan)