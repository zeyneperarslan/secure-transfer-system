# 🔐 Gelişmiş Güvenli Dosya Transfer Sistemi

**AES/RSA Şifreleme · SHA-256 Bütünlük Kontrolü · IP Header Manipülasyonu · MITM Simülasyonu · Ağ Performans Testi · Checksum Doğrulama**

Bu proje, dosya transferlerinde güvenliği artırmak amacıyla AES ve RSA şifreleme algoritmalarını, SHA-256 bütünlük kontrolünü ve IP paket işleme tekniklerini bir araya getiren gelişmiş bir sistemdir. Ek olarak, MITM (Man-in-the-Middle) simülasyonu ve ağ performans testleri içerir.

---

## 📌 Proje Özeti

- Dosya iletimi sırasında **gizlilik**, **bütünlük** ve **güvenlik** sağlanır.
- IP başlığı parametreleri (TTL, Fragment) doğrudan manipüle edilebilir.
- `iperf3` ile bant genişliği testleri yapılabilir.
- Tüm işlemler `log.txt` dosyasına kaydedilir.
- Kullanıcı dostu **Tkinter GUI** arayüzü ile etkileşim kolaylaştırılır.

**🎬 Demo Video:** [YouTube Linki](https://www.youtube.com/watch?v=IIAdUI5zL5I)

---

## 🚀 Özellikler

| Özellik                     | Açıklama |
|----------------------------|----------|
| AES-256 Şifreleme          | Güçlü ve hızlı simetrik şifreleme |
| RSA-2048 Anahtar Yönetimi  | Güvenli anahtar iletimi |
| SHA-256 Kontrolü           | Dosya bütünlüğü doğrulaması |
| IP Başlık Manipülasyonu    | TTL ve Fragmentation kontrolü |
| MITM Simülasyonu           | Saldırı imzası analizi |
| Ağ Performans Testi        | `iperf3` ile hız testi |
| Checksum Hesaplama         | IP paketlerinin elle checksum kontrolü |
| Tkinter GUI                | Grafiksel kullanıcı arayüzü |
| Loglama                    | Detaylı işlem kaydı tutulur |

---

## 📁 Dosya Yapısı

```
main.py             # Ana Python uygulaması
README.md           # Açıklama dosyası
log.txt             # Log kayıtları
```

---

## ⚙️ Kurulum

**Gereksinimler:**

- Python 3.8+
- Gerekli kütüphaneler:

```bash
pip install scapy pycryptodome iperf3
```

**iperf3 kurulumu:**

- macOS:
  ```bash
  brew install iperf3
  ```
- Ubuntu/Debian:
  ```bash
  sudo apt install iperf3
  ```

---

## 🧪 Kullanım

1. Uygulamayı çalıştır:
```bash
python3 main.py
```

2. GUI üzerinden:
   - Dosya gönder/al
   - Bant genişliği ölç
   - IP başlıklarını manipüle et
   - MITM simülasyonu çalıştır

3. İşlem sonuçları `log.txt` dosyasına kaydedilir.

---

## 🕵️ MITM Simülasyonu

Gerçek saldırı yapılmaz. `EXPLOIT`, `HACK`, `Saldiri` gibi anahtar kelimeler analiz edilir. Kullanıcıya şüpheli içerik hakkında uyarı verilir.

---

## 📡 Ağ Performans Testi

`iperf3` komutu ile ağ hızı ölçülür. Sonuçlar GUI penceresinde ve log dosyasında gösterilir.

---

## 📦 IP Paket İşleme & Checksum

`Scapy` ile özel IP paketleri oluşturulabilir. Ayrıca manuel olarak checksum hesaplanarak doğruluk kontrolü yapılır.

```python
pkt = IP(dst="192.168.1.1", ttl=1, flags="MF") / b"Test"
send(pkt)
```

---

## ✅ Test Senaryoları

| Test                           | Açıklama |
|--------------------------------|----------|
| Dosya Şifreleme ve Çözme       | AES ile şifreleme başarıyla sağlandı |
| SHA-256 Doğrulama              | Dosya bütünlüğü korundu |
| IP Paket Manipülasyonu         | TTL/Fragment başarıyla uygulandı |
| Bant Genişliği Ölçümü          | `iperf3` ile hız testi tamamlandı |
| MITM Simülasyonu               | Zararlı imzalar başarıyla tespit edildi |
| Checksum Hesaplama             | IP başlığı checksum değeri doğru bulundu |

---

## 📜 Lisans

MIT Lisansı ile lisanslanmıştır. Açık kaynaklıdır.

---

## 👤 Geliştirici

**Zeynep Erarslan**  
📧 zeyneperarslan03@gmail.com  
🔗 [github.com/zeyneperarslan](https://github.com/zeyneperarslan)
