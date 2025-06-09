# Gelişmiş Güvenli Dosya Transfer Sistemi

**AES/RSA Şifreleme · SHA-256 Bütünlük Kontrolü · IP Header Manipülasyonu · MITM Simülasyonu · Ağ Performans Testi**

Bu proje, dosya transferlerinde güvenliği en üst seviyeye çıkarmak amacıyla AES ve RSA şifreleme algoritmalarını, SHA-256 bütünlük kontrolünü ve düşük seviyeli IP paket işleme tekniklerini birleştiren bir sistemdir. Ek olarak, kullanıcı farkındalığı için MITM (Man-in-the-Middle) simülasyonu ve performans testleri içerir.

---

## Proje Özeti

Bu sistem ile amaçlanan; dosya iletimi sırasında gizliliği, bütünlüğü ve güvenliği sağlamaktır. Ek olarak:

- TTL ve Fragmentation gibi IP başlık alanları manuel olarak ayarlanabilir.
- `iperf3` aracıyla ağ bant genişliği testleri yapılabilir.
- Tüm işlemler `log.txt` dosyasına kayıt edilir.
- Kullanıcı dostu bir Tkinter arayüzü ile etkileşim sağlanır.

**Demo Video:** [YouTube Linki](https://www.youtube.com/watch?v=IIAdUI5zL5I)

---

## Özellikler

| Özellik                     | Açıklama |
|----------------------------|----------|
| AES-256 Şifreleme          | Hızlı ve güçlü simetrik şifreleme |
| RSA-2048 Anahtar Yönetimi  | Güvenli anahtar değişimi |
| SHA-256 Kontrolü           | Dosya bütünlüğü doğrulaması |
| IP Başlık Manipülasyonu    | TTL ve fragmentasyon kontrolü |
| MITM Simülasyonu           | Gerçek saldırı yerine imza analizi |
| Ağ Performans Testi        | `iperf3` ile hız ölçümü |
| Tkinter GUI                | Grafik arayüz ile işlem kolaylığı |
| Loglama                    | Tüm işlemler kaydedilir |

---

## Dosya Yapısı

```
main3.py         # Ana uygulama dosyası
README.md        # Açıklama dokümanı
log.txt          # Çalışma sırasında oluşturulan log kayıtları
```

---

## Kurulum

**Gereksinimler:**

- Python 3.8+
- Gerekli kütüphanelerin yüklenmesi:

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

## Kullanım

1. Uygulamayı başlatmak için:
```bash
python3 main3.py
```

2. Açılan GUI üzerinden:
   - Şifreli dosya gönderimi
   - Bant genişliği testi
   - IP başlığı ayarları
   - MITM simülasyonu işlemleri yapılabilir.

3. Kayıtlar `log.txt` içinde tutulur.

---

## MITM Simülasyonu

Gerçek bir saldırı gerçekleştirilmez. Aksine, belirli kelimeler içeren paketler (örn: `malware`, `trojan`, `attack`, `exploit`) analiz edilir ve kullanıcıya bildirim gönderilir.

---

## Ağ Performans Testi

Kullanıcı `iperf3` komutu ile ağ performansını ölçebilir. Sonuçlar grafik arayüzde gösterilir ve log dosyasına yazılır.

---

## IP Paket İşleme

`Scapy` ile özel IP paketleri oluşturulabilir. Örnek kullanım:

```python
pkt = IP(dst="192.168.1.5", ttl=1, flags="MF") / b"Test"
send(pkt)
```

---

## Test Senaryoları

| Test                             | Açıklama |
|----------------------------------|----------|
| Dosya Şifreleme ve Çözme         | AES ile şifreleme ve başarıyla çözme sağlandı. |
| SHA-256 Doğrulama                | Dosyanın bütünlüğü korundu. |
| IP Paket Manipülasyonu           | TTL ve Fragmentation başarıyla uygulandı. |
| Bant Genişliği Ölçümü            | `iperf3` ile ağ testi başarılı şekilde yapıldı. |
| MITM Simülasyonu                 | Zararlı imzalar doğru tespit edildi. |

---

## Lisans

Bu proje MIT lisansı ile lisanslanmıştır. Açık kaynak olarak sunulmaktadır.

---

## İletişim

Geliştirici: Zeynep Erarslan  
E-posta: [zeyneperarslan03@gmail.com](mailto:zeyneperarslan03@gmail.com)  
GitHub: [github.com/zeyneperarslan](https://github.com/zeyneperarslan)
