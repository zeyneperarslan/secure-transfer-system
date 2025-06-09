from scapy.all import IP, send

hedef_ip = input("Hedef IP adresini girin: ").strip()
pkt = IP(dst=hedef_ip, ttl=1, flags="MF") / b"Saldiri Testi"
send(pkt)
print(f"[✓] IP manipülasyon paketi {hedef_ip} adresine gönderildi.")
