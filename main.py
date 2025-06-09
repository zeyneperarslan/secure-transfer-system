import os
import socket
import hashlib
import time
import logging
import subprocess
import tkinter as tk
import struct
from tkinter import filedialog, messagebox
from threading import Thread
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from scapy.all import IP, send
from scapy.all import Raw

# === Genel Ayarlar ===
HOST = '127.0.0.1'
PORT = 5001
BUFFER_SIZE = 4096
CHUNK_SIZE = 1024
SEPARATOR = '<SEPARATOR>'
AUTHORIZED_PASSWORD = "gizliAnahtar"
RSA_KEY_BITS = 2048
RSA_CIPHERTEXT_LENGTH = RSA_KEY_BITS // 8

# === Loglama Ayarı ===
logging.basicConfig(
    filename="log.txt",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# === Anahtar Üretimi ===
def generate_keys():
    key = RSA.generate(RSA_KEY_BITS)
    return key.export_key(), key.publickey().export_key()

# === SHA-256 Checksum ===
def sha256_checksum(filename):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

# === RTT Ölçümü ===
def measure_rtt(sock):
    try:
        start = time.time()
        sock.send(b"PING")
        sock.recv(BUFFER_SIZE)
        end = time.time()
        logging.info(f"RTT: {(end - start) * 1000:.2f} ms")
    except Exception as e:
        logging.error(f"RTT ölçüm hatası: {e}")

# === IP Başlığı Manipülasyonu ===
def ip_manipulasyon():
    hedef_ip = input("Hedef IP adresini girin: ").strip()
    try:
        subprocess.run(["sudo", "python3", "scapy_packet_sender.py"], check=True)
    except subprocess.CalledProcessError:
        print("[!] Paket gönderimi sırasında hata oluştu.")

# === MITM Simülasyonu ===
def mitm_simulasyonu():
    print("[!] MITM saldırısı simülasyonu: Ağ trafiği kaydediliyor...")
    print("[!] Bu sadece bir simülasyondur. Gerçek MITM yapılmaz.")

# === Bant Genişliği Testi ===
def run_bandwidth_test():
    try:
        print("[+] iPerf ile bant genişliği testi başlatılıyor...")
        subprocess.run(["iperf3", "-c", "127.0.0.1", "-t", "5"])
    except Exception as e:
        print(f"[!] iPerf testi başarısız: {e}")

# === Paket Kaybı Simülasyonu ===
def simulate_packet_loss():
    try:
        subprocess.run(["sudo", "tc", "qdisc", "add", "dev", "lo", "root", "netem", "loss", "20%"])
        print("[✓] Paket kaybı simülasyonu aktif (lo üzerinde %20)")
    except Exception as e:
        print(f"[!] tc komutu başarısız: {e}")

# === IDS: Şüpheli Paket Algılayıcı ===
def detect_intrusion(data_chunk):
    signatures = [b"Saldiri", b"HACK", b"EXPLOIT"]
    for sig in signatures:
        if sig in data_chunk:
            print(f"[!] Şüpheli içerik algılandı: {sig.decode()}")


# === recv_all fonksiyonu ===
def recv_all(sock, length):
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return data
        data += packet
    return data

# === Checksum Hesaplama ===

def compute_ip_checksum(packet):
    pkt = packet.copy()
    pkt.chksum = 0
    ip_bytes = bytes(pkt)[:20]
    if len(ip_bytes) % 2 == 1:
        ip_bytes += b'\x00'
    checksum = 0
    for i in range(0, len(ip_bytes), 2):
        word = (ip_bytes[i] << 8) + ip_bytes[i+1]
        checksum += word
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = ~checksum & 0xFFFF
    return checksum

# Test için IP paketi oluştur
ip_pkt = IP(dst="8.8.8.8", ttl=64, flags="DF") / Raw(b"Test")
ip_pkt = ip_pkt.__class__(bytes(ip_pkt))  # Checksum hesaplat

# Karşılaştır
calc_checksum = compute_ip_checksum(ip_pkt)
print("Senin hesapladığın checksum:", hex(calc_checksum))
print("Scapy'nin hesapladığı checksum:", hex(ip_pkt.chksum))

if calc_checksum == ip_pkt.chksum:
    print("Checksum doğru hesaplandı!")
else:
    print("Checksum uyuşmuyor.")
    
# === SERVER TARAFI ===

def server_program():
    private_key, public_key = generate_keys()
    server_socket = socket.socket()
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"[Server] Dinlemede: {HOST}:{PORT}")

    conn, addr = server_socket.accept()
    print(f"[Server] Yeni bağlantı: {addr}")

    conn.send(b"AUTH_REQUEST")
    auth = conn.recv(BUFFER_SIZE).decode()
    if auth != AUTHORIZED_PASSWORD:
        conn.send(b"AUTH_FAILED")
        conn.close()
        return
    conn.send(b"AUTH_SUCCESS")

    client_pub_key_len = int.from_bytes(conn.recv(4), 'big')
    client_pub_key = recv_all(conn, client_pub_key_len)
    conn.send(len(public_key).to_bytes(4, 'big'))
    conn.send(public_key)

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    encrypted_key = recv_all(conn, RSA_CIPHERTEXT_LENGTH)
    session_key = cipher_rsa.decrypt(encrypted_key)

    file_info_len = int.from_bytes(conn.recv(4), 'big')
    file_info = conn.recv(file_info_len).decode()
    filename, filesize = file_info.split(SEPARATOR)
    filename = os.path.basename(filename)
    filesize = int(filesize)

    with open("received_" + filename, "wb") as f:
        while True:
            header_data = conn.recv(BUFFER_SIZE)
            if header_data == b"EOF":
                print("[✓] İstemciden dosya sonu bildirimi alındı.")
                break
            if not header_data:
                print("[!] Bağlantı kesildi veya boş veri alındı.")
                break
            header = header_data.decode().strip('\x00')
            if not header.startswith("PART"):
                print("[!] Beklenmeyen veri başlığı:", header)
                break
            try:
                _, part_id, part_size = header.split(":")
                conn.send(b"ACK")
                encrypted_data = recv_all(conn, int(part_size))
                detect_intrusion(encrypted_data)
                cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=encrypted_data[:16])
                decrypted_data = cipher_aes.decrypt(encrypted_data[16:])
                f.write(decrypted_data)
            except Exception as e:
                print(f"[!] Hata oluştu: {e}")
                break

    print(f"[✓] Dosya başarıyla alındı: received_{filename}")
    try:
        conn.send(b"TRANSFER_COMPLETE")
    except:
        print("[!] İstemci bağlantısı zaten kapatılmış olabilir.")
    conn.close()

# === CLIENT TARAFI ===

def client_program(file_path):
    client_socket = socket.socket()
    client_socket.connect((HOST, PORT))

    try:
        response = client_socket.recv(BUFFER_SIZE).decode()
        if response == "AUTH_REQUEST":
            client_socket.send(AUTHORIZED_PASSWORD.encode())
            result = client_socket.recv(BUFFER_SIZE).decode()
            if result != "AUTH_SUCCESS":
                print("[X] Kimlik doğrulama başarısız!")
                client_socket.close()
                return

        private_key, public_key = generate_keys()
        client_socket.send(len(public_key).to_bytes(4, 'big'))
        client_socket.send(public_key)

        server_pub_key_len = int.from_bytes(client_socket.recv(4), 'big')
        server_pub_key = recv_all(client_socket, server_pub_key_len)

        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(server_pub_key))
        encrypted_key = cipher_rsa.encrypt(session_key)
        client_socket.send(encrypted_key)

        if not os.path.isfile(file_path):
            print("[!] Dosya bulunamadı:", file_path)
            return

        filename = file_path
        filesize = os.path.getsize(filename)
        file_info = f"{filename}{SEPARATOR}{filesize}"
        client_socket.send(len(file_info.encode()).to_bytes(4, 'big'))
        client_socket.send(file_info.encode())

        with open(filename, "rb") as f:
            part_id = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                encrypted_data = cipher_aes.nonce + cipher_aes.encrypt(chunk)
                header = f"PART:{part_id}:{len(encrypted_data)}"
                header_padded = header.ljust(BUFFER_SIZE, '\x00').encode()
                try:
                    client_socket.send(header_padded)
                    ack = client_socket.recv(BUFFER_SIZE)
                    if ack == b"ACK":
                        client_socket.send(encrypted_data)
                        part_id += 1
                except (BrokenPipeError, ConnectionResetError):
                    print("[X] Bağlantı sunucu tarafından kapatıldı. Aktarım başarıyla tamamlandı.")
                    return

        # EOF bildirimi
        client_socket.send(b"EOF")
        final_ack = client_socket.recv(BUFFER_SIZE)
        if final_ack == b"TRANSFER_COMPLETE":
            print("[✓] Aktarım başarıyla tamamlandı.")
    finally:
        client_socket.close()

# === GUI ===
def start_gui():
    def start_server_thread():
        Thread(target=server_program).start()

    def send_file_thread():
        file_path = filedialog.askopenfilename()
        if file_path:
            Thread(target=client_program, args=(file_path,)).start()

    def show_bandwidth_result():
        try:
            output = subprocess.check_output(["iperf3", "-c", "127.0.0.1", "-t", "5"], stderr=subprocess.STDOUT)
            result = output.decode("utf-8")
            messagebox.showinfo("iPerf3 Test Sonucu", result)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Hata", f"iPerf hatası:\n{e.output.decode('utf-8')}")
        except FileNotFoundError:
            messagebox.showerror("Hata", "iPerf3 yüklü değil veya sistemde bulunamadı.")

    root = tk.Tk()
    root.title("Güvenli Dosya Transfer Sistemi")
    root.geometry("400x400")

    tk.Label(root, text="Güvenli Dosya Transfer Arayüzü", font=("Arial", 14)).pack(pady=10)
    tk.Button(root, text="Sunucuyu Başlat", command=start_server_thread, width=30).pack(pady=5)
    tk.Button(root, text="Dosya Gönder (İstemci)", command=send_file_thread, width=30).pack(pady=5)
    tk.Button(root, text="IP Başlığı Manipülasyonu", command=ip_manipulasyon, width=30).pack(pady=5)
    tk.Button(root, text="MITM Saldırısı Simülasyonu", command=mitm_simulasyonu, width=30).pack(pady=5)
    tk.Button(root, text="Bant Genişliği Testi", command=show_bandwidth_result, width=30).pack(pady=5)
    tk.Button(root, text="Paket Kaybı Simülasyonu", command=simulate_packet_loss, width=30).pack(pady=5)
    tk.Button(root, text="Çıkış", command=root.destroy, width=30).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    start_gui()
