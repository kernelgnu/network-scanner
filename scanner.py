from scapy.all import ARP, Ether, srp, IP, TCP, sr1
import socket
from concurrent.futures import ThreadPoolExecutor

# Função para escanear dispositivos na rede
def scan(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

# Função para escanear portas
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port
        sock.close()
    except Exception as e:
        pass
    return None

# Função para escanear várias portas em paralelo
def scan_ports(ip, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        for future in futures:
            port = future.result()
            if port is not None:
                open_ports.append(port)
    return open_ports

# Função para detectar o sistema operacional
def detect_os(ip):
    try:
        # Envia um pacote TCP SYN para uma porta comum (ex: 80)
        packet = IP(dst=ip)/TCP(dport=80, flags="S")
        response = sr1(packet, timeout=2, verbose=0)
        
        if response:
            # Analisa o TTL (Time to Live) da resposta
            ttl = response[IP].ttl
            # Analisa as flags TCP da resposta
            flags = response[TCP].flags

            # Inferir o sistema operacional com base no TTL
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            elif ttl <= 255:
                return "Solaris/AIX"
            else:
                return "Desconhecido"
        else:
            return "Sem resposta"
    except Exception as e:
        return "Erro ao detectar"

# Função principal
def main():
    target_ip = "192.168.1.1/24"  # Intervalo de IPs para escanear
    ports_to_scan = range(1, 1025)  # Portas de 1 a 1024

    print("Escaneando a rede...")
    devices = scan(target_ip)

    print("Dispositivos encontrados:")
    print("IP\t\t\tMAC Address\t\tPortas Abertas\t\tSistema Operacional")
    print("-------------------------------------------------------------------------------")
    for device in devices:
        ip = device['ip']
        mac = device['mac']
        print(f"{ip}\t\t{mac}", end="\t\t")
        
        # Escaneia portas abertas
        open_ports = scan_ports(ip, ports_to_scan)
        if open_ports:
            print(", ".join(map(str, open_ports)), end="\t\t")
        else:
            print("Nenhuma porta aberta", end="\t\t")
        
        # Detecta o sistema operacional
        os = detect_os(ip)
        print(os)

if __name__ == "__main__":
    main()