# Network Scanner
Um scanner de rede escrito em Python que descobre dispositivos ativos na rede, verifica portas abertas e detecta o sistema operacional dos dispositivos.

## Funcionalidades
- Descoberta de dispositivos: Escaneia a rede local para encontrar dispositivos ativos usando o protocolo ARP.

- Verificação de portas abertas: Escaneia portas TCP para identificar serviços em execução.

- Detecção de sistema operacional: Infere o sistema operacional dos dispositivos com base no TTL (Time to Live) das respostas TCP.

## Requisitos
- Python 3.x

- Bibliotecas Python:
    - scapy
    - socket
    - concurrent.futures

## Instalação
    1.Clone o repositório:
    ```bash
    git clone https://github.com/kernelgnu/network-scanner.git
    cd network-scanner
    ```
    2.Instale as dependências:
    ```bash
    pip install scapy
    ```

## Uso
Execute o script scanner.py para escanear a rede:
```bash
python scanner.py
```