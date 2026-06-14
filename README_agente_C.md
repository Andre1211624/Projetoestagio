# Agente de Captura em C — Router Asus XT8

Esta é a versão **robusta em C** do agente de captura, que substitui as
tentativas anteriores em shell/netcat. O C lida com sockets TCP de forma
fiável, resolvendo o problema das ligações repetidas que a app faz.

## Os 2 ficheiros do projeto

| Ficheiro | Onde corre | Função |
|----------|-----------|--------|
| `app.py` | Attack Station (Kali) | Dashboard + lança ataques + cliente integrado |
| `agente_router.c` | Router Asus | Agente de captura (compilar lá) |

## Protocolo (igual ao anterior — a app não muda)

| Comando | Resposta |
|---------|----------|
| `PING` | `OK\|Agent alive` |
| `START\|nome_ataque` | `OK\|Capture started: ...` |
| `STOP` | `OK\|Capture stopped: ...` |
| `GET\|nome_ataque` | `FILE\|nome\|tamanho\n` + bytes do PCAP |
| `LIST` | `OK\|ficheiro1,ficheiro2,...` |

## Como instalar no router (quando tiveres acesso SSH)

### 1. Copiar o ficheiro fonte para o router
```bash
scp agente_router.c admin@192.168.1.1:/tmp/
```

### 2. Ligar ao router por SSH
```bash
ssh admin@192.168.1.1
```

### 3. Confirmar a interface de captura
```bash
ip link show
# ou
brctl show
```
Procura a interface que junta tudo (cabo + Wi-Fi). Costuma ser `br0`.
Se for diferente, edita a linha no .c:
```c
#define CAPTURE_IFACE "br0"   // muda aqui se necessário
```

### 4. Confirmar que existe o compilador e o tcpdump
```bash
which gcc
which tcpdump
```
Se faltar algum, instala via Entware:
```bash
opkg install gcc
opkg install tcpdump
```

### 5. Compilar no router
```bash
cd /tmp
gcc -o agente_router agente_router.c
```

### 6. Arrancar o agente
```bash
./agente_router
```
Deves ver:
```
[xx:xx:xx] AGENTE DE CAPTURA — Asus XT8 (C)
[xx:xx:xx] A escutar na porta: 9999
[xx:xx:xx] Interface de captura: br0
```

### 7. Em background (sobrevive ao fecho do SSH)
```bash
./agente_router &
```
Ou com nohup para garantir:
```bash
nohup ./agente_router > /tmp/agente.log 2>&1 &
```

## Na app (Kali)

1. `streamlit run app.py`
2. Na sidebar, em "Router Capture Agent":
   - Router Agent IP -> IP do router (ex: 192.168.1.1)
   - Router Agent Port -> 9999
3. Clica "Test Agent Connection" -> deve dar ✅
4. Lança ataques normalmente

## Testado e validado

Esta versão foi testada com:
- 5 ligações PING seguidas (todas responderam) ✅
- Ciclo completo START -> STOP -> LIST ✅
- Transferência de ficheiro PCAP via GET (bytes corretos) ✅

O problema das ligações repetidas que existia com o netcat está resolvido.

## Notas

- O agente é leve: o Python/C só orquestra, o trabalho pesado é do tcpdump.
- Para PCAPs grandes, considera mudar `PCAP_DIR` para a pen USB do router
  (ex: `/mnt/sda1` ou o caminho do USB montado).
- O agente processa uma ligação de cada vez, mas de forma rápida e fiável
  (sem o "tempo morto" do netcat).
