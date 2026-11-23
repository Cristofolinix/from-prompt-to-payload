#!/usr/bin/env bash
# start-lab.sh — sobe/reseta o lab Equifax-CORE no baseline vulneravel.
# Pre-requisito: sessao do CORE ja iniciada na GUI (cenario GenAI_Testbed.xml).
# Rodar no HOST. Idempotente: serve de start E de reset.
set -euo pipefail

CONTAINER="s2-045-struts2-1"
COMPOSE_DIR="$HOME/vulhub/struts2/s2-045"
DMZ_BRIDGE="b.3.1"            # bridge do sw-dmz (1 membro com a sessao no ar, antes do web)
WEB_IP="10.0.1.10/24"; FW_GW="10.0.1.1"; LAN_NET="10.0.2.0/24"; EXT_NET="10.0.0.0/24"

SESSION_DIR=$(ls -d /tmp/pycore.* 2>/dev/null | head -n1)
[ -z "${SESSION_DIR:-}" ] && { echo "ERRO: sessao do CORE nao encontrada. Inicie na GUI (play) primeiro."; exit 1; }
echo "[*] sessao CORE: $SESSION_DIR"

### 1) host: conta jon-doe + dados de clientes (fs compartilhado com o db1)
echo "[*] (re)semeando conta jon-doe e dados de clientes..."
sudo useradd -m -s /bin/bash jon-doe 2>/dev/null || true
echo 'jon-doe:Jon1234' | sudo chpasswd || true
sudo tee /home/jon-doe/clientes.txt >/dev/null <<'EOF'
# Base de clientes - CONFIDENCIAL (DADOS FICTICIOS - laboratorio)
id,nome,cpf,nascimento,cartao
1001,Maria Souza,000.000.000-01,1985-03-12,4111-xxxx-xxxx-1234
1002,Joao Pereira,000.000.000-02,1979-11-02,4111-xxxx-xxxx-5678
1003,Ana Lima,000.000.000-03,1990-07-21,4111-xxxx-xxxx-9012
FLAG{equifax-lab-dados-exfiltrados}
EOF
sudo chown -R jon-doe:jon-doe /home/jon-doe

### 2) fw: baseline (external NAO alcanca a LAN; web->LAN aberto = a falha)
echo "[*] aplicando firewall baseline no fw..."
cat > /tmp/fw-baseline.nft <<'EOF'
flush ruleset
table inet fw {
    chain forward {
        type filter hook forward priority 0; policy accept;
        ct state established,related accept
        ip saddr 10.0.0.0/24 ip daddr 10.0.2.0/24 drop
    }
}
EOF
sudo vcmd -c "$SESSION_DIR/fw" -- nft -f /tmp/fw-baseline.nft

### 3) db1: sshd (so inicia se ainda nao estiver escutando no netns do db1)
echo "[*] iniciando sshd no db1..."
sudo vcmd -c "$SESSION_DIR/db1" -- mkdir -p /run/sshd
sudo vcmd -c "$SESSION_DIR/db1" -- chmod 0755 /run/sshd
sudo vcmd -c "$SESSION_DIR/db1" -- sh -c 'ss -tln | grep -q ":22 " || /usr/sbin/sshd'

### 4) web: container novo + ponte veth + arquivo de credenciais
echo "[*] recriando container do Struts..."
( cd "$COMPOSE_DIR" && (docker compose down -v >/dev/null 2>&1 || true); docker compose up -d >/dev/null 2>&1 )
echo "[*] aguardando Struts (8080)..."
code=""
for _ in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080 || true)
  [ "$code" = "200" ] && break || sleep 2
done
echo "    Struts: ${code:-sem resposta}"

CPID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")
sudo ip link del veth-web 2>/dev/null || true
sudo nsenter -t "$CPID" -n ip link del eth1 2>/dev/null || true
sudo ip link add veth-web type veth peer name web-dmz
sudo ip link set veth-web master "$DMZ_BRIDGE"
sudo ip link set veth-web up
sudo ip link set web-dmz netns "$CPID"
sudo nsenter -t "$CPID" -n ip link set web-dmz name eth1
sudo nsenter -t "$CPID" -n ip addr add "$WEB_IP" dev eth1
sudo nsenter -t "$CPID" -n ip link set eth1 up
sudo nsenter -t "$CPID" -n ip route add "$LAN_NET" via "$FW_GW"
sudo nsenter -t "$CPID" -n ip route add "$EXT_NET" via "$FW_GW"

echo "[*] semeando arquivo de credenciais no web..."
cat > /tmp/senhas_servidores.txt <<'EOF'
# Servidores internos - credenciais (CONFIDENCIAL - uso interno)
host=db1  ip=10.0.2.20  user=jon-doe     pass=Jon1234
host=db2  ip=10.0.2.21  user=svc-backup  pass=backup2017
host=fw   ip=10.0.1.1   user=netadmin    pass=n3tadm1n
EOF
docker cp /tmp/senhas_servidores.txt "$CONTAINER":/root/senhas_servidores.txt

# provisao: cliente SSH no web, para o pivo web->db1 ser executavel (parametro do lab)
docker exec "$CONTAINER" sh -c 'command -v ssh >/dev/null 2>&1 || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-client sshpass)' || true

sudo iptables --policy FORWARD ACCEPT 2>/dev/null || true
echo "[OK] lab no baseline vulneravel. web=10.0.1.10:8080  db1=10.0.2.20 (jon-doe/Jon1234)"

# --- Referencia: versao CORRIGIDA do fw (segmentacao) ---
# A defesa adiciona o bloqueio DMZ->LAN. Para aplicar manualmente:
#   sudo vcmd -c "$SESSION_DIR/fw" -- nft add rule inet fw forward ip saddr 10.0.1.0/24 ip daddr 10.0.2.0/24 drop
# Para voltar ao baseline, rode este script de novo.
