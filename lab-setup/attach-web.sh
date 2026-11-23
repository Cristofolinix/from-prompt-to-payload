#!/usr/bin/env bash
# attach-web.sh — conecta o container do Struts (CVE-2017-5638) ao segmento DMZ do CORE.
# Idempotente: rode a cada início de sessão do CORE (e como parte do reset).
# Requer: sessão do CORE rodando (cenário GenAI_Testbed.xml).
set -euo pipefail

# --- parâmetros (ajuste se o cenário do CORE mudar) ---
COMPOSE_DIR="$HOME/vulhub/struts2/s2-045"
CONTAINER="s2-045-struts2-1"
DMZ_BRIDGE="b.3.1"          # bridge do sw-dmz (ver NOTA no final)
WEB_IP="10.0.1.10/24"
FW_GW="10.0.1.1"
LAN_NET="10.0.2.0/24"
EXT_NET="10.0.0.0/24"

echo "[*] subindo o container do Struts..."
( cd "$COMPOSE_DIR" && docker compose up -d >/dev/null 2>&1 )

echo "[*] aguardando o Struts responder (porta 8080)..."
for _ in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080 || true)
  if [ "$code" = "200" ]; then break; fi
  sleep 2
done
echo "[*] Struts respondeu: ${code:-sem resposta}"

CPID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")
echo "[*] container PID: $CPID"

echo "[*] limpando ponte anterior (se existir)..."
sudo ip link del veth-web 2>/dev/null || true
sudo nsenter -t "$CPID" -n ip link del eth1 2>/dev/null || true

echo "[*] criando ponte veth container <-> $DMZ_BRIDGE (sw-dmz)..."
sudo ip link add veth-web type veth peer name web-dmz
sudo ip link set veth-web master "$DMZ_BRIDGE"
sudo ip link set veth-web up
sudo ip link set web-dmz netns "$CPID"
sudo nsenter -t "$CPID" -n ip link set web-dmz name eth1
sudo nsenter -t "$CPID" -n ip addr add "$WEB_IP" dev eth1
sudo nsenter -t "$CPID" -n ip link set eth1 up
sudo nsenter -t "$CPID" -n ip route add "$LAN_NET" via "$FW_GW"
sudo nsenter -t "$CPID" -n ip route add "$EXT_NET" via "$FW_GW"

echo "[*] garantindo encaminhamento (Docker x CORE)..."
sudo iptables --policy FORWARD ACCEPT 2>/dev/null || true

echo "[OK] web na DMZ em ${WEB_IP%/*} (gateway $FW_GW)."
echo "    Teste do external: curl http://${WEB_IP%/*}:8080"

# NOTA — como achar o DMZ_BRIDGE se o cenário mudar:
# com a sessão rodando e o web AINDA sem conectar, o bridge do sw-dmz é o
# 'b.*' com 1 membro (só o fw); o sw-lan e o 'b.*' com 3. Verifique com:
#   for b in $(ip -br link show type bridge | awk '{print $1}'); do \
#     echo "$b : $(ls /sys/class/net/$b/brif 2>/dev/null | wc -l)"; done
