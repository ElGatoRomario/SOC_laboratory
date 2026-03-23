"""Build Kibana Detection Engine rule bodies from config."""

from ..config import get_index
from ..generators.pools import MALICIOUS_IPS, USERS_ADMIN, SUSPICIOUS_PORTS
from .mitre import build_threat_block


def build_all_rules(cfg: dict) -> list[dict]:
    """Return the full list of internal rule definitions."""
    ai = get_index(cfg, "auth")
    ni = get_index(cfg, "network")
    ei = get_index(cfg, "endpoint")
    di = get_index(cfg, "dns")
    fi = get_index(cfg, "firewall")

    mal_ips = " or ".join(MALICIOUS_IPS[:15])
    adm_users = " or ".join(USERS_ADMIN[:8])
    sus_ports = " or ".join(str(p) for p, _ in SUSPICIOUS_PORTS)

    rules = [
        # ── Initial Access ──
        _r("soc-ia-001", "Brute Force - Multiple Failed Logins", "threshold",
           'event.outcome: "failure" and event.category: "authentication"',
           [ai], "high", 73, "Initial Access", "T1110.001", "Brute Force: Password Guessing",
           "10+ failed logins from same IP in 1h.",
           threshold={"field": ["source.ip"], "value": 10, "cardinality": []}),
        _r("soc-ia-002", "Login from Known Malicious IP", "query",
           f'event.outcome: "success" and event.category: "authentication" and source.ip: ({mal_ips})',
           [ai], "critical", 99, "Initial Access", "T1078", "Valid Accounts",
           "Successful auth from known threat-intel IPs."),
        _r("soc-ia-003", "Admin Login from External IP", "query",
           f'event.outcome: "success" and user.name: ({adm_users}) and not source.ip: 10.* and not source.ip: 172.16.* and not source.ip: 192.168.*',
           [ai], "high", 78, "Initial Access", "T1078.002", "Valid Accounts: Domain Accounts",
           "Admin accounts authenticating from non-RFC1918."),

        # ── Execution ──
        _r("soc-ex-001", "Suspicious PowerShell Encoded Command", "query",
           'process.name: "powershell.exe" and (process.command_line: *-enc* or process.command_line: *hidden* or process.command_line: *bypass* or process.command_line: *IEX* or process.command_line: *DownloadString* or process.command_line: *DisableRealtimeMonitoring*)',
           [ei], "high", 75, "Execution", "T1059.001", "PowerShell",
           "PowerShell with encoded/hidden/bypass flags."),
        _r("soc-ex-002", "CMD Reconnaissance Commands", "query",
           'process.name: "cmd.exe" and (process.command_line: *whoami* or process.command_line: *"net user"* or process.command_line: *"net localgroup"* or process.command_line: *nltest* or process.command_line: *systeminfo*)',
           [ei], "medium", 55, "Execution", "T1059.003", "Windows Command Shell",
           "cmd.exe running recon commands."),
        _r("soc-ex-003", "LOLBin Proxy Execution", "query",
           '(process.name: "mshta.exe" or process.name: "rundll32.exe" or process.name: "regsvr32.exe") and (process.command_line: *http* or process.command_line: *javascript* or process.command_line: *vbscript* or process.command_line: *scrobj*)',
           [ei], "high", 70, "Execution", "T1218", "System Binary Proxy Execution",
           "LOLBin execution with suspicious arguments."),

        # ── Persistence ──
        _r("soc-pe-001", "Registry Run Key Modification", "query",
           "process.command_line: *reg* and process.command_line: *add* and process.command_line: *CurrentVersion\\Run*",
           [ei], "high", 72, "Persistence", "T1547.001", "Registry Run Keys",
           "reg add targeting Run keys."),
        _r("soc-pe-002", "Scheduled Task for Persistence", "query",
           "process.command_line: *schtasks* and process.command_line: */create*",
           [ei], "medium", 60, "Persistence", "T1053.005", "Scheduled Task",
           "schtasks /create detected."),
        _r("soc-pe-003", "Suspicious Service Installation", "query",
           'process.command_line: *"sc create"* and (process.command_line: *Temp* or process.command_line: *ProgramData* or process.command_line: *Public*)',
           [ei], "high", 70, "Persistence", "T1543.003", "Windows Service",
           "sc create from temp locations."),

        # ── Credential Access ──
        _r("soc-ca-001", "Credential Dumping - Mimikatz / LSASS", "query",
           'process.command_line: (*mimikatz* or *sekurlsa* or *lsadump* or *procdump*lsass* or *"reg save"*SAM* or *"reg save"*SYSTEM* or *ntdsutil*)',
           [ei], "critical", 95, "Credential Access", "T1003.001", "LSASS Memory",
           "Mimikatz / procdump / SAM dump detected."),

        # ── Discovery ──
        _r("soc-di-001", "Network Reconnaissance Tools", "query",
           '(process.name: ("nmap" or "nmap.exe" or "masscan" or "masscan.exe")) or (process.command_line: (*"arp -a"* or *"netstat -an"* or *"net view"*))',
           [ei], "medium", 50, "Discovery", "T1018", "Remote System Discovery",
           "nmap, masscan, arp, netstat, net view."),

        # ── Lateral Movement ──
        _r("soc-lm-001", "Lateral Movement via PsExec / SMB", "query",
           "process.command_line: (*psexec* or *"net use"*C$* or *"net use"*IPC$* or *wmic*/node*)",
           [ei], "high", 80, "Lateral Movement", "T1021.002", "SMB/Windows Admin Shares",
           "PsExec or net use to admin shares."),
        _r("soc-lm-002", "External RDP Connection", "query",
           "destination.port: 3389 and not source.ip: 10.* and not source.ip: 172.16.* and not source.ip: 192.168.*",
           [ni], "medium", 55, "Lateral Movement", "T1021.001", "Remote Desktop Protocol",
           "RDP from non-internal IPs."),

        # ── Defense Evasion ──
        _r("soc-de-001", "Certutil File Download", "query",
           'process.name: "certutil.exe" and (process.command_line: *urlcache* or process.command_line: *encode* or process.command_line: *decode*)',
           [ei], "high", 70, "Defense Evasion", "T1140", "Deobfuscate/Decode Files",
           "Certutil used for download/encode/decode."),
        _r("soc-de-002", "Shadow Copy Deletion - Ransomware", "query",
           "process.command_line: (*vssadmin*delete*shadow* or *bcdedit*recoveryenabled*No* or *wbadmin*delete*catalog*)",
           [ei], "critical", 95, "Defense Evasion", "T1490", "Inhibit System Recovery",
           "Shadow copy deletion or recovery disable."),

        # ── Command & Control ──
        _r("soc-cc-001", "Outbound to Known Malicious IP", "query",
           f'network.direction: "outbound" and destination.ip: ({mal_ips})',
           [ni], "critical", 90, "Command and Control", "T1071.001", "Web Protocols",
           "Outbound to threat-intel IPs."),
        _r("soc-cc-002", "Suspicious DGA / DNS Tunnel", "query",
           'tags: ("dga_suspect" or "dns_tunnel_suspect" or "known_malicious_domain")',
           [di], "high", 75, "Command and Control", "T1568.002", "Domain Generation Algorithms",
           "DNS tagged as DGA or tunnel."),
        _r("soc-cc-003", "Connection on Suspicious Port", "query",
           f'network.direction: "outbound" and destination.port: ({sus_ports})',
           [ni], "medium", 55, "Command and Control", "T1571", "Non-Standard Port",
           "Outbound to suspicious ports."),

        # ── Exfiltration ──
        _r("soc-xf-001", "Large Outbound Data Transfer", "query",
           'network.direction: "outbound" and source.bytes >= 10000000 and not destination.ip: 10.* and not destination.ip: 172.16.* and not destination.ip: 192.168.*',
           [ni], "high", 70, "Exfiltration", "T1048.003", "Exfiltration Over Unencrypted Protocol",
           "Outbound >10MB to external."),
        _r("soc-xf-002", "Data Archiving Before Exfiltration", "query",
           "process.command_line: (*rar*-hp* or *7z*-p* or *curl*POST*upload*)",
           [ei], "high", 68, "Exfiltration", "T1560.001", "Archive via Utility",
           "rar/7z with password or curl upload."),

        # ── Firewall ──
        _r("soc-fw-001", "Inbound Blocked from Malicious IP", "query",
           f'network.direction: "inbound" and event.action: ("denied" or "dropped" or "reset") and source.ip: ({mal_ips})',
           [fi], "medium", 50, "Initial Access", "T1190", "Exploit Public-Facing Application",
           "FW blocked inbound from known bad IPs."),
        _r("soc-fw-002", "Outbound to Malicious IP Allowed", "query",
           f'network.direction: "outbound" and event.action: "allowed" and destination.ip: ({mal_ips})',
           [fi], "critical", 90, "Command and Control", "T1071", "Application Layer Protocol",
           "FW allowed outbound to threat-intel IPs."),
    ]
    return rules


def _r(rule_id, name, rtype, query, index, severity, risk_score,
       tactic, tech_id, tech_name, description, threshold=None):
    d = {
        "rule_id": rule_id, "name": name, "type": rtype,
        "query": query, "index": index,
        "severity": severity, "risk_score": risk_score,
        "tactic": tactic, "technique_id": tech_id,
        "technique_name": tech_name, "description": description,
    }
    if threshold:
        d["threshold"] = threshold
    return d


def to_kibana_body(rule: dict) -> dict:
    """Convert internal rule dict to Kibana Detection Engine API format."""
    body = {
        "rule_id": rule["rule_id"],
        "name": rule["name"],
        "description": rule["description"],
        "type": rule["type"],
        "query": rule["query"],
        "language": "kuery",
        "index": rule["index"],
        "severity": rule["severity"],
        "risk_score": rule["risk_score"],
        "interval": "5m",
        "from": "now-6m",
        "to": "now",
        "enabled": True,
        "tags": ["SOC-Ingestor", "Auto-Generated"],
        "threat": build_threat_block(rule["tactic"], rule["technique_id"], rule["technique_name"]),
    }
    if rule["type"] == "threshold":
        body["threshold"] = rule["threshold"]
    return body
