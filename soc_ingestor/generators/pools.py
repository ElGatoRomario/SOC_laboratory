"""Expanded data pools — IPs, hostnames, users, processes, domains, etc."""

import random

# ── Internal IPs (multi-subnet corp network) ─────────────────
_SUBNETS = [
    ("10.0.1", 10, 254), ("10.0.2", 10, 254), ("10.0.3", 10, 254),
    ("10.0.10", 10, 254), ("10.0.20", 10, 254), ("10.0.50", 10, 254),
    ("10.1.0", 10, 254), ("10.1.1", 10, 254),
    ("172.16.0", 10, 254), ("172.16.1", 10, 254), ("172.16.10", 10, 254),
    ("192.168.1", 10, 254), ("192.168.10", 10, 254), ("192.168.100", 10, 254),
]
INTERNAL_IPS = []
for _s, _lo, _hi in _SUBNETS:
    INTERNAL_IPS.extend(f"{_s}.{random.randint(_lo, _hi)}" for _ in range(8))

# ── External IPs ─────────────────────────────────────────────
EXTERNAL_IPS = [
    f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    for _ in range(200)
]

# ── Malicious IPs (Tor, C2, APT, scanners, mining) ──────────
MALICIOUS_IPS = [
    "185.220.101.34", "185.220.101.35", "185.220.101.46",
    "23.129.64.210", "23.129.64.211", "23.129.64.213",
    "171.25.193.77", "171.25.193.78", "162.247.74.27", "162.247.74.74",
    "199.249.230.87", "199.249.230.119",
    "89.248.167.131", "89.248.174.203",
    "45.154.255.147", "45.154.255.148",
    "194.26.29.102", "5.188.206.76", "5.188.210.12",
    "103.145.13.56", "198.98.56.189",
    "45.77.65.211", "104.168.44.129", "149.28.100.10", "95.179.163.20",
    "64.227.0.177", "137.184.100.50",
    "58.218.198.100", "61.160.224.50",
    "77.83.247.81", "176.119.1.100", "185.141.63.120", "91.215.85.100",
    "142.4.211.40", "54.36.108.155", "88.198.117.170",
]

# ── DNS domains ──────────────────────────────────────────────
DNS_MALICIOUS = [
    "evil-c2.darknet.xyz", "exfil.badactor.ru", "update.malware-cdn.com",
    "c2-beacon.attacker.net", "data-collector.evil.io", "payload.exploit.cc",
    "implant-callback.malnet.ru", "reverse-shell.hacker.cc",
    "login-microsft.com", "g00gle-auth.net", "0ffice365-login.com",
    "paypa1-secure.com", "app1e-id-verify.net", "okta-sso-verify.net",
    "pool.minexmr.shadow.com", "upload.anon-files.cc",
]

DNS_NORMAL = [
    "google.com", "www.google.com", "mail.google.com", "microsoft.com",
    "login.microsoftonline.com", "teams.microsoft.com", "github.com",
    "api.github.com", "amazon.com", "aws.amazon.com", "facebook.com",
    "linkedin.com", "stackoverflow.com", "gitlab.com", "elastic.co",
    "cdn.cloudflare.com", "api.slack.com", "zoom.us", "salesforce.com",
    "jira.atlassian.com", "virustotal.com", "wikipedia.org", "youtube.com",
    "reddit.com", "windowsupdate.microsoft.com", "ocsp.digicert.com",
    "crl.microsoft.com",
]

# ── Users ────────────────────────────────────────────────────
USERS_STANDARD = [
    "jgarcia", "mlopez", "asmith", "kbrown", "lmartin", "rjohnson",
    "pwilliams", "cdavis", "tjones", "bmiller", "nwilson", "dmoore",
    "ktaylor", "janderson", "bthomas", "sjackson", "lwhite", "dharris",
    "mclark", "alewis", "jrobinson", "pwalker", "ryoung", "tallen",
    "eking", "dwright", "sscott", "mgreen", "jbaker", "cadams",
]

USERS_SERVICE = [
    "svc_backup", "svc_monitor", "svc_deploy", "svc_scanner", "svc_elastic",
    "svc_splunk", "svc_jenkins", "svc_ansible", "svc_sql", "svc_web",
    "svc_api", "svc_mail", "svc_k8s", "svc_docker", "svc_vault",
    "svc_logstash", "app_backend", "app_worker",
]

USERS_ADMIN = [
    "admin", "administrator", "root", "dbadmin", "webadmin", "sysadmin",
    "netadmin", "secadmin", "cloudadmin", "superuser", "itadmin",
    "domainadmin", "sa", "dba",
]

USERS_ALL = USERS_STANDARD + USERS_SERVICE + USERS_ADMIN

# ── Hostnames ────────────────────────────────────────────────
HOSTNAMES = (
    [f"WS-PC{i:03d}" for i in range(1, 31)]
    + [f"LPT-{d}{i:02d}"
       for d in ["SALES", "DEV", "EXEC", "FIN", "IT", "SEC"]
       for i in range(1, 4)]
    + [f"SRV-DC{i:02d}" for i in range(1, 4)]
    + [f"SRV-WEB{i:02d}" for i in range(1, 6)]
    + [f"SRV-APP{i:02d}" for i in range(1, 6)]
    + [f"SRV-DB{i:02d}" for i in range(1, 4)]
    + ["SRV-JUMP01", "SRV-PROXY01", "SRV-SIEM01", "SRV-VPN01",
       "SRV-DNS01", "SRV-MAIL01", "SRV-BACKUP01", "SRV-DOCKER01",
       "SRV-K8S-MASTER01", "SRV-ELASTIC01", "SRV-KIBANA01",
       "SRV-JENKINS01", "SRV-VAULT01"]
    + ["AWS-EC2-PROD01", "AWS-EC2-DEV01", "AZ-VM-PROD01", "GCP-GCE-PROD01"]
)

# ── Processes ────────────────────────────────────────────────
PROCS_NORMAL = [
    "chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe", "explorer.exe",
    "svchost.exe", "teams.exe", "slack.exe", "code.exe", "python.exe",
    "node.exe", "java.exe", "sqlservr.exe", "MsMpEng.exe", "WINWORD.EXE",
    "EXCEL.EXE", "mstsc.exe", "git.exe", "docker.exe",
    "nginx", "httpd", "sshd", "cron", "systemd", "dockerd", "kubelet",
    "python3", "postgres", "redis-server", "elasticsearch", "bash",
    "curl", "wget",
]

PROCS_SUSPICIOUS = [
    "powershell.exe", "cmd.exe", "certutil.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe", "net.exe",
    "nltest.exe", "msbuild.exe",
    "mimikatz.exe", "psexec.exe", "procdump.exe", "rubeus.exe",
    "sharphound.exe", "nmap.exe", "masscan.exe", "hashcat.exe", "hydra.exe",
    "chisel.exe", "ncat.exe", "meterpreter.exe", "beacon.exe", "nc.exe",
    "nmap", "masscan", "sqlmap", "hydra", "msfconsole", "responder",
    "crackmapexec", "socat", "tcpdump", "linpeas.sh",
]

# ── Countries ────────────────────────────────────────────────
COUNTRIES = [
    "Russia", "China", "North Korea", "Iran", "Brazil", "Romania",
    "Ukraine", "India", "Nigeria", "Germany", "United States", "France",
    "United Kingdom", "Netherlands", "Canada", "Australia", "Japan",
    "South Korea", "Turkey", "Indonesia", "Poland", "Czech Republic",
    "Bulgaria", "Moldova", "Kazakhstan", "Belarus", "Taiwan",
]

# ── Auth-specific ────────────────────────────────────────────
AUTH_FAILURE_REASONS = [
    "Invalid password", "Account locked out", "Account disabled",
    "Password expired", "Unknown username", "KDC_ERR_PREAUTH_FAILED",
    "STATUS_LOGON_FAILURE", "NTLM blocked",
]

AUTH_LOGON_TYPES = [
    ("interactive", "2"), ("network", "3"), ("batch", "4"),
    ("service", "5"), ("remote_interactive", "10"), ("cached_interactive", "11"),
]

AUTH_PROVIDERS = [
    "Windows Security", "Active Directory", "Kerberos", "NTLM",
    "OAuth2", "Azure AD", "Okta",
]

AUTH_APPLICATIONS = [
    "Windows Logon", "RDP Gateway", "VPN Portal", "SSH",
    "AWS Console", "Azure Portal", "Kibana",
]

# ── Network ports ────────────────────────────────────────────
COMMON_PORTS = [
    (22, "ssh"), (25, "smtp"), (53, "dns"), (80, "http"), (110, "pop3"),
    (135, "msrpc"), (143, "imap"), (389, "ldap"), (443, "https"),
    (445, "smb"), (636, "ldaps"), (1433, "mssql"), (3306, "mysql"),
    (3389, "rdp"), (5432, "postgresql"), (5985, "winrm"), (6379, "redis"),
    (8080, "http-alt"), (8443, "https-alt"), (9200, "elasticsearch"),
    (27017, "mongodb"),
]

SUSPICIOUS_PORTS = [
    (4444, "meterpreter"), (1337, "leet"), (9001, "tor"), (31337, "elite"),
    (6667, "irc"), (1080, "socks"), (3128, "proxy"), (5555, "adb"),
    (12345, "netbus"),
]

# ── Firewall ─────────────────────────────────────────────────
FW_VENDORS = [
    ("Palo Alto", "PAN-OS 11.1"), ("Fortinet", "FortiOS 7.4"),
    ("Cisco", "ASA 9.18"), ("Check Point", "R81.20"),
    ("Sophos", "SFOS 20"), ("pfSense", "2.7.2"), ("Juniper", "SRX 23.2"),
]

FW_ZONES = [
    ("trust", "untrust"), ("internal", "external"), ("lan", "wan"),
    ("dmz", "external"), ("servers", "internet"), ("users", "internet"),
    ("guest", "internet"),
]

FW_HOSTNAMES = [
    "FW-EDGE-01", "FW-EDGE-02", "FW-CORE-01",
    "FW-DMZ-01", "FW-VPN-01", "FW-WAF-01",
]

# ── OS families ──────────────────────────────────────────────
OS_WINDOWS = [
    ("windows", "Windows 10 22H2"), ("windows", "Windows 11 23H2"),
    ("windows", "Windows Server 2019"), ("windows", "Windows Server 2022"),
]

OS_LINUX = [
    ("linux", "Ubuntu 22.04"), ("linux", "RHEL 9.3"),
    ("linux", "Debian 12"), ("linux", "Amazon Linux 2023"),
]

OS_ALL = OS_WINDOWS + OS_LINUX


def pick_os(hint=None):
    if hint == "windows":
        return random.choice(OS_WINDOWS)
    if hint == "linux":
        return random.choice(OS_LINUX)
    return random.choice(OS_ALL)


# ── User agents ──────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0",
    "python-requests/2.31.0", "curl/8.4.0", "Go-http-client/2.0",
    "PowerShell/7.4.0",
]

# ── Suspicious file paths ───────────────────────────────────
SUSPICIOUS_PATHS = [
    "C:\\Temp\\", "C:\\Users\\Public\\", "C:\\Windows\\Temp\\",
    "C:\\ProgramData\\",
    "/tmp/", "/var/tmp/", "/dev/shm/", "/home/.hidden/", "/opt/.cache/",
]
