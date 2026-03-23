"""Network log generator."""

import random
from .pools import (
    INTERNAL_IPS, EXTERNAL_IPS, MALICIOUS_IPS, HOSTNAMES, COUNTRIES,
    COMMON_PORTS, SUSPICIOUS_PORTS, USER_AGENTS, pick_os,
)
from .helpers import random_timestamp, random_agent_version


def generate(index: str, ts: str = None) -> dict:
    src = random.choice(INTERNAL_IPS)
    suspicious = random.random() < 0.1
    dst = random.choice(MALICIOUS_IPS) if suspicious else random.choice(EXTERNAL_IPS)

    if suspicious and random.random() < 0.4:
        port, proto = random.choice(SUSPICIOUS_PORTS)
    else:
        port, proto = random.choice(COMMON_PORTS)

    bytes_out = random.randint(500_000, 50_000_000) if suspicious else random.randint(64, 500_000)
    bytes_in = random.randint(64, 50_000) if suspicious else random.randint(64, 500_000)
    os_fam, _ = pick_os()

    return {
        "_index": index,
        "_source": {
            "@timestamp": ts or random_timestamp(),
            "event.category": "network",
            "event.type": "connection",
            "event.outcome": "success",
            "source.ip": src,
            "source.port": random.randint(1024, 65535),
            "source.bytes": bytes_out,
            "destination.ip": dst,
            "destination.port": port,
            "destination.bytes": bytes_in,
            "destination.geo.country_name": random.choice(COUNTRIES),
            "network.transport": random.choice(["tcp", "udp", "tcp"]),
            "network.bytes": bytes_out + bytes_in,
            "network.direction": "outbound",
            "network.protocol": proto,
            "host.name": random.choice(HOSTNAMES),
            "host.os.family": os_fam,
            "user_agent.original": (
                random.choice(USER_AGENTS) if port in [80, 443, 8080, 8443] else None
            ),
            "agent.type": random.choice(["packetbeat", "elastic-agent"]),
            "agent.version": random_agent_version(),
            "tags": (
                (["suspicious"] if suspicious else [])
                + (["encrypted"] if port in [443, 8443] else [])
            ),
            "message": f"Conn {src}->{dst}:{port} {bytes_out + bytes_in}B",
        },
    }
