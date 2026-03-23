"""Firewall log generator."""

import random
from .pools import (
    INTERNAL_IPS, EXTERNAL_IPS, MALICIOUS_IPS, COUNTRIES,
    COMMON_PORTS, SUSPICIOUS_PORTS,
    FW_VENDORS, FW_ZONES, FW_HOSTNAMES, pick_os,
)
from .helpers import random_timestamp, random_agent_version


def generate(index: str, ts: str = None) -> dict:
    action = random.choices(["allowed", "denied", "dropped"], weights=[60, 25, 15])[0]
    inbound = random.random() < 0.4

    if inbound:
        src = random.choice(EXTERNAL_IPS + MALICIOUS_IPS[:10])
        dst = random.choice(INTERNAL_IPS)
    else:
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(
            EXTERNAL_IPS + (MALICIOUS_IPS[:5] if random.random() < 0.08 else [])
        )

    port, proto = random.choice(
        COMMON_PORTS + (SUSPICIOUS_PORTS if random.random() < 0.1 else [])
    )
    vendor, product = random.choice(FW_VENDORS)
    zone_src, zone_dst = random.choice(FW_ZONES)
    rule_id = random.randint(100, 9999)

    return {
        "_index": index,
        "_source": {
            "@timestamp": ts or random_timestamp(),
            "event.category": "network",
            "event.type": "connection",
            "event.action": action,
            "event.outcome": "success" if action == "allowed" else "failure",
            "source.ip": src,
            "source.port": random.randint(1024, 65535),
            "source.geo.country_name": random.choice(COUNTRIES) if inbound else None,
            "destination.ip": dst,
            "destination.port": port,
            "network.transport": random.choice(["tcp", "udp"]),
            "network.protocol": proto,
            "network.direction": "inbound" if inbound else "outbound",
            "observer.type": "firewall",
            "observer.vendor": vendor,
            "observer.product": product,
            "observer.ingress.zone": zone_src,
            "observer.egress.zone": zone_dst,
            "rule.id": str(rule_id),
            "rule.name": f"FW-RULE-{rule_id}",
            "host.name": random.choice(FW_HOSTNAMES),
            "agent.type": "filebeat",
            "agent.version": random_agent_version(),
            "tags": (
                (["malicious_ip"] if dst in MALICIOUS_IPS or src in MALICIOUS_IPS else [])
                + (["blocked"] if action != "allowed" else [])
            ),
            "message": f"FW {action} [{zone_src}->{zone_dst}] {src}->{dst}:{port}",
        },
    }
