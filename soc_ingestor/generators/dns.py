"""DNS log generator."""

import random
from .pools import (
    INTERNAL_IPS, HOSTNAMES, DNS_NORMAL, DNS_MALICIOUS, pick_os,
)
from .helpers import random_timestamp, fake_ip, random_dga_domain, random_agent_version


def generate(index: str, ts: str = None) -> dict:
    suspicious = random.random() < 0.08

    if suspicious:
        domain = (random.choice(DNS_MALICIOUS) if random.random() < 0.4
                  else random_dga_domain())
    else:
        domain = random.choice(DNS_NORMAL)

    qtype = random.choices(
        ["A", "AAAA", "TXT", "MX", "CNAME"], weights=[40, 10, 8, 5, 10]
    )[0]
    rcode = random.choices(
        ["NOERROR", "NXDOMAIN", "SERVFAIL"], weights=[85, 10, 5]
    )[0]
    resolved = [fake_ip() for _ in range(random.randint(1, 3))] if rcode == "NOERROR" else []
    is_tunnel = suspicious and (qtype == "TXT" or len(domain) > 40)

    return {
        "_index": index,
        "_source": {
            "@timestamp": ts or random_timestamp(),
            "event.category": "network",
            "event.type": "protocol",
            "event.action": "dns_query",
            "dns.question.name": domain,
            "dns.question.type": qtype,
            "dns.response_code": rcode,
            "dns.resolved_ip": resolved,
            "dns.answers_count": len(resolved),
            "source.ip": random.choice(INTERNAL_IPS),
            "destination.port": 53,
            "host.name": random.choice(HOSTNAMES),
            "network.protocol": "dns",
            "agent.type": random.choice(["packetbeat", "elastic-agent"]),
            "agent.version": random_agent_version(),
            "tags": (
                (["dga_suspect"] if suspicious and not is_tunnel else [])
                + (["dns_tunnel_suspect"] if is_tunnel else [])
                + (["known_malicious_domain"] if suspicious and domain in DNS_MALICIOUS else [])
            ),
            "message": f"DNS {qtype} {domain} -> {rcode}",
        },
    }
