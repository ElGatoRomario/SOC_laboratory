"""Authentication log generator."""

import random
from .pools import (
    USERS_ALL, USERS_ADMIN, HOSTNAMES, INTERNAL_IPS, EXTERNAL_IPS,
    MALICIOUS_IPS, COUNTRIES, AUTH_FAILURE_REASONS, AUTH_LOGON_TYPES,
    AUTH_PROVIDERS, AUTH_APPLICATIONS, pick_os,
)
from .helpers import random_timestamp, random_agent_version


def generate(index: str, ts: str = None) -> dict:
    user = random.choice(USERS_ALL)
    host = random.choice(HOSTNAMES)
    src = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
    failed = random.random() < 0.15
    brute = failed and random.random() < 0.25
    logon_type, _ = random.choice(AUTH_LOGON_TYPES)
    os_fam, os_ver = pick_os()

    if brute:
        src = random.choice(MALICIOUS_IPS + EXTERNAL_IPS[:10])
        user = random.choice(USERS_ADMIN)

    return {
        "_index": index,
        "_source": {
            "@timestamp": ts or random_timestamp(),
            "event.category": "authentication",
            "event.type": "start",
            "event.outcome": "failure" if failed else "success",
            "event.action": "logon-failed" if failed else "logon-success",
            "event.provider": random.choice(AUTH_PROVIDERS),
            "event.reason": random.choice(AUTH_FAILURE_REASONS) if failed else None,
            "user.name": user,
            "source.ip": src,
            "source.port": random.randint(1024, 65535),
            "source.geo.country_name": (
                random.choice(COUNTRIES) if src in EXTERNAL_IPS + MALICIOUS_IPS else None
            ),
            "host.name": host,
            "host.os.family": os_fam,
            "host.os.full": os_ver,
            "application.name": random.choice(AUTH_APPLICATIONS),
            "agent.type": random.choice(["winlogbeat", "filebeat", "elastic-agent"]),
            "agent.version": random_agent_version(),
            "tags": (["brute_force"] if brute else []) + (["failed_login"] if failed else []),
            "message": (
                f"{'Brute: ' if brute else ''}User {user} "
                f"{'failed' if failed else 'ok'} on {host} via {logon_type}"
            ),
        },
    }
