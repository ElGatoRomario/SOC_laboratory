"""Shared helper functions for event generators."""

import random
import uuid
import string
from datetime import datetime, timedelta, timezone

DGA_TLDS = [
    ".xyz", ".tk", ".top", ".cc", ".pw", ".club", ".info",
    ".site", ".online", ".icu", ".monster", ".cfd", ".sbs",
]


def fake_ip() -> str:
    return (f"{random.randint(1, 223)}.{random.randint(0, 255)}"
            f".{random.randint(0, 255)}.{random.randint(1, 254)}")


def random_timestamp(days_back: int = 30) -> str:
    now = datetime.now(timezone.utc)
    delta = timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
        microseconds=random.randint(0, 999999),
    )
    return (now - delta).isoformat()


def now_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def random_sha256() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex[:32]


def random_dga_domain() -> str:
    charset = random.choice([
        string.ascii_lowercase,
        string.ascii_lowercase + string.digits,
        "abcdef0123456789",
    ])
    length = random.randint(12, 25)
    return "".join(random.choices(charset, k=length)) + random.choice(DGA_TLDS)


def random_agent_version() -> str:
    return f"{random.randint(7, 8)}.{random.randint(10, 17)}.{random.randint(0, 3)}"
