"""Log event generators — one module per log category."""

from .auth import generate as gen_auth
from .network import generate as gen_network
from .endpoint import generate as gen_endpoint
from .dns import generate as gen_dns
from .firewall import generate as gen_firewall

GENERATORS = {
    "auth": gen_auth,
    "network": gen_network,
    "endpoint": gen_endpoint,
    "dns": gen_dns,
    "firewall": gen_firewall,
}
