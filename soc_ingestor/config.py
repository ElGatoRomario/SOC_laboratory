"""Configuration management — load, save, defaults."""

import json
from pathlib import Path

CFG_PATH = Path.home() / ".soc_ingestor_config.json"

LOG_CATEGORIES = {
    "auth":     {"label": "🔐 Autenticación",  "default_index": "soc-logs-auth"},
    "network":  {"label": "🌐 Network",         "default_index": "soc-logs-network"},
    "endpoint": {"label": "💻 Endpoint",         "default_index": "soc-logs-endpoint"},
    "dns":      {"label": "🔍 DNS",              "default_index": "soc-logs-dns"},
    "firewall": {"label": "🧱 Firewall",         "default_index": "soc-logs-firewall"},
}


def load_config() -> dict:
    if CFG_PATH.exists():
        with open(CFG_PATH) as f:
            return json.load(f)
    return {}


def save_config(cfg: dict) -> None:
    with open(CFG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def get_index(cfg: dict, category: str) -> str:
    return (cfg.get("indices", {})
              .get(category, {})
              .get("name", LOG_CATEGORIES[category]["default_index"]))


def is_data_stream(cfg: dict, category: str) -> bool:
    return cfg.get("indices", {}).get(category, {}).get("data_stream", False)
