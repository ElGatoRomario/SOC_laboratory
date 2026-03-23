"""Elasticsearch connection helpers and data-stream management."""

from elasticsearch import Elasticsearch


def create_client(cfg: dict) -> Elasticsearch:
    """Build an Elasticsearch client from app config."""
    kw = dict(
        verify_certs=cfg.get("verify_certs", True),
        ssl_show_warn=False,
        request_timeout=120,
        retry_on_timeout=True,
        max_retries=3,
    )
    ca = cfg.get("ca_cert", "")
    if ca:
        kw["ca_certs"] = ca
    if cfg.get("auth_method") == "apikey" and cfg.get("api_key"):
        kw["api_key"] = cfg["api_key"]
    else:
        kw["basic_auth"] = (cfg.get("es_user", ""), cfg.get("es_password", ""))
    return Elasticsearch(cfg["es_url"], **kw)


def ensure_data_stream(es: Elasticsearch, index_name: str, log_fn=None) -> bool:
    """Create index template + data stream if they don't exist."""
    tpl_name = f"tpl-ds-{index_name}"
    log = log_fn or (lambda m: None)

    try:
        existing = es.indices.get_index_template(name=tpl_name)
        if existing and existing.get("index_templates"):
            log(f"  ℹ Template '{tpl_name}' ya existe.")
            return True
    except Exception:
        pass

    body = {
        "index_patterns": [index_name],
        "data_stream": {},
        "priority": 200,
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "event.category": {"type": "keyword"},
                    "event.type": {"type": "keyword"},
                    "event.action": {"type": "keyword"},
                    "event.outcome": {"type": "keyword"},
                    "source.ip": {"type": "ip"},
                    "destination.ip": {"type": "ip"},
                    "host.name": {"type": "keyword"},
                    "user.name": {"type": "keyword"},
                    "message": {"type": "text"},
                }
            },
        },
    }
    try:
        es.indices.put_index_template(name=tpl_name, body=body)
        log(f"  ✅ Template '{tpl_name}' creado.")
    except Exception as ex:
        log(f"  ❌ Error template: {ex}")
        return False

    try:
        es.indices.create_data_stream(name=index_name)
        log(f"  ✅ Data stream '{index_name}' creado.")
    except Exception as ex:
        if "already_exists" in str(ex):
            log(f"  ℹ Data stream ya existe.")
        else:
            log(f"  ⚠ {ex}")
    return True


def prepare_for_data_stream(doc: dict) -> dict:
    """Adapt a document for data-stream ingestion (op_type=create, no _id)."""
    ds_doc = dict(doc)
    ds_doc.pop("_id", None)
    ds_doc["_op_type"] = "create"
    return ds_doc
