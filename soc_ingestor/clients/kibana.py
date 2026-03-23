"""Kibana HTTP API client — Spaces, Detection Engine, Alerts."""

import json
import ssl
import base64
import urllib.request
import urllib.error


class KibanaAPI:
    """Lightweight Kibana REST client using only stdlib."""

    def __init__(self, url: str, auth_method="basic", api_key="",
                 user="", password="", verify=True, ca=""):
        self.url = url.rstrip("/")
        self.auth_method = auth_method
        self.api_key = api_key
        self.user = user
        self.pw = password
        self.ctx = ssl.create_default_context()
        if ca:
            self.ctx.load_verify_locations(ca)
        if not verify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _headers(self) -> dict:
        h = {
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
            "elastic-api-version": "2023-10-31",
        }
        if self.auth_method == "apikey" and self.api_key:
            h["Authorization"] = f"ApiKey {self.api_key}"
        else:
            cred = base64.b64encode(f"{self.user}:{self.pw}".encode()).decode()
            h["Authorization"] = f"Basic {cred}"
        return h

    def _request(self, method: str, path: str, body=None):
        url = f"{self.url}{path}"
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            resp = urllib.request.urlopen(req, context=self.ctx, timeout=30)
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", "replace")
            raise Exception(f"HTTP {e.code}: {err_body[:300]}")

    # ── Public API ───────────────────────────────────────────

    def test_connection(self) -> dict:
        return self._request("GET", "/api/status")

    def list_spaces(self) -> list:
        return self._request("GET", "/api/spaces/space")

    def _space_prefix(self, space_id: str) -> str:
        return "" if space_id == "default" else f"/s/{space_id}"

    def create_rule(self, space_id: str, rule_body: dict) -> dict:
        return self._request("POST", f"{self._space_prefix(space_id)}/api/detection_engine/rules", rule_body)

    def find_rules(self, space_id: str, per_page=100) -> dict:
        return self._request(
            "GET",
            f"{self._space_prefix(space_id)}/api/detection_engine/rules/_find"
            f"?per_page={per_page}&sort_field=name&sort_order=asc",
        )

    def delete_rule(self, space_id: str, rule_id: str) -> dict:
        return self._request(
            "DELETE",
            f"{self._space_prefix(space_id)}/api/detection_engine/rules?rule_id={rule_id}",
        )

    def search_alerts(self, space_id: str, size=200) -> dict:
        body = {"query": {"match_all": {}}, "size": size, "sort": [{"@timestamp": {"order": "desc"}}]}
        return self._request(
            "POST",
            f"{self._space_prefix(space_id)}/api/detection_engine/signals/search",
            body,
        )
