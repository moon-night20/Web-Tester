import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from .security import alert_fingerprint, classify_alert


class ScanError(Exception):
    pass


class ZapClient:
    def __init__(self):
        self.base_url = os.environ.get("ZAP_API_URL", "http://127.0.0.1:8080").rstrip("/")
        self.api_key = os.environ.get("ZAP_API_KEY", "")
        self.timeout = 20
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _api(self, component, action, operation, params=None):
        query = dict(params or {})
        if self.api_key:
            query["apikey"] = self.api_key
        url = "{}/JSON/{}/{}/?{}".format(
            self.base_url, component, action + "/" + operation, urllib.parse.urlencode(query)
        )
        request = urllib.request.Request(url)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read(2_000_000)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ScanError("Could not reach the configured OWASP ZAP API.") from exc
        try:
            result = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScanError("OWASP ZAP returned an invalid API response.") from exc
        if isinstance(result, dict) and result.get("code") not in (None, "ok"):
            raise ScanError("OWASP ZAP rejected the scan request.")
        return result

    def scan(self, target_url, domain, scan_id):
        context = "securelaunch-{}".format(scan_id)
        scope = r"^https?://" + re.escape(domain) + r"(?::(?:80|443))?(?:/.*)?$"
        try:
            self._api("core", "view", "version")
        except ScanError as exc:
            raise ScanError(
                "OWASP ZAP is unavailable. Start the ZAP daemon and configure ZAP_API_URL."
            ) from exc
        self._api("context", "action", "newContext", {"contextName": context})
        self._api(
            "context",
            "action",
            "includeInContext",
            {"contextName": context, "regex": scope},
        )
        result = self._api(
            "spider",
            "action",
            "scan",
            {
                "url": target_url,
                "contextName": context,
                "recurse": "true",
                "subtreeOnly": "true",
                "maxChildren": "100",
            },
        )
        spider_id = result.get("scan")
        if spider_id is None:
            raise ScanError("OWASP ZAP did not return a spider scan identifier.")
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            status = self._api("spider", "view", "status", {"scanId": spider_id})
            if int(status.get("status", -1)) >= 100:
                break
            time.sleep(1)
        else:
            raise ScanError("The ZAP spider exceeded the 30-minute scan limit.")
        while time.monotonic() < deadline:
            pending = self._api("pscan", "view", "recordsToScan")
            if int(pending.get("recordsToScan", -1)) == 0:
                break
            time.sleep(1)
        else:
            raise ScanError("ZAP passive analysis did not finish within the scan limit.")
        alerts = []
        start = 0
        while True:
            page = self._api(
                "alert",
                "view",
                "alerts",
                {
                    "baseurl": target_url,
                    "contextName": context,
                    "start": start,
                    "count": 500,
                },
            )
            batch = page.get("alerts", [])
            alerts.extend(batch)
            if len(batch) < 500:
                break
            start += len(batch)
        findings = []
        seen = set()
        for alert in alerts:
            fingerprint = alert_fingerprint(alert)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            findings.append(
                {
                    "fingerprint": fingerprint,
                    "category": classify_alert(alert),
                    "alert_json": json.dumps(alert, separators=(",", ":")),
                }
            )
        return findings


def verify_ownership(domain, token):
    name = "_securelaunch-challenge." + domain
    params = urllib.parse.urlencode({"name": name, "type": "TXT"})
    request = urllib.request.Request(
        "https://cloudflare-dns.com/dns-query?" + params,
        headers={"accept": "application/dns-json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read(100_000).decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScanError(
            "The DNS verification service could not be reached. Check your internet "
            "connection and try again."
        ) from exc
    expected = "securelaunch-verification=" + token
    if payload.get("Status") not in (0, None):
        raise ScanError(
            "DNS could not find a TXT record for {}. Make sure the record is added "
            "to the domain's active DNS provider, then wait for it to publish.".format(name)
        )
    records = payload.get("Answer", [])
    for record in records:
        value = record.get("data", "")
        if record.get("type") == 16 and value.replace('"', "").strip() == expected:
            return True
    return False


def assert_public_dns(domain):
    addresses = set()
    for record_type in ("A", "AAAA"):
        params = urllib.parse.urlencode({"name": domain, "type": record_type})
        request = urllib.request.Request(
            "https://cloudflare-dns.com/dns-query?" + params,
            headers={"accept": "application/dns-json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read(100_000).decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScanError("Could not check the website's public DNS records.") from exc
        addresses.update(
            record.get("data", "")
            for record in payload.get("Answer", [])
            if record.get("type") in (1, 28)
        )
    if not addresses:
        raise ScanError("The verified hostname does not currently have public A or AAAA records.")
    try:
        parsed = {ipaddress.ip_address(address) for address in addresses}
    except ValueError as exc:
        raise ScanError("The hostname returned an invalid IP address.") from exc
    if any(not address.is_global for address in parsed):
        raise ScanError("Scanning hostnames that resolve to private or reserved IP addresses is blocked.")
