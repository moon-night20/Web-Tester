import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import urllib.parse


OWASP_CATEGORIES = (
    "A01:2025 Broken Access Control",
    "A02:2025 Security Misconfiguration",
    "A03:2025 Software Supply Chain Failures",
    "A04:2025 Cryptographic Failures",
    "A05:2025 Injection",
    "A06:2025 Insecure Design",
    "A07:2025 Authentication Failures",
    "A08:2025 Software or Data Integrity Failures",
    "A09:2025 Security Logging & Alerting Failures",
    "A10:2025 Mishandling of Exceptional Conditions",
)

_CATEGORY_TERMS = (
    (OWASP_CATEGORIES[0], ("access control", "directory browsing", "path traversal", "idor", "csrf", "cross-site request forgery")),
    (OWASP_CATEGORIES[1], ("security misconfiguration", "http header", "cookie without", "server leaks", "directory listing", "cors")),
    (OWASP_CATEGORIES[2], ("outdated component", "vulnerable component", "known vulnerable", "third-party", "third party", "software composition")),
    (OWASP_CATEGORIES[3], ("weak encryption", "cleartext", "clear text", "insecure tls", "weak cipher", "sensitive information in url")),
    (OWASP_CATEGORIES[4], ("injection", "cross-site scripting", "sql", "command injection", "xml external")),
    (OWASP_CATEGORIES[5], ("insecure design",)),
    (OWASP_CATEGORIES[6], ("authentication", "session fixation", "weak password", "password")),
    (OWASP_CATEGORIES[7], ("integrity", "unsigned", "subresource integrity", "deserialization")),
    (OWASP_CATEGORIES[8], ("logging", "audit", "log injection")),
    (OWASP_CATEGORIES[9], ("error", "exception", "stack trace", "unhandled")),
)

_CWE_CATEGORIES = {
    22: OWASP_CATEGORIES[0],
    73: OWASP_CATEGORIES[0],
    284: OWASP_CATEGORIES[0],
    285: OWASP_CATEGORIES[0],
    352: OWASP_CATEGORIES[0],
    522: OWASP_CATEGORIES[6],
    601: OWASP_CATEGORIES[0],
    693: OWASP_CATEGORIES[1],
    732: OWASP_CATEGORIES[0],
    798: OWASP_CATEGORIES[6],
    295: OWASP_CATEGORIES[3],
    319: OWASP_CATEGORIES[3],
    326: OWASP_CATEGORIES[3],
    327: OWASP_CATEGORIES[3],
    330: OWASP_CATEGORIES[3],
    79: OWASP_CATEGORIES[4],
    89: OWASP_CATEGORIES[4],
    78: OWASP_CATEGORIES[4],
    611: OWASP_CATEGORIES[4],
    829: OWASP_CATEGORIES[7],
    494: OWASP_CATEGORIES[7],
    532: OWASP_CATEGORIES[8],
    778: OWASP_CATEGORIES[8],
    248: OWASP_CATEGORIES[9],
    476: OWASP_CATEGORIES[9],
}


def new_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
    return salt.hex() + "$" + derived.hex()


def verify_password(password, encoded):
    try:
        salt_hex, digest_hex = encoded.split("$", 1)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 310000
        ).hex()
        return hmac.compare_digest(actual, digest_hex)
    except (ValueError, TypeError):
        return False


def normalize_domain(value):
    domain = (value or "").strip().rstrip(".").lower()
    if not domain or len(domain) > 253 or "://" in domain or "/" in domain:
        raise ValueError("Enter a hostname such as example.com, without a scheme or path.")
    try:
        domain.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Use the ASCII/Punycode form of the hostname.") from exc
    labels = domain.split(".")
    if len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Enter a valid public hostname.")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("IP addresses are not supported; verify a public hostname instead.")


def validate_target_url(value, verified_domain):
    value = (value or "").strip()
    if any(ord(character) < 33 for character in value):
        raise ValueError("The scan URL contains invalid whitespace or control characters.")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("The target must be an HTTP or HTTPS URL.")
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("Credentials, query strings, and fragments are not allowed in scan URLs.")
    if parsed.hostname.lower().rstrip(".") != verified_domain:
        raise ValueError("The scan URL must use the exact verified hostname.")
    expected_port = 443 if parsed.scheme == "https" else 80
    if port not in (None, expected_port):
        raise ValueError("Use the standard port for the selected HTTP or HTTPS scheme.")
    if parsed.path and not parsed.path.startswith("/"):
        raise ValueError("The target path is invalid.")
    return urllib.parse.urlunsplit((parsed.scheme, verified_domain, parsed.path or "/", "", ""))


def classify_alert(alert):
    cwe = alert.get("cweid")
    try:
        mapped = _CWE_CATEGORIES.get(int(cwe))
    except (TypeError, ValueError):
        mapped = None
    if mapped:
        return mapped
    text = " ".join(str(alert.get(field, "")) for field in ("alert", "name")).lower()
    for category, terms in _CATEGORY_TERMS:
        if any(term in text for term in terms):
            return category
    return "Needs review"


def alert_fingerprint(alert):
    parsed = urllib.parse.urlsplit(str(alert.get("url", "")))
    identity = {
        "plugin": str(alert.get("pluginId") or alert.get("alert") or alert.get("name", "")),
        "path": parsed.path or "/",
        "param": str(alert.get("param", "")),
        "method": str(alert.get("method", "")),
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def compare_findings(previous, current):
    previous_by_id = {alert_fingerprint(item): item for item in previous}
    current_by_id = {alert_fingerprint(item): item for item in current}
    previous_ids = set(previous_by_id)
    current_ids = set(current_by_id)
    return {
        "new": [item for item in current if alert_fingerprint(item) not in previous_ids],
        "resolved": [item for item in previous if alert_fingerprint(item) not in current_ids],
        "unchanged": len(previous_ids & current_ids),
    }
