import http.cookies
import json
import logging
import mimetypes
import os
import re
import secrets
import sqlite3
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import database
from .security import (
    OWASP_CATEGORIES,
    compare_findings,
    hash_password,
    hash_token,
    new_token,
    normalize_domain,
    validate_target_url,
    verify_password,
)
from .zap import ScanError, ZapClient, assert_public_dns, verify_ownership


LOG = logging.getLogger("securelaunch")
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
SCAN_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="zap-scan")
SESSION_SECONDS = 7 * 24 * 60 * 60


class AuthenticationError(Exception):
    pass


def _row_dict(row):
    return dict(row) if row is not None else None


def _start_scan(scan_id, site, target_url):
    try:
        assert_public_dns(site["domain"])
        findings = ZapClient().scan(target_url, site["domain"], scan_id)
        with database.connect() as db:
            db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            db.executemany(
                """INSERT INTO findings (scan_id, fingerprint, category, alert_json)
                   VALUES (?, ?, ?, ?)""",
                [
                    (scan_id, item["fingerprint"], item["category"], item["alert_json"])
                    for item in findings
                ],
            )
            db.execute(
                "UPDATE scans SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (scan_id,),
            )
    except Exception as exc:
        LOG.exception("Scan %s failed", scan_id)
        message = str(exc) if isinstance(exc, (ScanError, ValueError)) else "The scan failed unexpectedly."
        with database.connect() as db:
            db.execute(
                "UPDATE scans SET status = 'failed', error = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (message[:500], scan_id),
            )


class Handler(BaseHTTPRequestHandler):
    server_version = "SecureLaunch/0.1"

    def log_message(self, fmt, *args):
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def _headers(self, content_type="application/json; charset=utf-8", status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("Cache-Control", "no-store")

    def _json(self, data, status=200, cookie=None):
        body = json.dumps(data, separators=(",", ":")).encode("utf-8")
        self._headers(status=status)
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message, status=400):
        self._json({"error": message}, status)

    def _read_json(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request body.") from exc
        if size < 0 or size > 1_000_000:
            raise ValueError("Request body is too large.")
        try:
            value = json.loads(self.rfile.read(size).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must be valid JSON.") from exc
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object.")
        return value

    def _session(self, require_csrf=False):
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
            token = jar["securelaunch_session"].value
        except (KeyError, http.cookies.CookieError):
            return None
        with database.connect() as db:
            row = db.execute(
                """                SELECT sessions.*, users.email, users.username FROM sessions
                   JOIN users ON users.id = sessions.user_id
                   WHERE token_hash = ? AND expires_at > ?""",
                (hash_token(token), int(time.time())),
            ).fetchone()
        if not row:
            return None
        if require_csrf:
            supplied = self.headers.get("X-CSRF-Token", "")
            if not secrets.compare_digest(hash_token(supplied), row["csrf_hash"]):
                raise PermissionError("Your session token expired. Sign in again.")
        return row

    def _cookie(self, token, clear=False):
        parts = ["securelaunch_session=" + ("" if clear else token), "Path=/", "HttpOnly", "SameSite=Strict"]
        parts.append("Max-Age=0" if clear else "Max-Age={}".format(SESSION_SECONDS))
        if os.environ.get("SECURE_COOKIE") == "1":
            parts.append("Secure")
        return "; ".join(parts)

    def _issue_session(self, db, user_id):
        token, csrf = new_token(), new_token()
        db.execute(
            "INSERT INTO sessions (token_hash, csrf_hash, user_id, expires_at) VALUES (?, ?, ?, ?)",
            (hash_token(token), hash_token(csrf), user_id, int(time.time()) + SESSION_SECONDS),
        )
        return token, csrf

    def _owned_site(self, db, user_id, site_id):
        site = db.execute(
            "SELECT * FROM sites WHERE id = ? AND user_id = ?", (site_id, user_id)
        ).fetchone()
        if not site:
            raise LookupError("Website not found.")
        return site

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/":
            self._serve_static("index.html")
            return
        if path in ("/app.js", "/styles.css"):
            self._serve_static(path.lstrip("/"))
            return
        if path == "/api/me":
            session = self._session()
            if not session:
                self._error("Sign in to continue.", 401)
            else:
                csrf = new_token()
                with database.connect() as db:
                    db.execute(
                        "UPDATE sessions SET csrf_hash = ? WHERE token_hash = ?",
                        (hash_token(csrf), session["token_hash"]),
                    )
                self._json(
                    {"username": session["username"], "email": session["email"], "csrf": csrf}
                )
            return
        if path == "/api/sites":
            session = self._session()
            if not session:
                self._error("Sign in to continue.", 401)
                return
            with database.connect() as db:
                sites = db.execute(
                    """SELECT id, domain, verification_token, verified_at, created_at
                       FROM sites WHERE user_id = ? ORDER BY id DESC""",
                    (session["user_id"],),
                ).fetchall()
            self._json({"sites": [_row_dict(site) for site in sites]})
            return
        if path == "/api/scans":
            session = self._session()
            if not session:
                self._error("Sign in to continue.", 401)
                return
            with database.connect() as db:
                scans = db.execute(
                    """SELECT scans.id, scans.site_id, scans.target_url, scans.status,
                              scans.error, scans.started_at, scans.completed_at, sites.domain
                       FROM scans JOIN sites ON sites.id = scans.site_id
                       WHERE scans.user_id = ? ORDER BY scans.id DESC LIMIT 100""",
                    (session["user_id"],),
                ).fetchall()
                results = []
                for scan in scans:
                    item = _row_dict(scan)
                    item["findings"] = self._findings(db, scan["id"])
                    results.append(item)
            self._json({"scans": results, "categories": list(OWASP_CATEGORIES)})
            return
        match = re.fullmatch(r"/api/scans/(\d+)/comparison", path)
        if match:
            session = self._session()
            if not session:
                self._error("Sign in to continue.", 401)
                return
            scan_id = int(match.group(1))
            with database.connect() as db:
                current = db.execute(
                    "SELECT * FROM scans WHERE id = ? AND user_id = ?",
                    (scan_id, session["user_id"]),
                ).fetchone()
                if not current:
                    self._error("Scan not found.", 404)
                    return
                previous = db.execute(
                    """SELECT * FROM scans WHERE site_id = ? AND user_id = ?
                       AND id < ? AND status = 'completed' ORDER BY id DESC LIMIT 1""",
                    (current["site_id"], session["user_id"], scan_id),
                ).fetchone()
                if current["status"] != "completed":
                    self._error("Comparison is available after this scan completes.", 409)
                    return
                current_alerts = self._alert_rows(db, scan_id)
                previous_alerts = self._alert_rows(db, previous["id"]) if previous else []
            comparison = compare_findings(previous_alerts, current_alerts)
            self._json(
                {
                    "previousScanId": previous["id"] if previous else None,
                    "new": comparison["new"],
                    "resolved": comparison["resolved"],
                    "unchanged": comparison["unchanged"],
                }
            )
            return
        self._error("Not found.", 404)

    @staticmethod
    def _alert_rows(db, scan_id):
        alerts = []
        for row in db.execute(
            "SELECT category, alert_json FROM findings WHERE scan_id = ?", (scan_id,)
        ):
            alert = json.loads(row["alert_json"])
            alert["category"] = row["category"]
            alerts.append(alert)
        return alerts

    @classmethod
    def _findings(cls, db, scan_id):
        grouped = {category: 0 for category in OWASP_CATEGORIES}
        grouped["Needs review"] = 0
        findings = []
        for row in db.execute(
            "SELECT category, alert_json FROM findings WHERE scan_id = ? ORDER BY category",
            (scan_id,),
        ):
            alert = json.loads(row["alert_json"])
            alert["category"] = row["category"]
            grouped[row["category"]] = grouped.get(row["category"], 0) + 1
            findings.append(alert)
        return {"total": len(findings), "byCategory": grouped, "items": findings}

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        try:
            body = self._read_json()
            if path == "/api/register":
                self._register(body)
            elif path == "/api/login":
                self._login(body)
            elif path == "/api/logout":
                session = self._session(require_csrf=True)
                if session:
                    with database.connect() as db:
                        db.execute("DELETE FROM sessions WHERE token_hash = ?", (session["token_hash"],))
                self._json({"ok": True}, cookie=self._cookie("", clear=True))
            elif path == "/api/sites":
                self._add_site(body)
            else:
                verify_match = re.fullmatch(r"/api/sites/(\d+)/verify", path)
                scan_match = re.fullmatch(r"/api/sites/(\d+)/scans", path)
                if verify_match:
                    self._verify_site(int(verify_match.group(1)))
                elif scan_match:
                    self._create_scan(int(scan_match.group(1)), body)
                else:
                    self._error("Not found.", 404)
        except PermissionError as exc:
            self._error(str(exc), 403)
        except AuthenticationError as exc:
            self._error(str(exc), 401)
        except LookupError as exc:
            self._error(str(exc), 404)
        except (ValueError, ScanError) as exc:
            self._error(str(exc), 400)
        except sqlite3.IntegrityError:
            self._error("That username or email is already registered.", 409)
        except Exception:
            LOG.exception("Request failed")
            self._error("The request could not be completed.", 500)

    def _register(self, body):
        username = str(body.get("username", "")).strip().lower()
        email = str(body.get("email", "")).strip().lower()
        password = body.get("password", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,31}", username):
            raise ValueError(
                "Username must be 3–32 characters and use letters, numbers, dots, underscores, or hyphens."
            )
        if not re.fullmatch(r"[^@\s]{1,128}@[^@\s]{1,190}\.[^@\s]{2,63}", email):
            raise ValueError("Enter a valid email address.")
        if not isinstance(password, str) or not 12 <= len(password) <= 1024:
            raise ValueError("Password must contain 12–1024 characters.")
        with database.connect() as db:
            if db.execute(
                "SELECT 1 FROM users WHERE email = ? OR username = ? COLLATE NOCASE",
                (email, username),
            ).fetchone():
                raise ValueError("That username or email is already registered.")
            user_id = db.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, hash_password(password)),
            ).lastrowid
            token, csrf = self._issue_session(db, user_id)
        self._json(
            {"username": username, "email": email, "csrf": csrf},
            201,
            self._cookie(token),
        )

    def _login(self, body):
        identifier = str(body.get("identifier", body.get("email", ""))).strip().lower()
        password = body.get("password", "")
        with database.connect() as db:
            user = db.execute(
                """SELECT id, username, email, password_hash FROM users
                   WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE
                   ORDER BY CASE WHEN username = ? COLLATE NOCASE THEN 0 ELSE 1 END
                   LIMIT 1""",
                (identifier, identifier, identifier),
            ).fetchone()
            if not user or not isinstance(password, str) or not verify_password(
                password, user["password_hash"]
            ):
                raise AuthenticationError("Username/email or password is incorrect.")
            db.execute("DELETE FROM sessions WHERE user_id = ? AND expires_at <= ?", (user["id"], int(time.time())))
            token, csrf = self._issue_session(db, user["id"])
        self._json(
            {"username": user["username"], "email": user["email"], "csrf": csrf},
            cookie=self._cookie(token),
        )

    def _add_site(self, body):
        session = self._session(require_csrf=True)
        if not session:
            raise PermissionError("Sign in to continue.")
        domain = normalize_domain(body.get("domain"))
        token = new_token()
        with database.connect() as db:
            site_id = db.execute(
                """INSERT INTO sites (user_id, domain, verification_token)
                   VALUES (?, ?, ?)""",
                (session["user_id"], domain, token),
            ).lastrowid
        self._json(
            {
                "site": {
                    "id": site_id,
                    "domain": domain,
                    "verification_token": token,
                    "verified_at": None,
                }
            },
            201,
        )

    def _verify_site(self, site_id):
        session = self._session(require_csrf=True)
        if not session:
            raise PermissionError("Sign in to continue.")
        with database.connect() as db:
            site = self._owned_site(db, session["user_id"], site_id)
            domain, token = site["domain"], site["verification_token"]
        if not verify_ownership(domain, token):
            raise ValueError(
                "The TXT record is not visible yet. Add the exact value at "
                "_securelaunch-challenge.{} in the DNS provider for this domain, "
                "wait a few minutes, then select Check DNS again.".format(domain)
            )
        with database.connect() as db:
            db.execute(
                "UPDATE sites SET verified_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
                (site_id, session["user_id"]),
            )
        self._json({"verified": True})

    def _create_scan(self, site_id, body):
        session = self._session(require_csrf=True)
        if not session:
            raise PermissionError("Sign in to continue.")
        with database.connect() as db:
            site = self._owned_site(db, session["user_id"], site_id)
            if not site["verified_at"]:
                raise PermissionError("Verify website ownership before scanning.")
            domain, token = site["domain"], site["verification_token"]
        target_url = validate_target_url(body.get("url") or "https://" + domain, domain)
        if not verify_ownership(domain, token):
            raise PermissionError("Ownership verification is no longer present. Verify the website again.")
        assert_public_dns(domain)
        with database.connect() as db:
            scan_id = db.execute(
                """INSERT INTO scans (site_id, user_id, target_url, status)
                   VALUES (?, ?, ?, 'running')""",
                (site_id, session["user_id"], target_url),
            ).lastrowid
        SCAN_POOL.submit(
            _start_scan,
            scan_id,
            {"domain": domain},
            target_url,
        )
        self._json({"scanId": scan_id, "status": "running"}, 202)

    def _serve_static(self, filename):
        path = (STATIC_DIR / filename).resolve()
        if STATIC_DIR.resolve() not in path.parents or not path.is_file():
            self._error("Not found.", 404)
            return
        body = path.read_bytes()
        self._headers(mimetypes.guess_type(filename)[0] + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    database.initialize()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), Handler)
    LOG.info("SecureLaunch listening on http://%s:%s", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Shutting down")
    finally:
        server.server_close()
        SCAN_POOL.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    main()
