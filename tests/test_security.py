import os
import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import patch, mock_open

from securelaunch import database
from securelaunch.security import (
    OWASP_CATEGORIES,
    alert_fingerprint,
    classify_alert,
    compare_findings,
    hash_password,
    normalize_domain,
    validate_target_url,
    verify_password,
)
from securelaunch.zap import ScanError, verify_ownership


class PasswordTests(unittest.TestCase):
    def test_password_hash_verifies_without_storing_plaintext(self):
        password = "correct horse battery staple"
        encoded = hash_password(password)
        self.assertNotIn(password, encoded)
        self.assertTrue(verify_password(password, encoded))
        self.assertFalse(verify_password("incorrect", encoded))


class TargetValidationTests(unittest.TestCase):
    def test_normalizes_hostname(self):
        self.assertEqual(normalize_domain(" Example.COM. "), "example.com")

    def test_rejects_non_hostnames_and_ip_addresses(self):
        for value in ("https://example.com", "localhost", "127.0.0.1", "example.com/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)

    def test_target_must_be_exact_verified_host_and_standard_port(self):
        self.assertEqual(
            validate_target_url("https://example.com/account", "example.com"),
            "https://example.com/account",
        )
        for url in (
            "https://other.example.com/",
            "https://example.com:8443/",
            "https://example.com:80/",
            "http://example.com:443/",
            "https://user@example.com/",
            "https://example.com/?next=anything",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_target_url(url, "example.com")


class FindingTests(unittest.TestCase):
    def test_cwe_metadata_maps_to_top_10_2025(self):
        self.assertEqual(classify_alert({"cweid": "79"}), OWASP_CATEGORIES[4])
        self.assertEqual(classify_alert({"cweid": "352"}), OWASP_CATEGORIES[0])

    def test_unmapped_alert_remains_for_manual_review(self):
        self.assertEqual(classify_alert({"alert": "Novel alert"}), "Needs review")

    def test_comparison_detects_new_resolved_and_unchanged(self):
        previous = [
            {"pluginId": "1", "url": "https://example.com/old", "param": ""},
            {"pluginId": "2", "url": "https://example.com/same", "param": "q"},
        ]
        current = [
            {"pluginId": "2", "url": "https://example.com/same", "param": "q"},
            {"pluginId": "3", "url": "https://example.com/new", "param": ""},
        ]
        result = compare_findings(previous, current)
        self.assertEqual(result["unchanged"], 1)
        self.assertEqual(result["new"], [current[1]])
        self.assertEqual(result["resolved"], [previous[0]])

    def test_finding_identity_ignores_url_host_but_keeps_path_and_parameter(self):
        first = {"pluginId": "1", "url": "https://example.com/a?b=1", "param": "q"}
        same = {"pluginId": "1", "url": "http://example.org/a?b=1", "param": "q"}
        changed = {"pluginId": "1", "url": "https://example.com/b?b=1", "param": "q"}
        self.assertEqual(alert_fingerprint(first), alert_fingerprint(same))
        self.assertNotEqual(alert_fingerprint(first), alert_fingerprint(changed))


class OwnershipVerificationTests(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_verifies_exact_dns_txt_value(self, urlopen):
        response = mock_open(
            read_data=json.dumps(
                {
                    "Status": 0,
                    "Answer": [
                        {
                            "type": 16,
                            "data": '"securelaunch-verification=expected-token"',
                        }
                    ],
                }
            ).encode()
        ).return_value
        urlopen.return_value.__enter__.return_value = response
        self.assertTrue(verify_ownership("example.com", "expected-token"))
        request = urlopen.call_args.args[0]
        self.assertIn("_securelaunch-challenge.example.com", request.full_url)

    @patch("urllib.request.urlopen")
    def test_wrong_txt_value_does_not_verify(self, urlopen):
        response = mock_open(
            read_data=json.dumps(
                {"Status": 0, "Answer": [{"type": 16, "data": '"some-other-token"'}]}
            ).encode()
        ).return_value
        urlopen.return_value.__enter__.return_value = response
        self.assertFalse(verify_ownership("example.com", "expected-token"))

    @patch("urllib.request.urlopen")
    def test_dns_lookup_failure_explains_which_record_is_missing(self, urlopen):
        response = mock_open(read_data=json.dumps({"Status": 3}).encode()).return_value
        urlopen.return_value.__enter__.return_value = response
        with self.assertRaisesRegex(ScanError, "_securelaunch-challenge.example.com"):
            verify_ownership("example.com", "expected-token")


class DatabaseTests(unittest.TestCase):
    def test_schema_initializes_and_user_data_isolated_by_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "test.sqlite3")
            with patch.dict(os.environ, {"SECURELAUNCH_DB": path}):
                database.initialize()
                with database.connect() as db:
                    first = db.execute(
                        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                        ("first", "first@example.com", "hash"),
                    ).lastrowid
                    second = db.execute(
                        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                        ("second", "second@example.com", "hash"),
                    ).lastrowid
                    db.execute(
                        "INSERT INTO sites (user_id, domain, verification_token) VALUES (?, ?, ?)",
                        (first, "example.com", "token"),
                    )
                    self.assertIsNone(
                        db.execute(
                            "SELECT id FROM sites WHERE domain = ? AND user_id = ?",
                            ("example.com", second),
                        ).fetchone()
                    )

    def test_existing_email_accounts_receive_unique_usernames(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "legacy.sqlite3")
            with patch.dict(os.environ, {"SECURELAUNCH_DB": path}):
                with database.connect() as db:
                    db.execute(
                        """CREATE TABLE users (
                            id INTEGER PRIMARY KEY,
                            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                            password_hash TEXT NOT NULL,
                            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                        )"""
                    )
                    db.executemany(
                        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                        [
                            ("same@example.com", "first"),
                            ("same@another.example", "second"),
                        ],
                    )
                database.initialize()
                with database.connect() as db:
                    usernames = [
                        row["username"]
                        for row in db.execute("SELECT username FROM users ORDER BY id")
                    ]
                self.assertEqual(usernames[0], "same")
                self.assertNotEqual(usernames[0], usernames[1])


if __name__ == "__main__":
    unittest.main()
