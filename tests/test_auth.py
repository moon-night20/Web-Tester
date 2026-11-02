import http.cookiejar
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from securelaunch import database
from securelaunch.server import Handler
from http.server import ThreadingHTTPServer


class AuthenticationFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.environment = patch.dict(
            os.environ,
            {"SECURELAUNCH_DB": os.path.join(self.temp_dir.name, "auth.sqlite3")},
        )
        self.environment.start()
        database.initialize()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = "http://127.0.0.1:{}".format(self.server.server_address[1])
        self.opener = self._opener()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.environment.stop()
        self.temp_dir.cleanup()

    @staticmethod
    def _opener():
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def request(self, path, body=None, opener=None, csrf=None):
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            headers=headers,
            method="POST" if body is not None else "GET",
        )
        try:
            with (opener or self.opener).open(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))

    def test_registration_then_login_by_username_and_email(self):
        status, registered = self.request(
            "/api/register",
            {
                "username": "secure_user",
                "email": "secure-user@example.test",
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(registered["username"], "secure_user")
        self.assertTrue(registered["csrf"])

        username_opener = self._opener()
        status, username_login = self.request(
            "/api/login",
            {"identifier": "SECURE_USER", "password": "correct horse battery staple"},
            username_opener,
        )
        self.assertEqual(status, 200)
        self.assertEqual(username_login["username"], "secure_user")
        self.assertEqual(
            self.request("/api/me", opener=username_opener)[1]["username"],
            "secure_user",
        )

        email_opener = self._opener()
        status, email_login = self.request(
            "/api/login",
            {"identifier": "secure-user@example.test", "password": "correct horse battery staple"},
            email_opener,
        )
        self.assertEqual(status, 200)
        self.assertEqual(email_login["username"], "secure_user")

    def test_bad_password_returns_visible_authentication_error(self):
        self.request(
            "/api/register",
            {
                "username": "secure_user",
                "email": "secure-user@example.test",
                "password": "correct horse battery staple",
            },
        )
        status, result = self.request(
            "/api/login",
            {"identifier": "secure_user", "password": "incorrect password"},
            self._opener(),
        )
        self.assertEqual(status, 401)
        self.assertIn("incorrect", result["error"])

    def test_duplicate_username_is_rejected(self):
        account = {
            "username": "secure_user",
            "email": "secure-user@example.test",
            "password": "correct horse battery staple",
        }
        self.assertEqual(self.request("/api/register", account)[0], 201)
        account["email"] = "another@example.test"
        status, result = self.request("/api/register", account)
        self.assertEqual(status, 400)
        self.assertIn("username", result["error"])

    def test_verified_site_is_marked_ready_after_ownership_check(self):
        _, account = self.request(
            "/api/register",
            {
                "username": "site_owner",
                "email": "site-owner@example.test",
                "password": "correct horse battery staple",
            },
        )
        status, created = self.request(
            "/api/sites", {"domain": "example.com"}, csrf=account["csrf"]
        )
        self.assertEqual(status, 201)
        site_id = created["site"]["id"]

        with patch("securelaunch.server.verify_ownership", return_value=True):
            status, result = self.request(
                "/api/sites/{}/verify".format(site_id), {}, csrf=account["csrf"]
            )

        self.assertEqual(status, 200)
        self.assertTrue(result["verified"])
        status, sites = self.request("/api/sites")
        self.assertEqual(status, 200)
        self.assertIsNotNone(sites["sites"][0]["verified_at"])


if __name__ == "__main__":
    unittest.main()
