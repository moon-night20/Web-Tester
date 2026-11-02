# SecureLaunch

SecureLaunch is a small, self-hosted web security dashboard. It supports account
registration, DNS-based website ownership verification, OWASP ZAP passive scans,
OWASP Top 10:2025 grouping, finding remediation guidance, and scan comparisons.

## Requirements

- Python 3.9+
- A running OWASP ZAP daemon reachable by the application
- A DNS TXT record and a publicly routable website for each registered target

No Python packages are required. The application never runs ZAP's active scanner.
It crawls only the verified hostname, then waits for ZAP's passive rules to finish.
Only scan websites you own or are explicitly authorized to assess.

## Configure and run

Start ZAP in daemon mode with its API enabled and a strong API key. Keep the ZAP
API bound to localhost or a private, trusted network; do not expose it publicly.
For example, with ZAP installed:

```sh
zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.key=replace-with-a-long-random-key
```

In another terminal:

```sh
export ZAP_API_URL=http://127.0.0.1:8080
export ZAP_API_KEY=replace-with-a-long-random-key
python3 -m securelaunch
```

Open <http://127.0.0.1:8000>. Set `SECURELAUNCH_DB` to change the SQLite database
location, `HOST` to change the bind address, and `PORT` to change the web port.
The default bind address is loopback. For a remote deployment, keep the app and
ZAP API on trusted networks, put the app behind HTTPS, and set `SECURE_COOKIE=1`.
DNS verification and public-address checks require outbound HTTPS access to
Cloudflare's DNS-over-HTTPS resolver.

## Add and verify a website

Register using a unique username, email address, and password. Sign in with your
username or email address, then add the site's apex hostname (for example,
`example.com`). Usernames are 3–32 characters and may contain letters, numbers,
dots, underscores, and hyphens. Add the displayed token as a DNS TXT record at
`_securelaunch-challenge.example.com`. Select **Verify ownership** after DNS
propagation. SecureLaunch checks the TXT record through DNS-over-HTTPS and checks
that all resolved target IPs are globally routable before each scan.

Create a DNS record with type `TXT`, host/name
`_securelaunch-challenge.example.com`, and the exact `securelaunch-verification=...`
value shown in the app. If your DNS provider appends the domain automatically,
use `_securelaunch-challenge` as the host/name. If the check says the TXT record
is not visible, confirm you edited DNS at the domain's active nameserver provider
and try again after propagation. After verification, the scan dialog opens; ZAP
must be running before you start the scan.

The scanner is restricted to that exact verified hostname. ZAP's traditional
spider makes ordinary crawl requests; its active scanner is never invoked.
Network-level egress restrictions around the ZAP daemon are still recommended,
especially in shared or production deployments.

## OWASP Top 10:2025 categories

ZAP alerts are grouped into all ten OWASP Top 10:2025 categories where a rule's
name or CWE metadata supports a conservative mapping. Unmapped alerts remain
visible under **Needs review** rather than being assigned a guessed category.
The dashboard reports real alerts returned by the configured ZAP instance; it
does not generate sample scan findings.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The tests cover password handling, target scope validation, alert categorization,
finding identity/comparison, and database isolation. A real passive scan requires
a reachable ZAP daemon and an authorized, DNS-verified public website.
