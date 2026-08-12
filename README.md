# 🌐 DNS + SSL Utilities

**Fast DNS, TLS, certificate, hosting, mail, and web-security diagnostics from one terminal toolkit.**

Built for **Linux and WSL**, with registrar, hosting, infrastructure, support, and security workflows in mind.

```bash
check example.com
```

That’s the main idea.

No banner. No ceremony. No digging through five different tools just to answer a customer’s domain question. ⚡

---

## ✨ What It Does

DNS + SSL Utilities brings the most useful domain and infrastructure diagnostics into one CLI:

* 🌍 DNS records, delegation, DNSSEC, and reverse DNS
* 🧭 WHOIS and registrar detection
* 🏢 Hosting/provider identification
* 📬 MX, SPF, DMARC, DKIM, MTA-STS, and TLS-RPT
* 🔐 SSL/TLS certificates, chains, protocols, ciphers, OCSP, and CRLs
* 🌐 HTTP/HTTPS status, redirects, and security headers
* 🚨 Defensive website exposure and vulnerability auditing
* 🔑 CSR, certificate, private-key, and PKCS#12 utilities
* 🩺 Dependency and environment diagnostics
* 🎨 Colored, readable terminal output
* ⚡ Short aliases for common commands
* 🐧 First-class Linux and WSL support

---

# 🚀 Installation

Clone the repository and run:

```bash
chmod +x setup.sh
./setup.sh
```

The installer exposes the suite through `~/.local/bin`.

Make sure that directory is available in your `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload your shell:

```bash
exec zsh
```

or:

```bash
exec bash
```

Verify the installation:

```bash
check --version
```

---

# ⚡ Start Here

For a fast operational overview of a domain:

```bash
check example.com
```

The report focuses on the information most useful during real-world domain and hosting troubleshooting:

* registrar
* A / AAAA
* nameservers
* MX
* DNSSEC
* SPF
* DMARC
* CAA
* hosting/provider signals
* certificate hostname and expiry
* HTTP / HTTPS status
* redirects
* HSTS
* CSP
* server headers
* reverse DNS

`check` is deliberately designed as a **fast path**.

It does **not** automatically run heavyweight operations such as vulnerability scanning, cipher enumeration, CT discovery, large DKIM sweeps, or deep redirect analysis.

Those tools are available when you actually ask for them.

### Skip reverse DNS

PTR lookups can be slow or unreliable on some resolvers.

For the quickest possible overview:

```bash
check example.com --no-rdns
```

---

# 🧭 Command Overview

```text
check <domain>

check dns <command> <target>
check ssl <command> <target>
check audit <target>

check doctor
check help
check --help
check --version
```

Convenience commands are also installed:

```text
dnsutil
ssl
vulncheck
```

`dsu` remains available as a compatibility alias for existing scripts and installations.

---

# 🌍 DNS

View DNS help:

```bash
check dns --help
```

or:

```bash
dnsutil --help
```

## 🔎 DNS Records

```bash
dnsutil lookup example.com
dnsutil l example.com
```

Query a specific record type:

```bash
dnsutil lookup example.com MX
dnsutil lookup example.com TXT
dnsutil lookup example.com CAA
```

Supported record types include:

```text
A
AAAA
CNAME
MX
NS
TXT
CAA
SOA
```

---

## 🔁 Reverse DNS / PTR

```bash
dnsutil reverse 203.0.113.10
dnsutil r 203.0.113.10
```

IPv6 is supported:

```bash
dnsutil r 2001:db8::10
```

PTR results are classified explicitly:

* ✅ **PTR found**
* ℹ️ **No PTR configured**
* ❌ **Resolver or lookup failure**

Timeouts, `SERVFAIL`, unreachable resolvers, and transport errors are never presented as successful PTR records.

---

## 📬 Mail DNS & Policy

```bash
dnsutil mail example.com
dnsutil m example.com
```

Checks include:

* MX
* SPF
* DMARC
* DKIM selectors
* MTA-STS
* TLS-RPT
* multiple or invalid SPF records
* MX targets incorrectly using CNAME
* related mail-DNS inconsistencies

---

## 🛡️ DNSSEC

```bash
dnsutil dnssec example.com
```

Checks DNSSEC records and resolver validation.

---

## 🧱 Delegation Trace

```bash
dnsutil trace example.com
dnsutil t example.com
```

Useful for diagnosing:

* parent/child nameserver mismatches
* stale delegations
* broken authoritative paths
* DNSSEC delegation problems
* incorrect nameserver changes

---

## 🧾 WHOIS & Registrar

```bash
dnsutil whois example.com
dnsutil w example.com
```

Registrar detection uses a conservative WHOIS sequence designed to handle the inconsistent formats returned by different registries.

It checks:

1. direct `Registrar:` values
2. multi-line registrar fields
3. registrar handles
4. registrar-name resolution from those handles when necessary

WHOIS operations use bounded timeouts so a slow registry cannot hang indefinitely.

---

## 🏢 Hosting Provider Detection

```bash
dnsutil hosting example.com
dnsutil h example.com
```

Provider detection uses available signals such as:

* A / AAAA records
* CNAMEs
* PTR hostnames
* known address ranges
* hosting/provider naming patterns

The result is intentionally presented as a **best-effort guess** rather than pretending infrastructure detection is always absolute.

---

# 🔐 SSL / TLS

View SSL help:

```bash
ssl --help
```

or:

```bash
check ssl --help
```

Most SSL commands also have short aliases.

---

## 📜 Certificate Details

```bash
ssl cert example.com
ssl c example.com
```

Displays information such as:

* subject
* issuer
* SANs
* validity period
* expiry
* serial number
* signature algorithm
* key information
* certificate fingerprints

Custom TLS port:

```bash
ssl c example.com:8443
```

---

## ⚡ Quick Certificate Check

```bash
ssl quick example.com
ssl q example.com
```

For when you mostly care whether the certificate is healthy and how long it has left.

---

## ⛓️ Certificate Chain

```bash
ssl chain example.com
ssl ch example.com
```

Displays the certificate chain served by the remote endpoint.

---

## 🎯 Test SNI Against a Specific IP

```bash
ssl fetch example.com 203.0.113.10
```

Connects directly to the specified IP while still sending the hostname through SNI.

Useful for:

* migrations
* load balancers
* origin testing
* pre-DNS-cutover checks
* multi-server environments

---

## 🧪 TLS Versions

```bash
ssl versions example.com
```

Tests protocol support such as:

```text
TLS 1.0
TLS 1.1
TLS 1.2
TLS 1.3
```

---

## 🔢 Cipher Analysis

```bash
ssl ciphers example.com
ssl ci example.com
```

If `sslscan` is installed, it can be used for broader cipher enumeration.

---

## 🪪 Fingerprints

```bash
ssl fingerprint example.com
ssl fp example.com
```

---

## 📡 OCSP

```bash
ssl ocsp example.com
```

---

## 🧹 CRL

```bash
ssl crl example.com
```

---

## 🔭 Certificate Transparency

```bash
ssl ct example.com
```

---

## ⚙️ TLS Performance

```bash
ssl performance example.com
ssl perf example.com
```

Measures TLS handshake performance.

---

# 🔑 Certificate & Key Utilities

The SSL toolkit also works with local certificate material.

## ✍️ Create a Private Key + CSR

```bash
ssl new example.com
```

See all options:

```bash
ssl new --help
```

---

## 🔍 Decode Certificate Material

```bash
ssl decode certificate.pem
```

Supports certificate, CSR, and private-key inspection.

---

## 🧩 Verify Certificate / CSR / Key Matching

```bash
ssl match certificate.pem private.key
```

Matching is based on public-key hashes and supports both RSA and EC material.

---

## 📦 Create PKCS#12 / PFX

```bash
ssl pack certificate.pem private.key output.pfx
```

Short form:

```bash
ssl pk certificate.pem private.key output.pfx
```

---

## 📤 Extract PKCS#12 / PFX

```bash
ssl extract certificate.pfx
```

---

# 🌐 HTTP / HTTPS Diagnostics

The suite can inspect:

* HTTP and HTTPS availability
* status codes
* redirect behavior
* response headers
* HSTS
* CSP
* server disclosure
* certificate behavior
* protocol behavior

For the normal operational view:

```bash
check example.com
```

Use the dedicated site or audit commands when you need deeper HTTP analysis.

---

# 🚨 Defensive Security Audit

Run the standard audit:

```bash
vulncheck example.com
```

or:

```bash
check audit example.com
```

The normal audit is designed to be **low-impact and non-destructive**.

It focuses on weaknesses that are useful during infrastructure and hosting reviews without attempting exploitation.

---

## 🛡️ Audit Coverage

### 🔐 TLS & Certificates

Checks may include:

* hostname mismatch
* expiry and near-expiry
* weak signature algorithms
* weak public keys
* deprecated TLS versions
* TLS compression
* weak cipher posture
* OCSP stapling
* certificate-chain problems

### 🌍 DNS

Checks may include:

* DNSSEC
* CAA
* dangling CNAME indicators
* suspicious NXDOMAIN dependencies
* multiple SPF records
* invalid SPF configuration
* MX/CNAME problems
* other mail-related DNS mistakes

### 📬 Mail Policy

Checks may include:

* SPF
* DMARC
* MX
* DKIM discovery
* MTA-STS
* TLS-RPT

### 🧱 HTTP Security Headers

Checks may include:

* `Strict-Transport-Security`
* `Content-Security-Policy`
* `X-Frame-Options`
* `frame-ancestors`
* `X-Content-Type-Options`
* `Referrer-Policy`
* `Permissions-Policy`
* `Cross-Origin-Opener-Policy`
* `Cross-Origin-Resource-Policy`

### 🍪 Cookies

Detects cookies missing protections such as:

```text
Secure
HttpOnly
SameSite
```

### 🌐 CORS

Looks for suspicious or overly permissive cross-origin configurations.

### 🚪 HTTP Methods

Checks may inspect:

```text
TRACE
OPTIONS
```

and other unexpectedly exposed methods.

---

# 🔓 Accidental Exposure Detection

The audit can probe for commonly exposed files and diagnostic endpoints such as:

```text
/.env
/.git/HEAD
/server-status
/phpinfo.php
/wp-config.php.bak
/config.php.bak
/actuator/env
/.svn/entries
/debug/vars
/dump.sql
/backup.zip
/.DS_Store
/composer.json
/package.json
```

Where practical, responses are checked for recognizable content instead of assuming every HTTP `200` represents a real exposure.

This helps avoid false positives from soft-404 pages.

---

# 🧑‍💻 Frontend Security Signals

Checks may include:

* mixed-content references
* password forms over insecure transport
* directory listings
* insecure redirects
* information-leaking headers
* missing `security.txt`

---

# 🧨 Deep Authorized Audit

For systems you own or are explicitly authorized to assess:

```bash
vulncheck example.com --deep --authorized
```

Deep mode can add checks such as:

* DNS zone-transfer attempts
* open DNS recursion
* broader cipher inspection
* safe Nmap HTTP/TLS NSE scripts

Optional top-100 TCP port inventory:

```bash
vulncheck example.com --deep --ports --authorized
```

> ⚠️ **Only run deep scans against infrastructure you own or have explicit permission to assess.**

The suite deliberately avoids destructive actions such as:

* credential attacks
* denial-of-service testing
* exploit execution
* destructive fuzzing
* authentication bypass attempts

---

# 🎯 Strict Mode & Exit Codes

Normal audits report findings without necessarily causing the command itself to fail.

For automation or CI:

```bash
vulncheck example.com --strict
```

Inspect the result:

```bash
echo $?
```

Current exit codes:

```text
0    Command completed successfully
1    Operational failure, or MEDIUM finding with --strict
2    Invalid usage, or HIGH/CRITICAL finding with --strict
127  Required dependency missing
```

Without `--strict`, findings may still be present when the command exits with `0`.

---

# 🩺 Dependency Doctor

Check the local environment:

```bash
check doctor
```

Common dependencies:

```text
curl
openssl
dig
whois
python3
```

Optional tools unlock additional functionality:

```text
sslscan
nmap
```

For Debian, Ubuntu, or WSL:

```bash
sudo apt update
sudo apt install curl openssl dnsutils whois python3
```

Optional:

```bash
sudo apt install nmap sslscan
```

Package availability may vary by distribution.

---

# ⚡ Performance Tuning

The normal `check` path uses tighter limits than the deeper diagnostic commands:

```text
DSU_CHECK_DNS_TIMEOUT=1
DSU_CHECK_CONNECT_TIMEOUT=2
DSU_CHECK_MAX_TIME=4
DSU_CHECK_WHOIS_TIMEOUT=10
DSU_CHECK_WHOIS_HANDLE_TIMEOUT=10
DSU_CHECK_PTR_TIMEOUT=1
```

Override them per invocation:

```bash
DSU_CHECK_MAX_TIME=6 check example.com
```

The vulnerability scanner uses bounded concurrency controlled by:

```text
DSU_AUDIT_JOBS
```

Default:

```text
4
```

This keeps audits faster without unnecessarily hammering the target.

---

# 🎨 Colors

Colored output is enabled automatically when appropriate.

Disable it with:

```bash
NO_COLOR=1 check example.com
```

Useful for:

* logs
* CI
* redirected output
* text processing

---

# 🧠 Help

Start here:

```bash
check --help
```

Then drill down:

```bash
check dns --help
check ssl --help
check audit --help
```

Command-specific help is available too:

```bash
ssl cert --help
ssl new --help
ssl pack --help
```

Alternative help syntax:

```bash
check help
check help ssl
check help ssl cert
```

---

# ⚡ Short Aliases

Common commands have memorable short forms:

```text
ssl cert         → ssl c
ssl quick        → ssl q
ssl chain        → ssl ch
ssl ciphers      → ssl ci
ssl fingerprint  → ssl fp
ssl pack         → ssl pk
ssl performance  → ssl perf

dns lookup       → dns l
dns reverse      → dns r
dns mail         → dns m
dns trace        → dns t
dns whois        → dns w
dns hosting      → dns h
```

For example:

```bash
ssl c example.com
```

is equivalent to:

```bash
ssl cert example.com
```

---

# 🧪 Common Workflows

### Get the important domain information

```bash
check example.com
```

### Fast check without PTR

```bash
check example.com --no-rdns
```

### Inspect the certificate

```bash
ssl c example.com
```

### Diagnose mail DNS

```bash
dnsutil m example.com
```

### Trace DNS delegation

```bash
dnsutil t example.com
```

### Check reverse DNS

```bash
dnsutil r 203.0.113.10
```

### Run a defensive audit

```bash
vulncheck example.com
```

### Run an authorized deep audit

```bash
vulncheck example.com --deep --authorized
```

### Include port discovery

```bash
vulncheck example.com --deep --ports --authorized
```

### Diagnose the local environment

```bash
check doctor
```

---

# 🗂️ Project Layout

```text
dns-ssl-utilities/
├── dns-ssl-utilities.sh
├── setup.sh
├── update.sh
├── README.md
├── LICENSE
├── lib/
├── helpers/
└── tests/
```

### `dns-ssl-utilities.sh`

Main command router.

### `lib/`

Shared shell modules and command implementations.

### `helpers/`

Supporting utilities used by the suite.

### `tests/`

Smoke, regression, and performance tests.

---

# 🔧 Updating

From a Git checkout:

```bash
git pull
./setup.sh
```

If your installation includes the updater:

```bash
./update.sh
```

The installer is designed to be safe to rerun.

---

# 🧪 Testing

Run the smoke tests:

```bash
./tests/smoke.sh
```

Run the performance regression tests:

```bash
./tests/performance.sh
```

The test suite covers areas such as:

* CLI routing
* help output
* DNS parsing
* registrar detection
* PTR result classification
* certificate workflows
* audit authorization controls
* installation behavior
* performance regressions

---

# 🐧 WSL

For WSL, install the Linux-side networking tools inside your distribution:

```bash
sudo apt update
sudo apt install curl openssl dnsutils whois python3
```

Then verify everything with:

```bash
check doctor
```

---

# 🔒 Security & Authorization

The auditing tools are intended for:

* infrastructure you own
* infrastructure operated by your organization
* customer systems you are authorized to inspect
* test environments
* approved security assessments

Standard scans are designed to remain low-impact.

More active functionality requires explicit flags so deeper checks are intentional.

---

# 💡 Recommended Workflow

Start simple:

```bash
check example.com
```

If the problem looks DNS-related:

```bash
dnsutil l example.com
dnsutil t example.com
dnsutil m example.com
```

If it looks TLS-related:

```bash
ssl q example.com
ssl c example.com
ssl ch example.com
```

For a defensive security review:

```bash
vulncheck example.com
```

For an approved deeper assessment:

```bash
vulncheck example.com --deep --authorized
```

---

# 🤝 Design Philosophy

Infrastructure tooling should answer three questions quickly:

1. 🔎 **What is configured?**
2. 🚦 **Is it working?**
3. 🛡️ **Is anything obviously unsafe or exposed?**

DNS + SSL Utilities is built to answer those questions without turning a simple domain check into an expedition.

---

# 📄 License

See `LICENSE` for license information.

---

## 🌐🔐 DNS + SSL Utilities

**DNS. TLS. Domains. Mail. Hosting. Security. One terminal toolkit.** 🐧⚡
