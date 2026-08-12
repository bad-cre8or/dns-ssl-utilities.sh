# 🌐 DNS + SSL Utilities

A colorful, practical command-line toolkit for **DNS diagnostics, SSL/TLS inspection, domain troubleshooting, mail-security checks, hosting analysis, and defensive website auditing**.

Built for Linux and WSL environments, with a focus on registrar, hosting, infrastructure, support, and security workflows.

> 🧰 One toolkit. Clear commands. Useful output. No tab-juggling required.

---

## ✨ Highlights

- 🌍 DNS lookups and delegation checks
- 🔐 SSL/TLS certificate inspection
- 📬 SPF, DMARC, DKIM, MX, MTA-STS, and TLS-RPT checks
- 🧭 Registrar, WHOIS, nameserver, and hosting-provider information
- 🔁 Forward and reverse DNS analysis
- 🛡️ DNSSEC and CAA validation
- 🌐 HTTP/HTTPS diagnostics and redirect tracing
- 🚨 Defensive vulnerability and exposure auditing
- 🧪 Optional deep authorized scans
- 🎨 Colored terminal output with `NO_COLOR` support
- ⚡ Short, memorable aliases
- 🩺 Built-in dependency diagnostics
- 🧠 Hierarchical help for the suite and individual commands
- 🐧 Designed for Linux and WSL

---

# 🚀 Quick Start

## Install

```bash
chmod +x setup.sh
./setup.sh
```

The installer places the suite in your local user environment and exposes convenient commands through `~/.local/bin`.

Make sure this directory is in your `PATH`:

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

---

# ⚡ Performance

`dsu check` is deliberately a **hot path**. It does not run the vulnerability audit, cipher enumeration, redirect crawling, CT queries, DKIM selector sweeps, or other heavyweight checks. Independent DNS, WHOIS, HTTP, HTTPS and PTR work is launched concurrently, and the HTTPS transfer is reused for leaf-certificate data so a normal check does not need a second TLS handshake.

The fast overview uses tighter deadlines than the deeper subcommands:

```text
DSU_CHECK_DNS_TIMEOUT=1
DSU_CHECK_CONNECT_TIMEOUT=2
DSU_CHECK_MAX_TIME=4
DSU_CHECK_WHOIS_TIMEOUT=2
DSU_CHECK_WHOIS_HANDLE_TIMEOUT=1
DSU_CHECK_PTR_TIMEOUT=1
DSU_REGISTRAR_CACHE_TTL=21600   # 6 hours
```

The normal DNS/HTTP/TLS subcommands retain more forgiving defaults. You can tune only the overview without changing the deeper tools:

```bash
DSU_CHECK_MAX_TIME=6 DSU_CHECK_WHOIS_TIMEOUT=3 dsu check example.com
```

For the lowest possible latency, skip reverse DNS for that invocation:

```bash
dsu check example.com --no-rdns
```

Registrar names are cached briefly because registrars change far less often than DNS or HTTP state. Force a live WHOIS lookup with:

```bash
dsu check example.com --fresh
```

`DSU_AUDIT_JOBS` separately controls bounded concurrency for the defensive exposure audit. The default of `4` is intentionally conservative.

---

# 🧰 Main Commands

The canonical entry point is:

```bash
dsu
```

You can also run the script directly:

```bash
./dns-ssl-utilities.sh
```

## 🌐 Full Domain Overview

For the most useful domain information in one report:

```bash
dsu check example.com
```

This combines high-value DNS, registrar, mail, TLS, HTTP, hosting, and network information into a single readable output. It starts directly with the diagnostic sections: no product banner, tagline, target echo, spinner, or closing tip.

Perfect for:

- domain troubleshooting
- registrar support
- hosting investigations
- migration checks
- DNS propagation issues
- SSL troubleshooting
- mail-delivery triage
- customer support diagnostics

---

# 🧭 Command Structure

```text
dsu check <domain>
dsu dns <command> <target>
dsu ssl <command> <target>
dsu audit <target>
dsu doctor
dsu help
```

Convenience frontends are also available:

```text
dnsutil
ssl
vulncheck
```

---

# 🌍 DNS Toolkit

Use:

```bash
dsu dns --help
```

or:

```bash
dnsutil --help
```

## 🔎 Lookup Records

```bash
dnsutil lookup example.com
dnsutil l example.com
```

Useful records include:

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

Examples:

```bash
dnsutil lookup example.com
dnsutil lookup example.com MX
dnsutil lookup example.com TXT
```

---

## 🔁 Reverse DNS / PTR

```bash
dnsutil reverse 203.0.113.10
dnsutil r 203.0.113.10
```

IPv6 is supported as well:

```bash
dnsutil reverse 2001:db8::10
```

PTR results are classified explicitly:

- ✅ a real PTR answer is shown as successful
- ℹ️ a successful DNS response with no PTR is shown as `no PTR`
- ❌ resolver timeouts, `SERVFAIL`, unreachable DNS servers, and transport errors are shown as lookup failures

Resolver diagnostics are never presented as PTR hostnames.

---

## 📬 Mail Security

```bash
dnsutil mail example.com
dnsutil m example.com
```

Checks may include:

- MX records
- SPF
- DMARC
- DKIM selectors
- MTA-STS
- TLS-RPT
- suspicious or invalid SPF layouts
- MX targets using CNAMEs
- mail-related DNS inconsistencies

---

## 🛡️ DNSSEC

```bash
dnsutil dnssec example.com
```

Useful for confirming whether a domain is signed and whether validation succeeds.

---

## 🧱 Delegation Trace

```bash
dnsutil trace example.com
dnsutil t example.com
```

Helps diagnose:

- parent/child nameserver mismatches
- delegation problems
- stale nameservers
- DNSSEC delegation issues
- broken authoritative paths

---

## 🧾 WHOIS / Registrar Information

```bash
dnsutil whois example.com
dnsutil w example.com
```

The registrar parser understands common WHOIS layouts, including padded fields such as `Registrar Name........:`, multi-line registrar fields, and registries that expose a registrar handle which must be resolved to the registrar name. The compact site overview places the registrar near the top of the report. 🧭

---

## 🏢 Hosting / Provider Detection

```bash
dnsutil hosting example.com
dnsutil h example.com
```

Provider detection uses available DNS, IP, PTR, ASN/provider-style signals, and hostname information where possible.

---

# 🔐 SSL / TLS Toolkit

Use:

```bash
ssl --help
```

or:

```bash
dsu ssl --help
```

The SSL namespace supports both full command names and short aliases.

---

## 📜 Certificate Inspection

```bash
ssl cert example.com
ssl c example.com
```

Shows useful certificate information such as:

- subject
- issuer
- validity dates
- expiry
- SANs
- serial number
- signature algorithm
- key information
- certificate fingerprints

Custom port:

```bash
ssl cert example.com:8443
```

---

## ⚡ Quick TLS Check

```bash
ssl quick example.com
ssl q example.com
```

Useful when you want a fast answer without the full certificate dump.

---

## ⛓️ Certificate Chain

```bash
ssl chain example.com
ssl ch example.com
```

---

## 🎯 Connect to a Specific IP with SNI

Useful when multiple servers host the same domain:

```bash
ssl fetch example.com 203.0.113.10
```

This connects to the selected IP while still sending the domain as SNI.

---

## 🧪 TLS Protocol Support

```bash
ssl protocols example.com
```

Checks support for protocol generations such as:

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

If `sslscan` is installed, the suite can use it for broader cipher analysis.

---

## 🪪 Certificate Fingerprints

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

## 🧹 CRL Information

```bash
ssl crl example.com
```

---

## 🔭 Certificate Transparency

```bash
ssl ct example.com
```

---

# 🔑 Certificate & Key Utilities

The suite can also work with local certificate material.

## ✍️ Create a CSR

```bash
ssl new example.com
```

Use command-specific help for available options:

```bash
ssl new --help
```

---

## 🔍 Decode Certificate Material

```bash
ssl decode certificate.pem
```

---

## 🧩 Match Certificate, CSR, and Key

```bash
ssl match certificate.pem private.key
```

The comparison uses public-key hashes, making it suitable for RSA and EC material.

---

## 📦 PKCS#12 / PFX Packaging

```bash
ssl pack certificate.pem private.key output.pfx
ssl pk certificate.pem private.key output.pfx
```

---

## 📤 Extract PKCS#12 / PFX

```bash
ssl extract certificate.pfx
```

---

## ⚙️ TLS Handshake Performance

```bash
ssl performance example.com
ssl perf example.com
```

---

# 🌐 HTTP & Website Diagnostics

The suite can inspect:

- HTTP status
- HTTPS availability
- redirect chains
- response headers
- server information
- security headers
- certificate behavior
- protocol behavior
- network endpoints

A full domain overview is usually the best starting point:

```bash
dsu check example.com
```

---

# 🚨 Defensive Vulnerability Audit

Run the standard defensive audit with:

```bash
vulncheck example.com
```

or:

```bash
dsu audit example.com
```

The normal audit is designed to be **low-impact and non-destructive**.

It focuses on configuration weaknesses, information exposure, TLS posture, DNS mistakes, and common web-security problems.

---

# 🛡️ What the Audit Checks

## 🔐 TLS / Certificate Security

Checks may include:

- invalid or mismatched certificates
- expired certificates
- near-expiry warnings
- weak certificate signature algorithms
- weak public-key sizes
- deprecated TLS versions
- TLS compression
- cipher posture
- OCSP stapling
- certificate-chain problems

---

## 🌍 DNS Security

Checks may include:

- DNSSEC posture
- CAA records
- dangling CNAME indicators
- suspicious NXDOMAIN dependencies
- invalid SPF layouts
- multiple SPF records
- mail DNS inconsistencies
- MX targets incorrectly using CNAME records

---

## 📬 Mail Security

Checks may include:

- SPF
- DMARC
- MX
- MTA-STS
- TLS-RPT
- selected DKIM discovery
- policy weaknesses

---

## 🧱 HTTP Security Headers

Checks may include:

- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- frame-ancestors
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy

---

## 🍪 Cookie Security

The audit can detect cookies missing protections such as:

```text
Secure
HttpOnly
SameSite
```

---

## 🌐 CORS

Checks include suspicious configurations such as overly permissive origins and dangerous credential combinations.

---

## 🚪 HTTP Methods

Checks may inspect:

- TRACE
- OPTIONS
- unexpectedly exposed methods

---

## 🔓 Accidental Exposure Detection

The scanner can safely check for common exposed files and endpoints such as:

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

The suite performs **signature/content validation** where practical instead of treating every HTTP `200` response as a confirmed exposure.

This reduces false positives on websites using soft-404 pages.

---

## 🧑‍💻 Frontend Security Signals

Checks may include:

- mixed-content references
- password forms submitted insecurely
- directory listing indicators
- insecure redirects
- information-leaking headers
- missing `security.txt`

---

# 🧨 Deep Authorized Audit

For systems you are explicitly authorized to assess:

```bash
vulncheck example.com --deep --authorized
```

Deep mode can add more active checks such as:

- DNS zone-transfer attempts
- open-recursion checks
- broader TLS cipher inspection
- safe Nmap TLS/HTTP NSE scripts

To include a top-100 TCP port inventory:

```bash
vulncheck example.com --deep --ports --authorized
```

> ⚠️ Only use deep scanning against infrastructure you own or are explicitly authorized to test.

The suite deliberately avoids destructive behavior such as credential attacks, denial-of-service testing, exploit payload execution, destructive fuzzing, or authentication bypass attempts.

---

# 🎯 Strict Audit Mode

By default, audit findings are reported without making the command itself fail.

For automation or CI:

```bash
vulncheck example.com --strict
```

Then inspect the exit code:

```bash
echo $?
```

Current exit behavior:

```text
0    Command completed successfully
1    Operational failure, or MEDIUM audit finding with --strict
2    Invalid usage, or HIGH/CRITICAL audit finding with --strict
127  Missing required command dependency
```

Without `--strict`, security findings can still be present even when the command exits with `0`.

---

# 🩺 Dependency Doctor

Check your environment with:

```bash
dsu doctor
```

This reports required, recommended, and optional tools and clearly shows what functionality is available.

Common dependencies include:

```text
curl
openssl
dig
whois
python3
```

Optional tools can unlock additional functionality:

```text
sslscan
nmap
```

On Debian/Ubuntu/WSL, a useful starting point is:

```bash
sudo apt update
sudo apt install curl openssl dnsutils whois python3
```

Optional:

```bash
sudo apt install nmap sslscan
```

Package availability can vary by distribution.

---

# 🎨 Colors

The suite automatically uses colored terminal output when appropriate.

To disable colors:

```bash
NO_COLOR=1 dsu check example.com
```

This is useful for:

- logs
- CI
- text processing
- redirected output

---

# 🧠 Help System

The suite has hierarchical help.

Start with:

```bash
dsu --help
```

Then drill down:

```bash
dsu dns --help
dsu ssl --help
dsu audit --help
```

Command-specific help is also available:

```bash
ssl cert --help
ssl new --help
ssl pack --help
```

You can also use:

```bash
dsu help
dsu help ssl
dsu help ssl cert
```

---

# ⚡ Command Aliases

Short aliases are intended to keep common operations fast without making commands cryptic.

Examples:

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

Example:

```bash
ssl c example.com
```

is equivalent to:

```bash
ssl cert example.com
```

---

# 🧪 Examples

## Get the important information for a domain

```bash
dsu check example.com
```

## Inspect a certificate

```bash
ssl c example.com
```

## Diagnose mail DNS

```bash
dnsutil m example.com
```

## Trace delegation

```bash
dnsutil t example.com
```

## Check reverse DNS

```bash
dnsutil r 203.0.113.10
```

## Run a defensive audit

```bash
vulncheck example.com
```

## Run an authorized deep audit

```bash
vulncheck example.com --deep --authorized
```

## Include port discovery

```bash
vulncheck example.com --deep --ports --authorized
```

## Check installed dependencies

```bash
dsu doctor
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

Main CLI and command router.

### `lib/`

Reusable shell modules, formatting helpers, network logic, audit functionality, and command implementations.

### `helpers/`

Supporting utilities used by the suite.

### `tests/`

Smoke tests and regression checks.

---

# 🔧 Updating

If the installed copy includes the updater:

```bash
./update.sh
```

If you installed from a Git checkout, you can also update the repository normally and rerun:

```bash
./setup.sh
```

The installer is designed to be safe to rerun.

---

# 🧪 Testing

Run the included smoke suite with:

```bash
./tests/smoke.sh
```

Run the performance regression checks with:

```bash
./tests/performance.sh
```

The tests cover key CLI behavior, syntax, help routing, certificate workflows, DNS parsing, audit authorization controls, installation behavior, and protection against accidentally re-serializing latency-sensitive network checks.

---

# 🐧 WSL Notes

The suite works especially well in WSL when Linux networking tools are installed inside the distribution.

Recommended baseline:

```bash
sudo apt update
sudo apt install curl openssl dnsutils whois python3
```

If a command is missing:

```bash
dsu doctor
```

That should be your first stop.

---

# 🔒 Security Model

The auditing functionality is intended for:

- systems you own
- systems operated by your organization
- customer infrastructure you are authorized to inspect
- test environments
- approved security assessments

Standard scans are designed to remain low-impact.

More active functionality requires explicit flags so that deeper checks are deliberate rather than accidental.

---

# 💡 Recommended Workflow

For domain, hosting, or registrar troubleshooting:

```bash
dsu check example.com
```

If the problem appears DNS-related:

```bash
dnsutil l example.com
dnsutil t example.com
dnsutil m example.com
```

If it appears TLS-related:

```bash
ssl q example.com
ssl c example.com
ssl ch example.com
```

If you need a defensive security review:

```bash
vulncheck example.com
```

For an approved deeper assessment:

```bash
vulncheck example.com --deep --authorized
```

---

# 🤝 Philosophy

Good infrastructure tooling should answer three questions quickly:

1. 🔎 **What is configured?**
2. 🚦 **Is it working correctly?**
3. 🛡️ **Is anything obviously unsafe or exposed?**

DNS + SSL Utilities is built around making those answers fast, readable, and useful from a terminal.

---

# 📄 License

See:

```text
LICENSE
```

for license information.

---

## 🌐🔐 DNS + SSL Utilities

**DNS. TLS. Domains. Mail. Hosting. Security. One terminal toolkit.** 🐧⚡
