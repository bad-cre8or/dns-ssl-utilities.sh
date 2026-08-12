# DNS + SSL Utilities

A cohesive WSL/Linux terminal suite for DNS operations, SSL/TLS and certificate work, hosting diagnostics, and defensive web-security exposure checks.

The suite consolidates and refactors the original **domain-check**, **ssl-utils**, and **sitecheck** scripts into one consistent CLI:

```text
dns-ssl-utilities.sh
├── dns ...       DNS records, PTR, DNSSEC, mail policy, WHOIS, hosting hints
├── ssl ...       Live TLS checks plus certificate/CSR/key/PFX tools
├── site ...      Combined operational domain + hosting + web health checks
└── audit ...     Defensive web/TLS/DNS exposure and hardening audit
```

The interface is intentionally alias-friendly. For example, these are equivalent after running `setup.sh`:

```bash
ssl cert example.com
ssl c example.com

dnsutil lookup example.com
dnsutil l example.com
```

## Highlights

- Colored, structured terminal output with `NO_COLOR`, `--no-color`, `--color`, and ASCII fallbacks.
- Hierarchical `--help` for the whole suite and each command family.
- URLs are normalized to hostnames where appropriate.
- IPv4 **and** IPv6 reverse DNS.
- DNS A/AAAA/CNAME/MX/NS/TXT/CAA/SOA lookup, DNSSEC, delegation tracing, WHOIS, and provider hints.
- SPF, DMARC, common DKIM selectors, MTA-STS, SMTP TLS reporting, and CAA checks.
- Certificate identity, SANs, validity, signature algorithm, key details, chain verification, fingerprints, and TLS version probes.
- SNI testing against a specific server IP.
- OCSP, CRL, Certificate Transparency, cipher enumeration, sslscan, and TLS handshake benchmarking.
- Certificate/CSR/private-key decoding with OpenSSL only.
- Public-key matching based on SHA-256 of the DER public key, so it works with RSA and EC material instead of relying on MD5 modulus tricks.
- CSR creation with SANs, RSA or EC keys, optional key encryption.
- PFX/PKCS#12 pack and extract workflows.
- Combined site health view derived from the original domain-check and sitecheck tools.
- Defensive web security audit with a low-impact default mode and explicit authorization gate for deeper active checks.

## Requirements

Designed for Ubuntu / WSL with Bash 4+.

### Required

```bash
sudo apt update
sudo apt install -y bash curl openssl dnsutils python3 coreutils
```

### Recommended / optional

```bash
sudo apt install -y whois sslscan nmap file
```

- `whois`: registration and ownership summaries.
- `sslscan`: preferred cipher-suite enumeration.
- `nmap`: optional deep audit / TLS script support.
- `file`: helps classify exposed archives during deep audit.

No Python packages such as `colorama` or `cryptography` are required.

## Installation

From the extracted directory:

```bash
chmod +x dns-ssl-utilities.sh setup.sh
./setup.sh
```

`setup.sh` creates convenience commands in `~/.local/bin`:

```text
dns-ssl-utilities
dsu
ssl
dnsutil
sitecheck
vulncheck
```

If `~/.local/bin` is not already in your `PATH`, add this to `~/.bashrc` or `~/.zshrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload your shell:

```bash
source ~/.bashrc
# or
source ~/.zshrc
```

The installer will not overwrite an existing command with the same name unless you explicitly use:

```bash
./setup.sh --force
```

If your old SSL toolkit is still configured as a shell alias such as `alias ssl=~/ssl-utils/wrapper.py`, remove or update that alias in `.bashrc` / `.zshrc` because shell aliases take precedence over executables found in `PATH`. For the current shell you can use:

```bash
unalias ssl 2>/dev/null || true
```

You can also skip installation entirely:

```bash
./dns-ssl-utilities.sh --help
```

## Help

The top-level help is deliberately comprehensive:

```bash
dsu --help
```

Focused help:

```bash
dsu dns --help
dsu ssl --help
dsu site --help
dsu audit --help
```

Dependency diagnostics:

```bash
dsu doctor
```

## Quick start

```bash
# Full operational check
sitecheck example.com
# Same thing
dsu check example.com

# DNS
dnsutil lookup example.com
dnsutil l example.com A
dnsutil ptr example.com
dnsutil mail example.com
dnsutil mail example.com selector1
dnsutil dnssec example.com
dnsutil trace example.com
dnsutil whois example.com
dnsutil hosting example.com

# TLS / certificates
ssl c example.com
ssl q example.com
ssl chain example.com
ssl fetch 203.0.113.10 example.com
ssl versions example.com
ssl ciphers example.com
ssl scan example.com
ssl ocsp example.com
ssl crl example.com
ssl ct example.com
ssl headers example.com
ssl fp example.com
ssl performance example.com

# Certificate files
ssl decode server.crt
ssl match server.crt server.csr server.key
ssl new example.com --san www.example.com --san mail.example.com
ssl pack server.crt server.key chain.pem server.pfx
ssl extract server.pfx extracted

# Security audit
vulncheck example.com
vulncheck example.com --deep --authorized
vulncheck example.com --deep --ports --authorized --strict
```

## Command reference

### DNS

| Command | Aliases | Purpose |
|---|---|---|
| `dns lookup` | `l`, `look`, `resolve`, `records` | Curated records or one requested RR type |
| `dns reverse` | `ptr`, `rdns`, `r` | PTR lookup for domain A/AAAA or explicit IP |
| `dns mail` | `email`, `m` | SPF, DMARC, DKIM, CAA, MTA-STS, TLS-RPT |
| `dns dnssec` | `ds` | DNSKEY/DS and AD validation status |
| `dns trace` | `t` | `dig +trace` delegation walk |
| `dns whois` | `w` | Registrar, lifecycle, status, NS summary |
| `dns hosting` | `host`, `provider`, `h` | Best-effort provider guess from CNAME/PTR/IP/WHOIS |

Examples:

```bash
dsu dns lookup example.com
dsu dns l example.com CAA
dsu dns reverse 203.0.113.10
dsu dns mail example.com google
```

### SSL / TLS

| Command | Aliases | Purpose |
|---|---|---|
| `ssl cert` | `certificate`, `c` | Full live certificate summary |
| `ssl quick` | `q` | Compact expiry/issuer status |
| `ssl chain` | `ch` | Raw served certificate chain |
| `ssl fetch` | `f` | Test domain/SNI against a chosen server IP |
| `ssl versions` | `version`, `v` | TLS version support |
| `ssl ciphers` | `cipher`, `ci` | Cipher enumeration with sslscan/nmap |
| `ssl scan` | `s` | Direct sslscan |
| `ssl ocsp` | `o` | OCSP query using served leaf/issuer |
| `ssl crl` |  | CRL distribution point + serial check |
| `ssl ct` | `ctlogs`, `transparency` | crt.sh Certificate Transparency query |
| `ssl headers` | `header`, `h` | HTTPS security headers |
| `ssl performance` | `perf`, `bench` | OpenSSL handshake benchmark |
| `ssl fingerprint` | `pinning`, `pin`, `fp` | SHA-256 fingerprint / compare expected value |
| `ssl decode` | `d` | Decode PEM cert, CSR, or private key |
| `ssl match` | `modulus`, `m` | Compare public keys across files |
| `ssl new` | `csr`, `n` | Generate private key + CSR + SANs |
| `ssl pack` | `pfx-pack`, `pk` | Create PKCS#12/PFX |
| `ssl extract` | `pfx-extract`, `x` | Extract cert/chain/key from PFX |

#### CSR examples

Default RSA-2048:

```bash
ssl new example.com --san www.example.com
```

RSA-4096:

```bash
ssl new example.com --rsa 4096 --out wildcard-example
```

EC key:

```bash
ssl new example.com --ec prime256v1 --san www.example.com
```

Encrypted private key:

```bash
ssl new example.com --encrypted
```

#### PFX notes

`ssl pack` prompts for a PFX password unless `DSU_PFX_PASSWORD` is set in the environment.

```bash
ssl pack server.crt server.key ca-chain.pem server.pfx
```

`ssl extract` asks for the PFX password once. The extracted private key is deliberately written unencrypted for interoperability and chmodded to `0600`; handle it accordingly.

## Site checks

`site check` is the spiritual successor to the original `check` and `sitecheck` scripts. It gathers:

- A / AAAA / CNAME / NS / MX
- DNSSEC signal
- SPF / DMARC / CAA
- hosting/provider guess
- registrar and registration expiry where WHOIS provides them
- certificate hostname and expiry
- HTTP and HTTPS status
- HTTP-to-HTTPS redirect behavior
- HSTS / CSP / implementation headers
- reverse DNS for all resolved IPv4 and IPv6 addresses

```bash
sitecheck example.com
# or
dsu site c example.com
```

Other site commands:

```bash
dsu site headers example.com
dsu site redirects http://example.com
dsu site status example.com
```

## Security exposure audit

The audit is designed for defensive use by administrators, hosting teams, registrars, support engineers, and authorized security staff.

### Default mode

```bash
vulncheck example.com
```

Default mode is intentionally non-destructive and low-impact. It checks:

#### DNS and mail policy

- DNSSEC presence / partial configuration / resolver AD signal
- CAA
- SPF, including dangerous `+all`
- DMARC presence and `p=none`

#### TLS and certificate posture

- TLS service available
- chain verification result
- hostname identity match
- certificate expiry urgency
- weak certificate signature algorithms such as SHA-1 / MD5
- RSA public-key size
- SSLv3 / TLS 1.0 / TLS 1.1 acceptance when the local OpenSSL can probe them
- TLS 1.2 / TLS 1.3 support information
- OCSP stapling presence

#### HTTP/browser hardening

- HTTP → HTTPS redirect
- HSTS and max-age quality
- CSP presence plus obvious `unsafe-eval`, `unsafe-inline`, and wildcard sources
- clickjacking protection via X-Frame-Options or CSP `frame-ancestors`
- `X-Content-Type-Options: nosniff`
- Referrer-Policy
- Permissions-Policy
- COOP / CORP signals
- Server / X-Powered-By information leakage
- cookie Secure / HttpOnly / SameSite attributes
- benign arbitrary-Origin CORS behavior probe
- TRACE status
- OPTIONS / Allow methods
- obvious mixed-content references in the first 1 MiB of the homepage
- password forms submitting to plain HTTP
- root directory-listing signature
- `/.well-known/security.txt`

#### Accidental exposure checks

The default path set performs small, bounded requests and only reports a vulnerability when expected content signatures are present, which reduces false positives from SPA/soft-404 sites:

```text
/.git/HEAD
/.env
/server-status
/phpinfo.php
/wp-config.php.bak
/actuator/env
```

### Deep authorized mode

```bash
vulncheck example.com --deep --authorized
```

`--deep` requires the explicit `--authorized` acknowledgement and adds:

- authoritative DNS AXFR checks
- authoritative-name-server recursion checks
- extended accidental-exposure signatures, including database dumps and backup artifacts
- sslscan weak-cipher review when installed
- safe nmap TLS/HTTP information scripts on web ports when nmap is installed

Add an authorized top-100 TCP inventory with:

```bash
vulncheck example.com --deep --ports --authorized
```

The suite intentionally **does not** attempt SQL injection, XSS exploitation, authentication bypass, password attacks, destructive fuzzing, denial-of-service, malware delivery, or automatic exploitation. It is an exposure and hardening scanner, not proof that an application is vulnerability-free.

### Strict mode and exit status

For CI/support automation:

```bash
vulncheck example.com --strict
```

- `0`: no MEDIUM/HIGH/CRITICAL finding in strict mode, or a normal non-strict completion.
- `1`: MEDIUM finding with `--strict`, or an operational failure in a normal command.
- `2`: HIGH/CRITICAL finding with `--strict`, or invalid usage.
- `127`: required external command missing.

## Original-tool migration map

| Original | New suite |
|---|---|
| `check <domain>` | `sitecheck <domain>` or `dsu check <domain>` |
| `rdns <domain>` | `dnsutil ptr <domain>` |
| `checkcert <domain>` | `ssl cert <domain>` |
| `checkssl <domain>` | `ssl chain <domain>` |
| `ssl cert` / `ssl c` | unchanged conceptually |
| `ssl quick` | unchanged conceptually |
| `ssl fetch` | improved SNI-to-IP validation |
| `ssl md5` | `ssl match` using SHA-256 public-key identity |
| `ssl pinning` | `ssl fingerprint` / `ssl fp` |
| `ssl version` | `ssl versions` |
| `ssl headers` | `ssl headers` |
| standalone `sitecheck` | `sitecheck` or `dsu site check` |

## Environment variables

| Variable | Effect |
|---|---|
| `NO_COLOR=1` | Standard no-color convention |
| `DSU_FORCE_COLOR=1` | Force ANSI output |
| `DSU_ASCII=1` | ASCII status markers |
| `DSU_CONNECT_TIMEOUT=6` | curl/OpenSSL connection timeout baseline |
| `DSU_MAX_TIME=12` | common maximum network operation time |
| `DSU_USER_AGENT=...` | HTTP user agent |
| `DSU_BIN_DIR=...` | installer link directory, default `~/.local/bin` |
| `DSU_PFX_PASSWORD=...` | optional non-interactive PFX creation password |

## Project layout

```text
dns-ssl-utilities/
├── dns-ssl-utilities.sh      # main CLI/router
├── lib/
│   ├── core.sh               # colors, normalization, HTTP/TLS helpers, findings
│   ├── dns.sh                # DNS namespace
│   ├── ssl.sh                # TLS + certificate namespace
│   ├── site.sh               # combined site diagnostics
│   └── security.sh           # defensive security audit
├── helpers/
│   ├── hosting_provider.py   # provider heuristic
│   └── ct_query.py           # crt.sh formatter without jq
├── tests/
│   └── smoke.sh              # local/mocked validation
├── setup.sh
├── update.sh
├── README.md
└── LICENSE
```

## Design notes

- Results are network-derived and can be misleading behind CDNs, WAFs, reverse proxies, anycast, split-horizon DNS, TLS interception, or unusual registrar/registry WHOIS formats.
- Provider identification is heuristic and should be treated as a clue, not authoritative ownership data.
- DKIM cannot be exhaustively discovered from DNS without knowing selectors. The suite checks a curated list unless you provide a selector explicitly.
- A missing security header is not automatically an exploitable vulnerability. Severity is based on common hardening impact and should be interpreted in application context.
- OCSP/CRL availability varies by CA ecosystem; absence alone is not always a defect.
- TLS support also depends on the capabilities of your local OpenSSL build.
- Deep network checks should only be run where your organization has permission to assess the target.

## License

Apache License 2.0. See `LICENSE`.
