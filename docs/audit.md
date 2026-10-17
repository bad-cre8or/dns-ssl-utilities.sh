# Project audit — 2.2.3

Reviewed the public entry points, shell modules, Python helpers, installer,
updater, help catalogue, report renderers, documentation, test suites and CI.

| Area | Confirmed problem | Change |
| --- | --- | --- |
| TLS protocols | TLS 1.3 verbose output did not match the protocol probe; a Protocol line alone could also accompany failed negotiation. | Use brief handshake output and require both a protocol and a negotiated cipher. Separate negotiation refusal from inconclusive probes; count inconclusive audit probes as MEDIUM. |
| Certificate expiry | Bash division rounded a certificate expired less than a day ago to zero remaining days. | Round negative durations down so recently expired certificates are classified as expired. |
| Endpoint ports | Bracketed IPv6 ports were ignored; malformed ports fell back to 443; enormous integers could overflow. | Parse bracketed authorities, retain explicit invalid ports for validation, and bound numeric input before arithmetic. |
| Fingerprints | A mismatch printed an error but exited successfully. | Validate expected SHA-256 input and return 1 for mismatch, 2 for invalid input. |
| DNS | Transport failures and SERVFAIL/REFUSED could look like absent records or unpublished policies; mail posture omitted its advertised MX records. | Preserve DNS response status through concurrent jobs and display unknown states. Strict audits count incomplete DNS policy checks as MEDIUM. Existing policy fallback resolvers remain in use. Include MX records sorted by preference. CAA presence alone no longer claims issuance restriction. |
| HTTP | A failed redirect could leave partial headers; failed TRACE/CORS/cookie/exposure probes could imply clean results. | Discard incomplete header transfers and explicitly report unavailable checks. A failed cipher scan also produces an incomplete-check finding. |
| CRLs | Signature-verified but stale/future CRLs were accepted, and serial substring matching could produce false revocations. | Validate thisUpdate/nextUpdate and compare complete normalized serials. |
| Private files | PFX bundles inherited the caller's permissive umask; password EOF could create a blank-password bundle; failed CSR generation left partial files. | Use a private umask during creation, cancel on EOF, and clean up failed output. Detect existing third-argument PFX destinations consistently. |
| CT | Duplicate names could show an older certificate depending on response order; unexpected JSON structures crashed. | Retain the latest observed expiry for each name, validate response structure and require a positive limit. |
| Installation | The updater rejected Git worktrees; installed README image links lacked their docs directory. | Accept worktree Git metadata and copy optional documentation. Clarify that updates run from a checkout, not the installed non-Git copy. |

## Protected behavior

The registrar domain reduction, WHOIS parsing, registrar-handle fallback,
WHOIS utility, site registrar probe and hosting/IP-WHOIS helper are unchanged.
All timeout and retry defaults are unchanged. Exact WHOIS fixtures still cover
single-line, multiline and NORID handle responses and the kommune.no exception.

## Verification

`tests/audit.py` adds offline fault injection, real OpenSSL certificates and
signed CRLs, a loopback TLS 1.3-only endpoint, private-file checks and a real
local Git-worktree update/install test. The full smoke command runs this suite
alongside the existing report, certificate and presentation tests. CI also runs
ShellCheck and the concurrent-probe performance budgets.

This is a source and regression audit. It does not establish compatibility with
every live DNS provider, registrar, remote TLS stack or external API. Domain
WHOIS/registrar behavior was deliberately excluded from modification.
