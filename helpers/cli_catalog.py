"""One help catalogue for the public check and ssl commands."""

OUTPUT = [('--no-color', 'Disable ANSI colors; NO_COLOR is also supported.'),
          ('--color', 'Force colors and the formatted terminal view.'),
          ('--ascii', 'Use ASCII borders and status markers.'),
          ('--plain', 'Use simple line-by-line output.'),
          ('--help, -h', 'Show help for this command.')]
EXITS = [('0', 'Command completed; audit findings may still exist without --strict.'),
         ('1', 'Operational failure, key mismatch, or MEDIUM strict-audit finding.'),
         ('2', 'Invalid usage, or HIGH/CRITICAL strict-audit finding.'),
         ('127', 'A required command dependency is missing.')]
DNS = [('--dns [TYPE]', 'DNS records; optionally select one record type.'),
       ('--reverse', 'PTR records for a domain or IP address.'),
       ('--mail [selector]', 'MX, SPF, DMARC, DKIM, MTA-STS and TLS-RPT.'),
       ('--dnssec', 'DNSSEC records and resolver validation.'),
       ('--trace', 'DNS delegation trace from the root.'),
       ('--whois', 'Registrar, registration dates and domain status.'),
       ('--hosting', 'Likely provider, evidence and confidence.'),
       ('--no-rdns', 'Skip reverse-DNS lookups in the fast overview.')]
AUDIT = [('--audit', 'Low-impact DNS, TLS, HTTP and exposure audit.'),
         ('--strict', 'Return non-zero for MEDIUM-or-higher findings.'),
         ('--no-paths', 'Skip accidental-exposure path probes.'),
         ('--port N', 'HTTPS/TLS port; default: 443.'),
         ('--deep --authorized', 'Add authorized DNS and network probes.'),
         ('--ports --authorized', 'Add deep mode and a top-100 TCP inventory.')]

# Canonical name: summary, arguments, aliases, examples, details, local options.
SSL = {
    'cert': ('Inspect a live certificate', '<domain> [port]', ['c', 'certificate'],
             ['ssl cert example.com', 'ssl c example.com 8443'],
             'Subject, issuer, validity, SANs, key details, SHA-256 fingerprint, CA verification and identity match.', []),
    'quick': ('Compact certificate health', '<domain> [port]', ['q'],
              ['ssl q example.com'], 'Issuer, expiry and days remaining.', []),
    'chain': ('Inspect the served certificate chain', '<domain> [port]', ['ch'],
              ['ssl chain example.com'], 'Shows native OpenSSL handshake and served-chain output.', []),
    'fetch': ('Test SNI against a specific server IP', '<server-ip> <domain> [port]', ['f'],
              ['ssl fetch 203.0.113.10 example.com'], 'Useful before changing DNS or when testing a hosting node.', []),
    'versions': ('Probe TLS protocol support', '<domain> [port]', ['v', 'version'],
                 ['ssl versions example.com'], 'Uses version flags available in the local OpenSSL build.', []),
    'ciphers': ('Enumerate accepted cipher suites', '<domain> [port]', ['ci', 'cipher'],
                ['ssl ciphers example.com'], 'Uses sslscan when installed, otherwise nmap ssl-enum-ciphers. Native output follows the command header.', []),
    'scan': ('Run sslscan', '<domain> [port]', ['s'],
             ['ssl scan example.com'], 'Requires the optional sslscan package. Shows native scanner output.', []),
    'ocsp': ('Check certificate OCSP status', '<domain> [port]', ['o'],
             ['ssl ocsp example.com'], 'Checks the advertised responder and verifies the OCSP response.', []),
    'crl': ('Check certificate revocation lists', '<domain> [port]', [],
            ['ssl crl example.com'], 'Retrieves the advertised CRL and verifies its signature before checking the serial.', []),
    'ct': ('Find Certificate Transparency names', '<domain>', ['ctlogs', 'transparency'],
           ['ssl ct example.com'], 'Queries crt.sh and shows unique names, expiry dates and issuers.', []),
    'headers': ('Inspect HTTPS security headers', '<domain-or-url>', ['h', 'header'],
                ['ssl headers https://example.com'], 'Shows final-response security headers and exposed server identifiers.', []),
    'performance': ('Benchmark TLS handshakes', '<domain> [port] [seconds]', ['perf', 'bench'],
                    ['ssl perf example.com 443 5'], 'Runs native OpenSSL s_time output; duration must be 1–300 seconds.', []),
    'fingerprint': ('Show or compare a certificate fingerprint', '<domain> [expected-sha256] [port]', ['fp', 'pin', 'pinning'],
                    ['ssl fp example.com'], 'SHA-256 comparison ignores colons, whitespace and letter case.', []),
    'decode': ('Decode a certificate, CSR or key file', '<certificate.pem|request.csr|private.key>', ['d'],
               ['ssl decode site.crt'], 'Shows native OpenSSL detail. Private-key decoding displays public-key data.', []),
    'match': ('Compare certificate, CSR and private-key public keys', '<cert|csr|key> <cert|csr|key> [more files...]', ['m', 'modulus'],
              ['ssl match site.crt site.csr site.key'], 'Compares SHA-256 hashes of canonical DER public keys; supports RSA and EC.', []),
    'new': ('Create a private key and CSR', '<common-name> [options]', ['n', 'csr'],
            ['ssl new example.com --san www.example.com --out site'], 'SAN names can be repeated. Existing key and CSR files are never overwritten.',
            [('--san NAME', 'Add a DNS name or IP SAN; repeat as needed.'),
             ('--out PREFIX', 'Output prefix; default: common name.'),
             ('--rsa BITS', 'RSA key size, 2048–16384; default: 2048.'),
             ('--ec CURVE', 'EC key; default curve: prime256v1.'),
             ('--encrypted', 'Encrypt the private key and prompt for its password.')]),
    'pack': ('Create a PKCS#12/PFX bundle', '<certificate.pem> <private.key> [chain.pem] [output.pfx]', ['pk', 'pfx-pack'],
             ['ssl pack site.crt site.key chain.pem site.pfx'], 'Prompts for a PFX password. DSU_PFX_PASSWORD supports automation; a blank password is allowed. Existing bundles are never overwritten.', []),
    'extract': ('Extract a PKCS#12/PFX bundle', '<bundle.pfx> [output-directory]', ['x', 'pfx-extract'],
                ['ssl extract site.pfx'], 'Prompts for the PFX password. Extracts an unencrypted private key with mode 0600 into a directory with mode 0700. Existing directories are never overwritten.', []),
}


def ssl_name(name):
    name = name.lower()
    return next((key for key, data in SSL.items() if name == key or name in data[2]), None)


def document(command, description, usage, groups, examples=(), details='', aliases=()):
    usages = usage if isinstance(usage, list) else [usage]
    sections = [('USAGE', [('', 'Usage: ' + value) for value in usages])] + list(groups)
    if aliases:
        sections.append(('ALIASES', [('', ', '.join(aliases))]))
    if examples:
        sections.append(('EXAMPLES', [('', example) for example in examples]))
    if details:
        sections.append(('DETAILS', [('', details)]))
    return command, description, sections


def help_document(family, topic=''):
    if family == 'setup':
        return document('setup.sh', 'Install or refresh the per-user command links.', './setup.sh [--force]',
                        [('OPTIONS', [('--force', 'Replace conflicting command links.')] + OUTPUT),
                         ('LOCATIONS', [('DSU_INSTALL_DIR', 'Default: ~/.local/share/dns-ssl-utilities'),
                                        ('DSU_BIN_DIR', 'Default: ~/.local/bin')])],
                        ['./setup.sh', './setup.sh --force'],
                        'Installs check and ssl. Safe to rerun; optional documentation is not required.')
    if family == 'update':
        return document('update.sh', 'Update a source checkout and refresh the installed copy.', './update.sh',
                        [('OUTPUT', OUTPUT)], ['./update.sh'],
                        'Requires a Git checkout. Uses git pull --ff-only, then runs setup.sh. An installed archive/copy without Git metadata must be refreshed from its source checkout or a newer release.')
    if family == 'ssl' and ssl_name(topic or ''):
        name = ssl_name(topic)
        summary, args, aliases, examples, notes, options = SSL[name]
        if '[port]' in args:
            notes += ' Port defaults to 443.'
        return document(f'ssl {name}', summary, f'ssl {name} {args}',
                        [('OPTIONS', options + OUTPUT)], examples, notes,
                        [f'ssl {alias}' for alias in aliases])
    if family == 'ssl':
        names = list(SSL)
        remote = [(f'{name}, {SSL[name][2][0]}' if SSL[name][2] else name, SSL[name][0]) for name in names[:13]]
        files = [(f'{name}, {SSL[name][2][0]}', SSL[name][0]) for name in names[13:]]
        return document('ssl', 'Certificates, live endpoints, TLS and key files.', 'ssl <command> [flags]',
                        [('LIVE ENDPOINTS', remote), ('FILES & KEYS', files), ('OUTPUT', OUTPUT)],
                        ['ssl c example.com', 'ssl fetch 203.0.113.10 example.com', 'ssl match site.crt site.csr site.key'],
                        'Run ssl <command> --help for arguments, aliases and examples.')
    if topic == 'audit':
        return document('check --audit', 'DNS, TLS, HTTP and accidental-exposure review.',
                        'check <domain-or-url> --audit [options]', [('OPTIONS', AUDIT[1:] + OUTPUT),
                        ('SEVERITY', [('CRITICAL / HIGH', 'Direct exposure, identity failure or severe legacy crypto.'),
                                      ('MEDIUM', 'Material hardening gap or risky server behavior.'),
                                      ('LOW / INFO', 'Defense-in-depth findings and context.')]), ('EXIT CODES', EXITS)],
                        ['check example.com --audit', 'check example.com --audit --strict',
                         'check example.com --audit --deep --authorized'],
                        'Default mode is low-impact and non-destructive. Deep mode adds AXFR, recursion, broader TLS review and safe nmap scripts. --deep/--ports require --authorized; use only on systems you own or are explicitly authorized to assess. No credential attacks, destructive fuzzing, denial of service, authentication bypass or exploit execution.')
    domain = {
        'dns': ('Inspect DNS records', '--dns [TYPE]', ['check example.com --dns', 'check example.com --dns MX'],
                'TYPE: A, AAAA, MX, NS, TXT, CAA, SOA, CNAME, SRV, DS or DNSKEY. Omit TYPE for the multi-record summary.'),
        'reverse': ('Inspect reverse DNS', '--reverse', ['check 192.0.2.10 --reverse'], 'Shows PTR records for a domain or IP address.'),
        'mail': ('Inspect mail and sender policies', '--mail [selector]', ['check example.com --mail', 'check example.com --mail selector1'],
                 'Checks SPF, DMARC, CAA, MTA-STS, TLS-RPT and selected DKIM selectors. A missing checked DKIM selector is not definitive proof that DKIM is absent.'),
        'dnssec': ('Inspect DNSSEC records and validation', '--dnssec', ['check example.com --dnssec'], 'Shows DNSKEY, DS and the configured resolver AD flag.'),
        'trace': ('Trace delegation from the DNS root', '--trace', ['check example.com --trace'], 'Shows native dig +trace output.'),
        'whois': ('Inspect domain registration details', '--whois', ['check example.com --whois'], 'Shows registrar, creation and expiry dates, domain status and nameservers when available.'),
        'hosting': ('Identify likely hosting infrastructure', '--hosting', ['check example.com --hosting'], 'Shows the likely provider with supporting evidence and confidence.'),
        'doctor': ('Inspect runtime and dependencies', '--doctor', ['check --doctor'], 'Shows versions, installed dependencies and network timeout settings.'),
    }
    if topic in domain:
        summary, args, examples, notes = domain[topic]
        usage = 'check --doctor' if topic == 'doctor' else f'check <domain-or-ip> {args}'
        return document(f'check {args.split()[0]}', summary, usage, [('OUTPUT', OUTPUT)], examples, notes)
    return document('check', 'Domain, DNS, mail, hosting and TLS diagnostics.',
                    ['check <domain-or-ip> [flags]', 'check --doctor', 'check --version', 'ssl <command> [flags]'],
                    [('DOMAIN & DNS', DNS), ('SECURITY AUDIT', AUDIT), ('OUTPUT', OUTPUT + [('--doctor', 'Inspect runtime and dependencies.'),
                     ('--version', 'Print the installed version.')]), ('EXIT CODES', EXITS)],
                    ['check example.com', 'check example.com --dns MX', 'check example.com --mail', 'check example.com --audit', 'ssl c example.com'],
                    'Use one utility flag per invocation. Without one, check prints the fast domain overview. Audit options follow --audit. Run check example.com --dns --help or ssl cert --help for focused help.')
