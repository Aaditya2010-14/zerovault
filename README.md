# ZeroVault

An encrypted password manager, TOTP 2FA generator, secrets scanner, and local
web dashboard — built entirely on the Go 1.27 standard library. No
third-party runtime dependencies, no `golang.org/x/*`, no custom crypto
algorithms: only composition of `crypto/aes`, `crypto/cipher`,
`crypto/hmac`, `crypto/sha256`, `crypto/sha1`, and `crypto/rand`.

Built for the Zero Dependency 2026 Hackathon, Track E (Security & Crypto
Utilities).

**Features:**
- Encrypted password vault (AES-256-GCM, PBKDF2-derived key) — add, edit,
  delete, and browse entries from the CLI or the web dashboard
- TOTP 2FA code generator (RFC 6238), including QR code generation
  (`zerovault totp qr`) for re-enrolling a secret in an authenticator app
- Secrets scanner for a working directory or a git repository's full commit
  history, pattern- and entropy-based
- File encryption/decryption (`zerovault encrypt`/`decrypt`) for arbitrary
  files, independent of the vault
- Password health dashboard — flags weak, reused, and stale passwords
  across every vault entry
- Cryptographically random password generator with live strength estimate
  and crack-time projection
- Master password rotation (`zerovault rekey`) — re-encrypts the entire
  vault under a freshly derived key
- Local-only web dashboard (`zerovault serve`) mirroring every CLI
  capability, plus an About page describing the project
- Built-in penetration test suite (`zerovault attack`) — 13 real attacks
  against the live crypto and web code, not simulated, exportable as a
  self-contained HTML report (`--report`) or viewed on the dashboard's
  Audit page
- Offline breach-password check against 900+ known compromised passwords
  (SHA-256 hash comparison, never plaintext), surfaced in the generator,
  add/edit flow, and health dashboard
- Clipboard auto-clear — copied passwords are wiped from the clipboard 10
  seconds after being copied, from both the CLI and the web dashboard
- Optional two-factor unlock for the vault itself (`zerovault init --2fa`
  / `zerovault 2fa enable`) — TOTP secret stored inside the encrypted
  vault, requiring both the master password and a live code to unlock

Project overview page: `landing.html` in this repo, published at
`https://Aaditya2010-14.github.io/zerovault/landing.html` once GitHub Pages
is enabled on this repo.

## Build

```bash
go build -o zerovault ./cmd/zerovault
```

That's it — one command, one binary, no external files needed at runtime
(templates and static assets for the web dashboard are compiled in via
`//go:embed`).

Go version: **1.27.0**, pinned in `go.mod`.

## Demo Mode

Try ZeroVault in 10 seconds with pre-loaded test data:

```bash
go build -o zerovault ./cmd/zerovault
./zerovault demo
```

This creates a temporary vault (password: `demo2026`) with sample entries, TOTP secrets, and a test project with planted secrets for the scanner. Open http://127.0.0.1:8787 in your browser.

Try these commands in a second terminal:
- `zerovault get github` — retrieve a password
- `zerovault health` — see breach detection
- `zerovault totp get github-2fa` — compare with Google Authenticator
- `zerovault scan demo-project/` — find leaked secrets
- `zerovault scan --git demo-project/` — find deleted secrets in git history
- `zerovault attack --report audit.html` — run full security audit

To clean up: `zerovault demo --cleanup` or press Ctrl+C.

## Architecture

```
                      ┌─────────────────────┐
                      │   cmd/zerovault      │  entry point
                      └──────────┬───────────┘
                                 │
                      ┌──────────▼───────────┐
                      │   internal/cli        │  command dispatch
                      └───┬───────┬───────┬───┘
             ┌────────────┘       │       └────────────┐
             ▼                    ▼                     ▼
   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐
   │ internal/vault   │  │ internal/scanner │  │ internal/web         │
   │ (CRUD, storage)  │  │ (secrets scan)   │  │ (dashboard, sessions)│
   └────────┬─────────┘  └──────────────────┘  └──────────┬───────────┘
            │                                              │
            ▼                                              │
   ┌─────────────────┐   ┌──────────────────┐              │
   │ internal/crypto  │   │ internal/totp     │◄─────────────┘
   │ PBKDF2, AES-GCM  │   │ HOTP/TOTP, base32 │
   │ crypto/rand      │   │                    │
   └──────────────────┘   └───────────────────┘

   attacks/                   internal/cli/attack.go
   (self-contained pentest    ("zerovault attack" —
    suite, real crypto +      runs every attack, prints
    real HTTP against a       a pass/fail report card)
    disposable fixture vault)
```

Vault file on disk: `salt(16) || nonce(12) || AES-256-GCM(ciphertext || tag)`.
Every field after the salt is authenticated by the GCM tag — any tampering
anywhere in the file is detected on load.

## Usage

### Vault (password manager)

```bash
zerovault init                                    # create a new vault, set master password
zerovault add github --username dev@x.com          # add an entry (prompts for password)
zerovault add slack --generate --length 24          # add an entry with a generated password
zerovault get github                                # print an entry
zerovault get github -copy                          # copy password to clipboard (auto-clears in 10s)
zerovault list                                       # list all entry names
zerovault delete github                              # remove an entry
zerovault generate --length 32 --no-symbols          # generate a password without saving it
```

### TOTP (2FA codes)

```bash
zerovault totp add github-2fa                        # prompts for the base32 secret
zerovault totp add github-2fa --generate              # or generate a brand-new secret
zerovault totp get github-2fa                         # print the current 6-digit code
zerovault totp list                                   # list all TOTP entries with live codes
zerovault totp qr github-2fa                          # print a scannable QR code (otpauth:// URI) to the terminal
zerovault totp qr github-2fa -svg out.svg              # write the QR code as an SVG file instead
```

QR codes are generated entirely from stdlib primitives (`internal/qrcode`):
Reed-Solomon error correction over `GF(256)`, module layout (finder/timing/
alignment patterns), masking, and ASCII/SVG rendering, all hand-built — see
`STDLIB.md` entry 20. The encoded payload is a standard `otpauth://totp/...`
Key URI, so scanning it with Google Authenticator, Authy, or any other RFC
6238-compatible app enrolls the same secret ZeroVault already has stored.

### Secrets scanner

```bash
zerovault scan .                                      # scan the current directory
zerovault scan --min-entropy 4.0 ./some-project        # tune generic-secret sensitivity
```

Exit codes: `0` no findings, `1` warnings only, `2` at least one critical
finding — designed to be CI-friendly.

```bash
zerovault scan --git ~/my-project/              # scan git commit history for leaked secrets
zerovault scan --git ~/my-project/ -depth 100    # scan the last 100 commits (default: 50)
```

Reads `.git/objects` directly (`internal/gitscan`) — no shelling out to
`git`. Walks the commit graph from HEAD, scans every distinct file blob
it finds (identical content across commits is only scanned once) with the
same pattern/entropy detection as a regular scan, and flags anything whose
path no longer exists in HEAD's tree as **deleted in a later commit — but
still in history**. Only loose objects are supported (see `STDLIB.md`
entry 19) — a `git gc`'d repository with packed objects is out of scope.

### Web dashboard

```bash
zerovault serve                                        # http://127.0.0.1:8787
zerovault serve -addr 127.0.0.1:9000                    # custom port, still loopback-only
```

### Master password rotation

```bash
zerovault rekey    # change the vault's master password
```

Prompts for the current password, decrypts, prompts for a new password
(with confirmation), then re-encrypts every entry, TOTP secret, and note
under a freshly derived key with a brand-new random salt — the same
`vault.Save` path used everywhere else, so the write is atomic (temp file
+ rename) and a crash mid-rekey leaves either the untouched old vault or
the fully-written new one. `vault.Rekey` verifies the new password by
loading the vault back before returning. Also available from the
dashboard's Settings page, which signs you out afterward since the
session's old password no longer matches what's on disk.

### File encryption

```bash
zerovault encrypt report.pdf                 # -> report.pdf.enc (prompts for a password)
zerovault encrypt report.pdf -o backup.enc    # custom output name
zerovault decrypt report.pdf.enc              # -> report.pdf (original filename recovered automatically)
zerovault decrypt backup.enc -o restored.pdf  # custom output name
```

Encrypts any file — independent of the vault and its master password — with
AES-256-GCM under a PBKDF2-derived key, the same crypto pipeline the vault
itself uses. Files are streamed in 64KB chunks rather than loaded whole into
memory, so multi-hundred-megabyte files work without excessive RAM use; each
chunk is sealed under its own nonce (see `internal/fileenc` and `STDLIB.md`
entry 17), so tampering *or* truncating the ciphertext is always detected
before any plaintext is written to disk. The original filename travels
inside the encrypted envelope, so `decrypt` without `-o` restores it exactly.
The same flow is available from the dashboard's File Encryption page
(upload → encrypt/decrypt → download).

### Password health

```bash
zerovault health    # colorized health report in the terminal
```

Also available as the dashboard's Health page. Every entry gets an
entropy-based strength score (Weak / Fair / Strong / Very Strong from
`length * log2(charset size)`), checked against a built-in list of 100
commonly leaked passwords and a few common substrings (123/abc/qwerty).
Reused passwords are found by comparing SHA-256 hashes (never plaintext),
and entries not rotated in 90+ days are flagged. The overall vault score
starts at 100% and loses points per finding — red below 50%, yellow below
80%, green above.

### Security audit (attack suite)

```bash
zerovault attack
```

Runs 13 real attacks — dictionary brute force, GCM bit-flip/truncation
tampering, PBKDF2 timing analysis, nonce-reuse detection, encrypted-file
tampering, XSS injection, CSRF, session hijacking attempts, security-header
checks, path traversal, TOTP brute force, and a vault-2FA-unlock bypass
attempt (password-only, password+wrong-code, password+correct-code) —
against a disposable fixture vault and a real, locally-running copy of the
dashboard. See `attacks/` for the source; each attack performs the real
cryptographic operation or real HTTP request it claims to, not a
simulated one.

Add `--report <path>` to write a self-contained HTML report (results,
per-test methodology, timings, pass/fail badges — no external assets, no
JavaScript) instead of just printing to the console:

```bash
zerovault attack --report audit.html
```

The dashboard also has an **Audit** page (`/audit`) showing the same
results — the CLI and the web page share one in-memory report from the
last run, so running the suite from either place updates both.

### Two-factor vault unlock

```bash
zerovault init --2fa          # create a new vault with 2FA enabled
zerovault 2fa enable          # add 2FA to an existing vault
zerovault 2fa disable         # remove it (requires a valid code)
```

Both commands generate a fresh TOTP secret, show it as a terminal QR code
(scan with any authenticator app) plus the raw secret for manual entry,
and require you to type back one currently-valid code before the change
takes effect — this catches a bad scan or transcription before it locks
you out. The secret is stored as a field on the `Vault` struct itself
(`internal/vault/vault.go`), so it's encrypted under the master password
exactly like every entry — no separate secret store.

Once enabled, every unlock — CLI (`get`, `add`, `list`, ...) and web —
requires both the master password and a current code. The web dashboard's
`/unlock` only reveals the second step *after* the password has already
been verified, so a wrong password never leaks whether 2FA is on for that
vault. Settings has a matching card to set up, or disable, 2FA for an
already-unlocked vault.

## Threat model

### What ZeroVault protects against

- **Offline vault theft** — an attacker who copies `vault.db` cannot read
  it without the master password. Key derivation is PBKDF2-HMAC-SHA256 at
  100,000 iterations (`internal/crypto/pbkdf2.go`), making each guess
  measurably slow (see `zerovault attack`'s brute-force timing).
- **Vault tampering** — AES-256-GCM's authentication tag covers the entire
  ciphertext. Any bit flip, truncation, or byte injection is detected on
  load and rejected outright (no partial/garbage decrypt is ever returned).
- **Nonce reuse** — every save draws a fresh 12-byte nonce from
  `crypto/rand`; nonces are never derived, counted, or reused across saves.
- **XSS in the web dashboard** — all user-supplied data (entry names,
  usernames, notes, URLs) is rendered through `html/template`, which
  auto-escapes by output context (HTML body, HTML attribute, URL). No
  `template.HTML()` bypass exists anywhere in this codebase.
- **CSRF against the dashboard** — every mutating route is wrapped in
  `net/http.NewCrossOriginProtection()` (Go 1.25+), which rejects any
  request whose `Sec-Fetch-Site`/`Origin` doesn't match the server's own
  origin. No hand-rolled token scheme was needed.
- **Session hijacking via XSS** — session cookies are `HttpOnly` (invisible
  to JavaScript) and `SameSite=Strict` (never sent cross-site), with a
  15-minute sliding expiry enforced server-side.
- **Clickjacking / MIME sniffing / referrer leakage / password caching** —
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` are set on
  every response (`internal/web/security.go`).
- **Unthrottled master-password guessing via the web UI** — `/unlock`
  applies a 5-second delay after 5 failed attempts and a 60-second lockout
  after 10, on top of PBKDF2's own per-guess cost.
- **Scanning outside the intended target** — the dashboard's scanner
  rejects paths that don't exist, aren't directories, or are well-known
  system roots (`C:\`, `C:\Windows`, `/`, `/etc`, ...).
- **Tampered or truncated encrypted files** — `zerovault encrypt`/`decrypt`
  seals every 64KB chunk under its own nonce, with the final chunk's
  "last chunk" status bound into that nonce. A bit flip anywhere, or the
  file being cut short, is rejected before any plaintext is written —
  verified by `zerovault attack`'s file-tamper test and by
  `internal/fileenc`'s own test suite.
- **Clipboard auto-clear** — passwords are removed from the clipboard 10
  seconds after being copied (CLI `-copy` and every web UI copy button), to
  prevent accidental paste or clipboard scraping by another process.
- **Vault unlock with a stolen/guessed master password alone** — when
  two-factor unlock is enabled (`zerovault init --2fa` / `2fa enable`),
  knowing the master password is not sufficient: a current TOTP code is
  also required, both on the CLI and the web dashboard. The web unlock
  flow verifies the password before ever revealing that a code is needed,
  so a failed guess can't be used to fingerprint which vaults have 2FA on.

### What ZeroVault does NOT protect against (and why that's an acceptable
hackathon-scope trade-off)

- **Keyloggers / screen capture / clipboard snooping on the local
  machine.** If the machine is already compromised at that level, no
  application-layer defense here can help — this is true of essentially
  every password manager. (Clipboard contents are cleared automatically
  after 10 seconds to shrink this window.)
- **Memory forensics.** The decrypted vault and master password live in
  process memory for the session's duration; a memory dump of a running
  `zerovault` process would expose them. Go's garbage collector doesn't
  guarantee zeroing freed memory, and scrubbing secrets reliably in a
  managed-memory language is its own hard problem — out of scope here.
- **Master password reuse across services.** ZeroVault cannot detect or
  prevent a user reusing their vault's master password elsewhere.
- **GPU/ASIC-accelerated offline brute force.** PBKDF2-SHA256 is far more
  resistant to parallelization than an unsalted hash, but it is not
  memory-hard the way Argon2 is. Argon2 would need
  `golang.org/x/crypto/argon2`, which is explicitly disallowed by this
  hackathon's zero-dependency rule (see Design Decisions below) — so
  PBKDF2 at a high iteration count is the strongest option available from
  stdlib alone.
- **Network eavesdropping on the dashboard.** `zerovault serve` binds to
  the loopback interface only (`127.0.0.1`/`localhost`) and this is
  enforced in code (`internal/cli/serve.go: isLoopbackHost`), not just
  documented — but the connection itself is plain HTTP, no TLS. This is
  acceptable because loopback traffic never leaves the machine; it would
  not be acceptable if this server were ever bound to a non-loopback
  address, which the code refuses to do.
- **TOTP code brute force.** `zerovault attack`'s TOTP test demonstrates
  that a 6-digit code space (1,000,000 possibilities) can be exhausted in
  well under a second. This is expected and matches how every TOTP
  implementation works — TOTP's security guarantee is "you cannot predict
  the *next* code without the secret", not "the current code is
  unguessable". Real-world protection against this comes from the
  verifying service's own rate limiting (typically 3-5 attempts), which is
  outside ZeroVault's scope since ZeroVault is a code *generator*, not a
  verifying relying party.
- **Vault-level 2FA is a login gate, not extra encryption strength.**
  The TOTP secret is stored inside the same encrypted vault blob it
  protects, so anyone who has actually broken the master-password
  encryption (offline, given enough time/luck) can also read the 2FA
  secret and generate valid codes — 2FA here does not add cryptographic
  work to an offline attack the way a second independent key would. What
  it *does* add: an online attacker who has obtained the master password
  some other way (phishing, shoulder-surfing, a synced password manager
  leak) still cannot unlock the vault without also having the physical
  authenticator device. There are deliberately no recovery codes — a
  recovery code would just be a second secret to protect, and losing both
  the master password and the TOTP device makes the vault unrecoverable
  by design, the same as losing the master password alone.
- **A malicious or compromised build of ZeroVault itself.** As with any
  security tool, the user must trust the binary they run. The reproducible
  build section below lets anyone verify a given binary matches this
  source.

## Design decisions

- **AES-GCM over AES-CBC.** GCM is authenticated encryption — it detects
  tampering as part of decryption itself. CBC is not authenticated on its
  own and would need a separate MAC (encrypt-then-MAC) to reach the same
  guarantee, which is more code and more ways to get the composition
  wrong. GCM lets `crypto/cipher` do that correctly in one call.
- **PBKDF2, not Argon2.** Argon2 (memory-hard, generally preferred for new
  designs) lives in `golang.org/x/crypto/argon2`, which is a
  `golang.org/x/*` package — explicitly banned by this hackathon's
  zero-dependency rule. PBKDF2-HMAC-SHA256 is fully available in the
  standard toolbox (`crypto/hmac` + `crypto/sha256`, composed per RFC 8018
  in `internal/crypto/pbkdf2.go`) and, at 100,000 iterations, is still a
  meaningful barrier to offline guessing.
- **SHA-1 for TOTP, not SHA-256.** This looks backwards until you read RFC
  6238: it standardizes HMAC-SHA1 as the default TOTP algorithm, and every
  major authenticator app (Google Authenticator, Authy, etc.) expects it
  unless the provisioning URI explicitly says otherwise. Using SHA-256
  here would make ZeroVault's TOTP codes incompatible with real
  authenticator apps — the whole point of implementing RFC 6238. HMAC-SHA1
  is not broken as a MAC (the SHA-1 weaknesses are collision attacks,
  irrelevant to HMAC's construction); it's simply the interoperability
  requirement.
- **`net/http` directly, not a framework.** A stdlib-only project has no
  framework to reach for anyway, but even setting that aside: Go 1.22+'s
  `http.ServeMux` already supports method-based and wildcard routing
  (`"POST /delete/{name}"`), and Go 1.25 added `CrossOriginProtection`
  built in. Between those two additions, the stdlib router covers what a
  small dashboard like this needs without extra abstraction.
- **Reading `.git/objects` directly, not shelling out to `git`.** Parsing
  the object store (zlib-inflating blobs/trees/commits and walking the
  commit graph by hash, in `internal/gitscan`) keeps the scanner working
  anywhere Go runs, with no dependency on a `git` binary being installed or
  on its output format being stable across versions — and it's a small
  enough format that reimplementing the read path is less risk than
  shelling out and parsing `git log`/`git show` text output.
- **A dedicated `attacks/` package instead of inline demo commands.** Every
  claim in the threat model above ("XSS is blocked", "nonce reuse never
  happens") is backed by a real, runnable attack in `attacks/`, not just
  prose. `zerovault attack` is meant to be verifiable by anyone, not just
  trusted on the README's word.

## Testing

```bash
go test ./...
go vet ./...
gofmt -l .          # should print nothing
```

Cryptographic primitives are validated against official published test
vectors before anything is built on top of them:
- PBKDF2 — RFC 6070 test vectors (`internal/crypto/pbkdf2_test.go`)
- HOTP — RFC 4226 Appendix D test vectors (`internal/totp/hotp_test.go`)
- TOTP — RFC 6238 Appendix B test vectors (`internal/totp/totp_test.go`)

## Dependency proof

`go.mod`:

```
module zerovault

go 1.27
```

No `require` block — there is nothing to require. `go list -m all` output
(saved in `deps-proof.txt`):

```
zerovault
```

## Reproducible build

```
Build 1: 1c2b83848ef2a6a54edcd6a91013d2fee48b50aa242ef56d8333541571092de1
Build 2: 1c2b83848ef2a6a54edcd6a91013d2fee48b50aa242ef56d8333541571092de1
```

Hashes match — byte-identical output from two independent `go clean
-cache && go build` runs. Verify it yourself with `certutil -hashfile
zerovault SHA256` (Windows) or `sha256sum zerovault` (Linux/Mac).

## Hackathon Bonuses

- **Reproducible Build (+5)** — see above; two independent clean builds
  (`go clean -cache && go build ./cmd/zerovault`) produce byte-identical
  SHA-256 hashes:
  `1c2b83848ef2a6a54edcd6a91013d2fee48b50aa242ef56d8333541571092de1`.
- **Package Killer (+3)** — zero third-party runtime dependencies, no
  `golang.org/x/*`, empty `go.mod` require block. Specific packages
  replaced with stdlib-only equivalents:
  - `truffleHog`/`detect-secrets` → hand-rolled secret scanner and git
    history scanner (`internal/scanner`, `internal/gitscan`)
  - `pquerna/otp` → hand-rolled TOTP/HOTP (`internal/totp`)
  - `gorilla/csrf` → `net/http`'s built-in `CrossOriginProtection`
  - `gin`/`echo` → `net/http` directly
  - `fatih/color` → hand-rolled ANSI codes (`internal/cli/output.go`)
  - `google/uuid` → stdlib `uuid`
- **STDLIB Log (+3)** — 22 documented substitutions in `STDLIB.md`.
- **Single File (+5)** — Not attempted — modular architecture chosen for
  code quality and crypto isolation.
