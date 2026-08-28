# STDLIB.md — third-party packages we didn't use, and what replaced them

Every one of these is a real substitution made during this build, not a
hypothetical. Each entry: what a typical Go project would `go get`, what
stdlib we used instead, why it works, and what we gave up by not reaching
for the ecosystem package.

## 1. Password key derivation — `golang.org/x/crypto/pbkdf2`

**Used instead:** `crypto/hmac` + `crypto/sha256`, composed by hand into
PBKDF2 per RFC 8018 (`internal/crypto/pbkdf2.go`).

**Why it works:** PBKDF2 is just "run HMAC in a loop and XOR the blocks
together" — the RFC fully specifies the algorithm, and `crypto/hmac`
already provides a correct, constant-time-safe HMAC construction. There's
nothing x/crypto's PBKDF2 does that isn't a thin loop over stdlib's HMAC.

**Trade-off:** We had to implement and validate the block-construction loop
ourselves instead of trusting a maintained package — mitigated by testing
against all six official RFC 6070 test vectors before writing any code
that depends on it.

## 2. Password hashing for storage — `golang.org/x/crypto/argon2` /
`bcrypt`

**Used instead:** Same PBKDF2-HMAC-SHA256 as #1, at 100,000 iterations.

**Why it works:** ZeroVault's master password derives an AES key directly
(it's not stored as a hash for later comparison), so PBKDF2's iteration
count is the whole defense against offline guessing — no separate hashing
step needed.

**Trade-off:** Argon2 is memory-hard (resists GPU/ASIC parallelization
far better than PBKDF2); this is the single biggest security trade-off in
the project, and it's documented explicitly in README.md's threat model.

## 3. TOTP/HOTP code generation — `github.com/pquerna/otp`

**Used instead:** `crypto/hmac` + `crypto/sha1`, composed per RFC 4226
(HOTP) and RFC 6238 (TOTP) in `internal/totp/hotp.go` and `totp.go`.

**Why it works:** HOTP is HMAC-SHA1 truncated per a fixed byte-selection
rule from the RFC; TOTP is HOTP with the counter replaced by
`unix_time / period`. Both are small, fully specified algorithms — nothing
about them needs a library beyond a correct HMAC.

**Trade-off:** No built-in QR-code provisioning URI helpers (`otpauth://`
generation/parsing) — ZeroVault's CLI accepts/prints raw base32 secrets
instead of QR codes.

## 4. Base32 secret encoding — `github.com/pquerna/otp`'s helpers

**Used instead:** `encoding/base32`, stdlib.

**Why it works:** Base32 is a fully standardized encoding
(`encoding/base32` implements RFC 4648) with no TOTP-specific behavior
needed beyond padding tolerance, which `internal/totp/base32.go` handles
directly.

**Trade-off:** None — this is a straight, lossless substitution.

## 5. UUID generation — `github.com/google/uuid`

**Used instead:** Go 1.27's stdlib `uuid` package.

**Why it works:** Go 1.27 promoted UUID generation into the standard
library; `uuid.New().String()` is a drop-in replacement for the
third-party package's most common call.

**Trade-off:** None found for this project's usage (random v4 UUIDs as
opaque entry IDs) — no UUID v1/v5 namespace generation was needed anyway.

## 6. JSON serialization — a third-party JSON library (e.g. for
performance or struct-tag ergonomics)

**Used instead:** Go 1.27's `encoding/json/v2`.

**Why it works:** The vault's serialization needs are ordinary struct
marshal/unmarshal with tags — exactly what the stdlib JSON package (v1 or
v2) is built for.

**Trade-off:** None for this workload; v2 mainly improves performance and
some edge-case correctness over v1, both irrelevant at vault-file sizes.

## 7. Web framework — `gin`, `echo`, `chi`, etc.

**Used instead:** `net/http` with Go 1.22+'s `http.ServeMux`
(method + wildcard routing, e.g. `"POST /delete/{name}"`).

**Why it works:** ZeroVault's dashboard has a small, fixed set of routes.
Modern `ServeMux` already does method matching and path parameters —
the two things people usually reach for a router package for.

**Trade-off:** No middleware-chaining sugar, no route grouping — for ~15
routes this cost nothing; it would matter more at 10x the route count.

## 8. CSRF protection — a hand-rolled token middleware or a package like
`gorilla/csrf`

**Used instead:** Go 1.25+'s `net/http.NewCrossOriginProtection()`.

**Why it works:** It's now a stdlib primitive purpose-built for exactly
this: rejecting cross-origin state-changing requests by checking
`Sec-Fetch-Site`/`Origin` against the server's own origin.

**Trade-off:** Less configurable than some third-party CSRF middlewares
(e.g. no per-route opt-out granularity beyond what the API exposes), which
wasn't needed here.

## 9. HTML templating with auto-escaping — a template engine
(`pongo2`, etc.)

**Used instead:** `html/template`, stdlib.

**Why it works:** `html/template` auto-escapes by output context (HTML
body vs. attribute vs. URL vs. JS) automatically — the exact defense the
dashboard's XSS protection depends on, with zero extra configuration.

**Trade-off:** Less expressive template syntax than some third-party
engines (no template inheritance beyond Go's own `{{define}}`/`{{template}}`
blocks) — sufficient for eight simple pages.

## 10. Structured logging — `zerolog`, `zap`, `logrus`

**Used instead:** `log/slog`, stdlib (Go 1.21+).

**Why it works:** The dashboard's server-side error logging needs
structured key/value fields (`s.logger.Error("scan failed", "path", path,
"error", err)`) and level filtering — exactly `slog`'s design.

**Trade-off:** None meaningful for this project's logging volume.

## 11. Embedding static web assets — a build step that generates Go
byte slices, or reading files at runtime

**Used instead:** `//go:embed`, stdlib (Go 1.16+).

**Why it works:** `embed.FS` compiles `web/templates` and `web/static`
directly into the binary, which is also *why* the build stays a single
`go build` command with no separate asset-bundling step.

**Trade-off:** Assets are fixed at compile time — updating a template
requires a rebuild, not a deploy of loose files. For a single-binary CLI
tool, that's the desired behavior, not a limitation.

## 12. Password-strength / random-string generation — a package like
`sethvargo/go-password`

**Used instead:** `crypto/rand` plus a hand-written rejection-sampling
loop (`internal/crypto/random.go`).

**Why it works:** Uniform random character selection is a small, easily
verified algorithm; rejection sampling against `crypto/rand.Read` avoids
the modulo bias a naive `byte % n` would introduce, which is the one
subtlety such packages exist to get right.

**Trade-off:** No built-in "avoid ambiguous characters (0/O, 1/l)" preset
some third-party generators ship — not implemented here.

## 13. Clipboard access — `atotto/clipboard` or similar

**Used instead:** `os/exec`, shelling out to the platform's native
clipboard utility (`clip` on Windows, `pbcopy`/`xclip` elsewhere) —
`internal/vault/clipboard.go`.

**Why it works:** Every mainstream OS ships a command-line clipboard tool;
piping to it from `os/exec` needs no CGo and no platform-specific binding
code beyond picking the right command name.

**Trade-off:** Depends on the platform utility being installed (true for
Windows/macOS by default; `xclip`/`xsel` may need installing on some Linux
distros) — a third-party package with native bindings wouldn't have this
gap, at the cost of CGo or platform-specific build tags.

## 14. No-echo password input (masked terminal prompts) —
`golang.org/x/term`

**Used instead:** Raw platform syscalls — `kernel32.dll`
`GetConsoleMode`/`SetConsoleMode` on Windows
(`internal/cli/password_windows.go`), `TCGETS`/`TCSETS` ioctls on Unix
(`internal/cli/password_unix.go`) — gated behind Go build tags so each
platform only compiles its own implementation.

**Why it works:** `x/term`'s password-reading helper is itself a thin
wrapper over exactly these two syscalls per platform; calling them
directly avoids the dependency entirely.

**Trade-off:** More code to maintain across two platform-specific files
instead of one cross-platform call — and no Plan 9/WASM terminal support,
which `x/term` covers and this project doesn't need to.

## 15. HTTP integration testing — a package like `testify` for
assertions, or a browser-automation library for end-to-end checks

**Used instead:** `net/http/httptest` + `net/http/cookiejar`, stdlib, with
plain `if`-statement assertions.

**Why it works:** `httptest.NewServer` runs the real handler chain over a
real listener; `cookiejar` gives test clients real session-cookie
behavior. Together they exercise the dashboard exactly as a browser would,
without needing a headless-browser dependency.

**Trade-off:** No fluent assertion helpers (`assert.Equal`, etc.) — plain
`t.Fatalf` calls are more verbose but need nothing beyond `testing`.

## 16. The attack/pentest suite itself — a fuzzing or security-testing
framework

**Used instead:** Plain Go test-shaped code in `attacks/`, using the same
`net/http`/`crypto/*` packages the application itself uses, run through a
small custom runner (`attacks/runner.go`).

**Why it works:** Every attack here is a deterministic, scripted scenario
(try 20 known passwords, flip 5 specific bits, send 5 specific forged
Origins) rather than open-ended fuzzing — a hand-rolled runner over
stdlib's own HTTP/crypto packages was sufficient and kept the attack code
itself readable as a demo artifact.

**Trade-off:** Not a fuzzer — it won't discover *novel* attack shapes the
way `go test -fuzz` or a dedicated security scanner might; it verifies the
specific, documented threats in the threat model, which is what it was
built to do.

## 17. Streaming/chunked authenticated encryption for large files —
a library like Tink's streaming AEAD, or `age`'s encryption format

**Used instead:** A hand-built "STREAM" construction over `crypto/aes` +
`crypto/cipher`'s AES-GCM (`internal/fileenc/fileenc.go`), used by
`zerovault encrypt`/`decrypt` and the dashboard's File Encryption page.

**Why it works:** `cipher.AEAD` only exposes single-shot `Seal`/`Open`,
which would force an entire file into memory to get one authentication
tag — unworkable for the "must not load 100MB+ files into memory" and
"stream in 64KB chunks" requirements. Sealing each 64KB chunk under its
own nonce (a random 8-byte per-file prefix + a 4-byte big-endian counter)
gets bounded memory back, and setting the counter's top bit on the final
chunk binds "this is really the end" into that chunk's authenticated
nonce — an attacker who truncates the ciphertext can't make an earlier
chunk decrypt as if it were the last one, since it was never sealed that
way. This is the same idea published designs like age/rage and Tink's
streaming AEAD use; ours is a from-scratch implementation of that idea
using only stdlib's AES-GCM as the per-chunk primitive.

**Trade-off:** More code to get right than "encrypt once with one nonce"
(nonce/counter bookkeping, wire-position-based finality checks on both
the encode and decode side) — validated by dedicated tests for tampering,
truncation, and an exact-chunk-boundary empty file, not just a happy-path
round trip.
