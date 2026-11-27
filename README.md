# zpkb — a pure-Go recipe build tool

`zpkb` is a `CGO_ENABLED=0` build tool written from scratch in Go. It reads a
recipe, builds the package in a zpkx environment, relocates the install tree,
and packages an artifact.

It was written from a **bibliography** rather than from one predecessor:
[pkgx](https://pkgx.sh)'s [brewkit](https://github.com/pkgxdev/brewkit)
(Deno/TypeScript with Ruby and `patchelf` helpers) for the recipe shape,
[Guix](https://guix.gnu.org) for checking a digest when it is *recorded*
rather than at every build, [Arch](https://man.archlinux.org/man/PKGBUILD.5)'s
`validpgpkeys` for requiring a fingerprint rather than a keyring,
[Homebrew](https://docs.brew.sh)'s `rebuild` and Debian's `+bN` for the
rebuild counter, and [Spack](https://spack.readthedocs.io) for the concrete
spec. Each entry is credited where it is used, below.

⛔ **The format is `package.hcl`, with its own schema.** `package.yml` is
still read, tried second, and is on its way out with the rest of the pkgx
compatibility — see [the pantry question](https://github.com/go-zpkg/packages/issues/431).

A *native* build tool — pkgx's brewkit among them — pivots on the host it runs on
being the thing it builds for. `zpkb` is **Target ≠ Host by design**: the
build target (platform/arch/triple) is a first-class value, so cross-compilation —
notably **Windows PE artifacts built on a linux/darwin host** — is a supported path
rather than a retrofit.

## Verifying a downloaded `zpkb`

⛔ **`SHA256SUMS` is a checksum of itself.** It says the binaries on a
[release](https://github.com/go-zpkg/zpkb/releases) match a manifest published
beside them, and whoever replaced the binaries would replace the manifest.
The half that cannot be forged from the release page is GitHub's **provenance
attestation** — signed through Sigstore, saying that this repository's release
workflow built that file from that commit:

```sh
gh attestation verify -R go-zpkg/zpkb zpkb-linux-amd64
```

It matters more here than for the other binaries in this organisation:
`zpkb factory` is what signs and publishes every artifact, and a `zpkb lock`
records the version of the binary that wrote it. Every file of a release
published after 2026-10-20 carries an attestation; earlier ones carry none,
and `gh attestation verify` answers `HTTP 404` for those rather than failing
closed, so a 404 on an older binary means *unattested*, not *tampered with*.

## Status

In production: `zpkb factory` is what fills
[`ghcr.io/go-zpkg/packages`](https://github.com/orgs/go-zpkg/packages) —
**1585 projects, 42 746 signed (project, os, arch, version) artifacts** as of
2026-10-04 17:00 UTC+2 — linux/aarch64 15 136, linux/x86-64 13 255,
darwin/x86-64 7 113, darwin/aarch64 6 649, windows/x86-64 554, and
**linux/s390x 39**, an architecture being brought up now.

It is a moving target, and more literally than that phrasing suggests: the
same `zpkb builder --dry-run --platform linux/s390x` reported 25 of 25 toolchain
roots unresolvable at 11:45 and 21 of 25 at 17:03 the same day, because
another session was publishing while this was measured. A registry count is
dated to the HOUR. Re-measure it rather than trusting this line: `go run
./catalog` in
[go-zpkg/packages](https://github.com/go-zpkg/packages) enumerates the registry
itself, and <https://go-zpkg.github.io/packages> browses it.

The packages, all at 100% statement coverage (`go test ./... -coverprofile` + `go tool cover -func`, enforced in CI):

| package  | what it does |
|----------|--------------|
| `target` | the single source of truth for the build **target** vs the **host** (`ZPKB_TARGET` / `--platform`), incl. the llvm-mingw Windows cross triples and the `wasip1/wasm` target (`wasm32-wasip1`; no POSIX relocation; `wasm` is an arch of `wasip1` only). C/C++ for wasip1 uses our own toolchain from source — the `llvm.org` artifact's clang/wasm-ld, the `github.com/WebAssembly/wasi-libc` sysroot and the `compiler-rt.llvm.org/wasi` builtins — imposed through `$ZPKB_CC`/`$ZPKB_CXX` (`clang --target=wasm32-wasip1 --sysroot=… -resource-dir=… -mcpu=lime1`), which the cc/gcc/clang shims re-exec; `AR`/`RANLIB`/`NM`/`STRIP` are the LLVM ones, and recipes pass `--host={{hw.target}}` (= `wasm32-wasip1`) to configure. ⭐ A linux target may also NAME ITS C LIBRARY — `ZPKB_TARGET=linux-musl/x86-64`, beside `linux-gnu/…` — and the name then travels into every place a build is spelled: the artifact path, the published `Concrete.Platform` that `artifact.VerifySpec` recomputes, the `zpkb lock` spec hash, and the local build tree. ⛔ A libc is **not** an ordinary dependency to be solved per edge: every object in a closure must agree on it, so a mixed closure is not a resolution error to report but an artifact that cannot exist — which is why it sits in the target's identity, as it does in Rust's `x86_64-unknown-linux-musl` or Zig's triples, rather than in any recipe. No recipe names a libc, and none should. ⚠ An **unnamed** libc spells exactly what it spelled before, byte for byte, so nothing already published moves and no lock file is invalidated; `Host()` deliberately leaves it EMPTY rather than answering `gnu`, because nothing here has looked at the host's C library and a guess would publish a bottle labelled with an ABI it was never checked against. `bionic` is refused until there is an NDK toolchain to build it with. Detecting the host's libc, and a musl lane, are go-zpkg/packages#475 |
| `config` | the build workspace layout, keyed on the target so a cross build never collides with a native one |
| `schema` | ⛔ **Being retired with the rest of the pkgx compatibility.** A JSON Schema for `package.yml`, derived from libpkgx's parser and exercised against `pkgxdev/pantry` — 1890 recipes, 0 rejections. That number says the parser accepts what **pkgx** writes; it says nothing about our own recipes, and it is their corpus rather than ours. `package.hcl` has its own schema (`pantry/hcl`), which is the one this project keeps. |
| `pantry` | parses + schema-validates a `package.yml` into a shared `Recipe` |
| `pantry/hcl` | an **HCL2 front-end** — a `package.hcl` decodes into the *same* `Recipe` via the same schema, so a recipe written in HCL2 yields an identical build |
| `fixup`  | post-build relocatability: `.pc`/`.cmake` path rewriting, libtool `.la` cleanup, `lib64→lib`, single-dir header flattening, and a **pure-Go ELF RUNPATH rewriter** (`debug/elf`, no `patchelf`). A Windows target skips all POSIX relocation. A recipe that sets `build.rootfs: <subdir>` also gets a **rootfs closure** (Linux only): every ELF under that subdir has its `DT_NEEDED` libraries (transitively), its `PT_INTERP` loader and its `.note.dlopen` entries resolved against the dependency prefixes and copied into the rootfs, following usr-merge symlinks inside the rootfs only. An unresolved `DT_NEEDED`, a missing loader or a `required` dlopen entry fails the build; `recommended`/`suggested` misses are logged. Store RUNPATHs of the copies are rewritten in place (store entries dropped, `/usr/lib` kept or appended). |
| `moustache` | pkgx's `{{token}}` template substitution (version/deps/prefix/hw) |
| `buildscript` | the build/test script generator (`if:` guards vs the target, platform-reduced env, fixtures) + the porcelain `Wrap` (full runnable script) |
| `fetch` | source download + extract (tar.gz/xz/bz2/zip, git), zip-slip-safe |
| `artifactpkg` | package an install tree into an artifact + dist layout |
| `build` | the pipeline orchestrator (`Runner`): dep-closure, base toolchain, sanitized env, autotools maintainer-mode defeat |
| `overrides` | applies the factory's local recipe-override patches to a pantry checkout in pure Go — a `git diff` parsed and applied without shelling out to `git apply`, and idempotent (it resets the files it touches first) |
| `recipefile` | reads a recipe and applies the project's **logical** override on the way in — nothing on disk is touched, which is what lets the same pantry checkout be read twice |
| `logical` | the override algebra: `set`, substitute, `remove`, `append`, `prepend`, each reporting **applied / already true / premise gone**. A unified diff has two outcomes; the third is what distinguishes a defect from a job upstream has since done. A path (`build.dependencies["crates.io/semverator"]`) must be spellable in the form the parser reads: a step holding a quote, a backslash, a control character or invalid UTF-8 is refused, because `String` renders those with Go's `%q` and the reader understands no escapes — a backslash used to round-trip to *two* characters silently, so the diagnostic naming the place to fix named a different place. Found by this repository's first fuzz target in 0.03s |
| `httpretry` | which failed HTTP attempts are worth repeating. Measured on one 23-failure batch, **eleven** were transient HTTP and nothing else — a factory that gives a flaky host exactly one chance reports its own bad luck as a broken recipe |
| `useragent` | the one User-Agent every HTTP path in bk sends. It exists because they differed: `versions` set one and `fetch` did not, so bk could LIST a project's versions and then get 403 downloading the tarball it had just found |
| `versions` | resolves a project's upstream version from the recipe's `versions:` spec — deliberately distinct from what pkgx's dist advertises, which normalises versions the recipe's own source URL does not have |
| `cmd/zpkb` | forty-one subcommands. The pipeline: `build`, `test`, `publish`, `publish-stage` (signs and pushes what `factory --stage-only` staged, from a process that ran no recipe; `factory --mirror-from <seed> --require-origin --stage-only` stages a promotion the same way: it verifies the seed's signature and signed origin claim, signs nothing, and records the verdict `mirrored-verified`, which publish-stage accepts only with that record), `factory`, `builder`, `source`, `sourcepin` — the last one prints the `sha256` a recipe should pin, fetched with **the builder's own fetcher** rather than with `curl` and `shasum`, because every other distribution computes that digest with a tool its build does not run and so never meets the host quirk the build will. It was written the day GitHub's release CDN answered 504 and `curl -sSL | shasum` produced a perfectly plausible digest of a 92-byte error page. `--sig <url>|auto --key <file> --key-source <text>` adds the other half: **who** produced those bytes. A digest pins them, it does not say who made them. Measured over `pkgxdev/pantry` at `4eb778f`, with the builder's own loader counting the recipes: **1932 recipes, of which 1 names a `sha:`** (openssl.org), **1 a `sha256:`** (github.com/Virviil/oci2git) **and 3 a `sig:`** (ffmpeg.org, libuv.org, openssl.org — a fourth sits in haskell.org's `package.yml-from-source`, which is not a filename the loader reads). ⛔ go-zpkg/zpkb#282 says "1 recipe of 904" and "the one `sig:`"; the denominator was an older pantry and the `sig:` count was wrong, which is why this paragraph names the files rather than repeating a total. The check happens **when the digest is recorded**, not at every build — which is Guix's division, read from its own manual: its `origin` record has no signature field, because `guix refresh` does the checking, and the hash is then the durable pin. Verifying at every build instead would need the signature *and* the key reachable forever, from inside a sandbox, for every consumer. Two deliberate divergences from the four systems that do this at all (Gentoo's `verify-sig`, Arch's `validpgpkeys`, Debian's `Pgp-Mode:`, Guix's `guix refresh`): **no keyserver is ever asked** — Guix's `--key-download` defaults to `auto`, documented as `interactive` on a TTY and *"else `always`"*, so in CI an unknown key is fetched and accepted and the check degrades to "somebody signed it" — and **`--key-source` is mandatory**, because not one of the four records where a fingerprint came from. Debian's `uscan(1)` is the most explicit and it is an instruction rather than a procedure: *"You must verify the downloaded OpenPGP key using its full fingerprint value which you know is the trusted one."* Which you know. `sourcepin` prints a `provenance` block naming the fingerprint, the identity, the signature URL that actually answered, and where the author's trust in that key came from. ⛔ `--fingerprint` is the third divergence, and it came from running the thing: `https://ftp.gnu.org/gnu/gnu-keyring.gpg` is **3 700 423 bytes and holds every GNU maintainer's key**, so `--key` pointed at it alone would answer *"somebody in that file signed it"* — exactly the degradation criticised above. Naming the fingerprint is Arch's `validpgpkeys` semantics, stated in `PKGBUILD(5)`: makepkg "will only accept signatures from the keys listed here and **will ignore the trust values from the keyring**". It is compared on the primary key with spaces and colons ignored, because that is how `gpg --fingerprint` prints one; and the output always says how many keys the file held, so an author can see whether they passed a choice or a set. Two further measurements shaped the code: that keyring **cannot be read whole** by `ProtonMail/go-crypto` (`Cannot have multiple embedded signatures` — one entity in a thirty-year archive, and `ReadKeyRing` returns nothing at all), so naming a fingerprint also *rescues* such a file by reading only that key — 326 primary keys walked to reach gzip's; and `gpg --keyring` is **silently ignored** on a host using `keyboxd`, exiting 0 having exported nothing, which is why the extraction is done in Go rather than shelled out. ⛔⛔ **And the rescue itself stopped partway, which made 212 GNU maintainers' keys unreachable.** The walk used go-crypto's packet reader, which cannot be resynchronised after a packet it refuses, so it stopped at the GNU keyring's 402nd primary key, on *"Cannot have multiple embedded signatures"*; `gpg` reads **614** from the same file. `gnu.org/libidn2` 2.3.8 was the case that found it — its signer, Simon Josefsson's `B1D2BD1375BECB784CF4F8C4D73CF638C53C06BE`, sits past that point. ⭐ The format already holds the way through: every packet header states its body's length (RFC 9580 §4.2), so the next packet can be found without parsing this one. The walk now locates packets by their headers and hands go-crypto only the key packets it compares and the one entity it matched — that entity running to the next primary key (§10.1) — so a packet refused in some *other* key's entity no longer ends the search. Measured on the same file, same command: **402 → 614** primary keys walked, matching `gpg`. Only a header that states no usable length still stops it — a Partial Body Length, which §4.2.1.4 confines to data packets, or a Legacy indeterminate one, which §4.2.2 says runs to the end of the file — and lengths are compared in `uint64`, so a 4 GiB declaration cannot wrap a 32-bit bounds check. The splitter is fuzzed (8.5 M executions, corpus committed). ⚠ A consequence stated rather than hidden: rubbish *after* a complete entity is no longer read as part of it, so such a key is now returned where it used to be refused. ⛔⛔ **A key's expiry is judged at the SIGNATURE's creation instant, not at `time.Now()`** (go-zpkg/zpkb#484), and that is the fourth divergence. A signature's job here is to justify WRITING a digest, once; a warrant issued in 2024 by a key valid in 2024 does not stop being one because the key lapsed in 2025, and GNU maintainers let keys lapse routinely. Judged at `time.Now()`, `sourcepin` refused three real signatures that `gpg --verify` accepts with `Good signature` plus a *note* about the expiry: `gnu.org/wget` 1.25.0, the second case #484 records, and `x.org/libX11` 1.8.14, signed by Alan Coopersmith — the one that sent this to be fixed rather than worked around. ⚠ The weakening is real and bounded, so it is stated: the creation time comes from the signature, which an attacker writes, so somebody holding a lapsed private key could backdate a forgery past the expiry check. What that buys is nothing this check defended — the key is still *theirs*, the fingerprint is still compared against the one the author published, and **expiry has never been revocation**; a revoked key is refused at any clock. The alternative is a verifier that degrades into "cannot check" as keys age, which is how it stops being able to re-check the pantry at all. ⛔⛔ **And that rule had a defect of its own, found by its author** (go-zpkg/zpkb#512): go-crypto judges the key's self-signatures at the same single instant, and counts a signature *created after* that instant as expired (`packet/signature.go:762-765`). A keyring holds a key's **current** self-signatures, so a maintainer who refreshes them — routinely, to extend an expiry — made every release signed before the refresh unverifiable. `gnu.org/libidn2` 2.3.8 is the measured case: signed 2025-03-08, Simon Josefsson's user-ID self-signature dated 2026-04-17, refused as *"signature expired"*. The clock is now the **later** of the signature's own instant and the signing key's newest relevant self-signature — the refresh's instant capped at the present, so a self-signature from the future cannot carry the clock — and never earlier than the signature's own instant. With no refresh it is exactly the previous rule, and the output says which instant the checks ran at whenever the two differ: *"signed at 2025-03-08T23:10:44Z; judged at 2026-04-17T08:55:45Z, the key's newest self-signature, because the key was refreshed after it signed"*, in the provenance block too. ⚠ One behaviour change, stated: a data signature carrying its *own* lifetime that ended before a later refresh is now refused where it was accepted — rare in release signing. And an expiry refusal now says it is an expiry, instead of falling into the "key present and may sign" state and printing the `--sig-covers` bytes hint over it. ⛔ A signature dated in the FUTURE is refused, with an hour of slack for clock skew, because that is the one claim the signature's own clock cannot be trusted for; and the signature's instant **is** printed, in the terminal and in the pasted `provenance` block, because "verified" now means "the key was valid when it signed" and a reader cannot tell that from "the key is valid now" unless the instant is shown. ⛔⛔ That sentence stood here, and in the field's own doc comment, for the length of go-zpkg/zpkb#506 **while nothing printed anything**: the field was added, its test asserted it was populated — a different claim — and three surfaces then described a behaviour the code did not have. The true statements around it are what made it invisible. ⛔⛔ **Which bytes the signature covers is the author's to state, and `--sig-covers served|decompressed` is where they state it** (go-zpkg/zpkb#492). kernel.org signs the **uncompressed** tar and its `signature.html` says why — *"the signature is made against the uncompressed version of the archive … so there is only one signature required for .gz and .xz compressed versions of the release"* — and every `.sign` file repeats it in the armour header: `Comment: This signature is for the .tar version of the archive`. A recipe's `distributable.url` names the `.tar.xz`, so until this existed the verifier was handed bytes the signature never covered: `linux-7.2.15` serves `d0f6b1d7…` and the signature covers `1ade1a3b…`, refused as `openpgp: invalid signature: RSA verification failure` with a good key and a good signature. It is **one operation over two byte streams** — verify the decompressed contents, pin the compressed file, because the compressed file is what a build downloads — and the `provenance` block says so, since the digest and the warrant no longer describe the same bytes. ⛔ It is a flag and **not** a fallback: retrying the other stream whenever the first fails would make *"it verified the other way"* indistinguishable from *"somebody signed a different archive"*, and a refusal that can be shrugged off is not one. A misspelt value is a usage error rather than a silent return to the default, which would print a pin claiming `covers served` after checking exactly that. `--sig auto` strips the compression suffix in this mode, because a signature is published under the name of the bytes it covers — the four names measured are `linux-7.2.15.tar.xz.asc` 404, `.tar.xz.sig` 404, `.tar.xz.sign` 404, `linux-7.2.15.tar.sign` **200** — so appending to the compressed URL could not have found it in principle. Memory is bounded while this runs and time is not, which is stated rather than fixed: every decoder streams and nothing is buffered, since the verifier only hashes, but a total-bytes ceiling would be a number with no upstream meaning — the real tar is 1.69 GB from a 160 MB `.tar.xz`, a 10.5× ratio, and any cap that passes a real kernel passes most bombs. ⛔⛔ **And a refusal now names the cause it MET rather than the one it had a sentence for** (go-zpkg/zpkb#482). Every refused signature used to end *"what failed is WHO signed them"*, which is wrong whenever the key is present and sends the reader to audit a keyring that is fine; the three states — no key with that id, a key that cannot sign, a key that may sign — are separated by reading the signature's issuer against the keyring, and only the last of them is a case where `--sig-covers` means anything. ⭐ The issue's **own** diagnosis was an instance of the defect it reports, which is why the cause was measured rather than relayed: it read a packet dump (`algo 17 is DSA; digest algo 2 is SHA-1`) and concluded go-crypto declines that combination. It does not. Measured against the real 3 700 423-byte GNU keyring and the real 95-byte signature for `gnu.org/help2man` 1.49.3 — `KeysById` **1**, `KeysByIdUsage(KeyFlagSign)` **0**, `SelfSignature.FlagsValid` **false, made 2001-06-19**, and `VerifySignature` by hand **nil**, SHA-1 and all — so the key is found, the signature is by it and it verifies; `openpgp/keys.go:343` skips it because a self-signature from 2001 carries no key-flags subpacket, the candidate list empties and `openpgp/read.go:493` reports `ErrUnknownIssuer`. **A key older than the flag, not a weak algorithm.** ⚠ Nothing was relaxed, and the spec is why: treating a flagless key as sign-capable, as `gpg` does, makes that signature verify — one patched field proves it — but **RFC 9580 §5.2.3.29 does not say what an absent subpacket implies**, and its nearest statement goes the other way, *"If a list is shorter than an implementation expects, the unstated flags are considered to be zero."* So go-crypto's refusal is the conservative reading, granting sign capability would be a policy change resting on an inference with no line behind it, and the verdict is left to whoever owns that decision; this names the cause and changes no outcome. Whether two builds AGREE: `reproduce` — it compares two artifacts entry by entry and classes what differs, because "the digests differ" is the start of an afternoon with two tarballs rather than a finding. It exists because the question was asked once by hand, on 2026-09-29, and found one: zlib.net 1.3.2 built on the s390x seed VM before and after it was replaced had every file byte-identical and its directories 0755 against 0775 — the two hosts' umasks. Whether a second builder VOUCHES: `sign` — it attaches your signature to an artifact somebody else published, after checking your rebuild produced the same bytes, and refuses when it did not. Republishing an artifact VERBATIM, which is what a mirror does: `copy` — it moves published artifacts from one OCI namespace to another with their signatures and attestations, digests unchanged. ⛔⛔ **It is NOT how a registry namespace is moved,** and it was written believing it was. GitHub's container packages are org-scoped and did not follow the repository transfer — every repository went from `go-pkgx` to `go-zpkg` and every artifact stayed — so the new namespace has to be *populated*; but it is populated by **building correct recipes into it**, not by transplanting artifacts that were built from recipes this project has established it can neither read nor copy (go-zpkg/packages#431 measured 2453 upstream files with no `LICENSE` and no `COPYING`; go-zpkg/packages#440 carries the corrected order). Copying them forward would carry their measured defects by digest, and `.github/workflows/wasip1.yml:201` in the packages repository states the rest: *"Nothing in go-pkgx carries a build identity — it predates them."* What is left for this verb is the case where republishing verbatim is the point — a mirror (`go-zpkg/mirror`; `mirroraudit` opens with "A mirrored artifact is republished verbatim"). It is a copy and not a re-sign because verification is digest-bound: `payloadCommitsTo` checks `critical.image.docker-manifest-digest` against `sha256(tarball)` and nothing about where the artifact lives. ⛔ It **verifies at the destination by default**, because "the bytes arrived" is not the question: a cosign signature is a *referrer* of a platform manifest rather than a child of it, and `oras.ExtendedCopy` from a version tag resolves an INDEX — already a root, so no predecessors are collected and the signature of a child is never seen. `artifact.CopyPublished` was written with exactly that defect and its test caught it: a byte-identical artifact at the destination answering `unsigned (no signature referrer)`. So each platform manifest is copied by digest first, which makes its signature a root; a copy into the namespace it came from is refused outright, since "copied, nothing moved" is how an empty destination passes for a full one. What a recipe set SAYS: `target`, `versions`, `closure`, `lock`, `catalog`, `tools`, `overrides`, `tohcl`, `version`, `buildenv`, `origin`, `vulnid`, `advisories`, `vulnfetch`, `attest`, `eol`. What it gets WRONG: `depgaps`, `depsplit`, `undeclared`, `unlinked`, `unresolved`, `provides`, `lint`, `weather`, `sonames`, `runlog`, `bakedpaths`. ⛔⛔ `bakedpaths` reads a built tree's BYTES and refuses three things, and the reason it reads bytes rather than build inputs is that the previous attempt at this check was a `grep -n AC_PATH_PROG configure.ac` run before writing a recipe — which prints **nothing** on `gnu.org/findutils`, whose `AC_PATH_PROG([SORT],[sort])` is in `m4/nullsort.m4`, reached from `configure.ac` by one word. A check scoped to one file cannot see a macro search path, and a clean result from it reads exactly like an absence; a tree cannot be wrong about its own contents. It refuses **another project's versioned store path** (`<store>/<project>/v<ver>`, go-zpkg/zpkb#397 — stale the day that project is rebuilt) and **any reference to a `+builddir` staging tree** (go-zpkg/zpkb#152 — a directory that does not exist once the artifact is installed, and the one rule with no `--allow`, since there is no tree in which it is the intent; the suffix was spelled `+brewing` until 2026-11-15, a word borrowed from pkgx's lexicon, so the measured instances quoted below still carry the old spelling — they are other builders' artifacts, not ours). The third is a **census and not yet a refusal**: absolute paths outside the store, counted per path, in files that run things. ⭐ Every rule came from an artifact that was READ rather than from a prediction, and the first version of the check — which looked only for the store-path shape the two recipes predicted — passed all three measured instances. Run over `~/.pkgx` on 2026-11-09: `gnu.org/findutils` v4.10.0 is **refused** on four staging references, among them `: ${LIBEXECDIR=/opt/gnu.org/findutils/v4.10.0+brewing/libexec}` in `bin/updatedb`, so that script cannot find its own `frcode`; `gnu.org/libtool` v2.5.4 is **refused** on `lib/libltdl.la`, and its census independently rediscovers the `/Users/builder/actions-runner/_work/_actions/pkgxdev/brewkit/v1/libexec/sed` baked into `bin/libtool` 11× — the defect `fix/libtool-baked-tool-paths` was opened for, in the darwin spelling rather than that branch's `/__w/…` one; and `gnu.org/diffutils` v3.12.0 passes both refusals while its census names `/usr/bin/pr` in `bin/diff` once, which is `AC_PATH_PROG([PR_PROGRAM],[pr])`'s value — the build host's `pr`, compiled in beside the string `pagination not supported on this host`. ⛔ That one was invisible at first because the census is **ranked by count** and truncated at ten: the builder's own object-file paths occur 147× and the baked tool path once, so `--census-limit 0` exists because "not shown" had become "not found". The same census is how the leak in go-zpkg/zpkb#395 reads from outside: **208 references** to `/Users/builder/actions-runner/_work/pantry/pantry/builds/gnu.org__findutils-4.10.0/…` inside `bin/find`, naming the builder's account in a published binary. Build-time shims a recipe invokes rather than a person: `fixup`, `libtool`, `zpkvenv`. `zpkvenv seal` — and the two older `python-venv.{sh,py}` shims beside it — used to finish by writing a **launcher script** into the artifact; all three now install `cmd/venvlaunch` instead, and relativise the venv's interpreter symlink so that nothing has to be repaired at run time. It is looked for **on `PATH` first, then beside the running `zpkb`**, and that order is the correctness argument rather than a preference: only `PATH` can hold the *target's* launcher under a cross build, while the one beside `zpkb` came out of the same release matrix and so is the *host's* — right for every native build, which is what a venv built by running the packaged python always is. The fallback is what lets this improve every python-venv recipe at once instead of after a campaign to edit each one. That deleted the last three verbatim copies of `pkgxdev/brewkit` in this repository, which matters twice: brewkit declares no licence at all, so a published `zpkb` was redistributing somebody else's expression without a grant, and one of the three rewrote the venv's shebangs with `sed` on **every invocation of every packaged tool** — three dependencies (`sh`, `sed`, a writable artifact) that a sealed, signed artifact should not have. `zpkb tools` is worth singling out: it reports which external commands a recipe set invokes, parsed rather than grepped, and `--scope build\|test\|all` separates two surfaces that disagree — a build's is what the IMAGE must hold, a test's is what the package's own acceptance check needs, and **260 tests call a compiler where 6 declare one**. `zpkb lint --check-newest-pinned` (network; each request is retried up to 5 times over about 30 s on a timeout, a TLS handshake timeout, 5xx or 429, never on 404 or 403; a host that never answers is reported as a WARNING apart from a stale pin, because the pin was not judged, and `--strict-resolve` makes it fail, while a source that answered and gave no version always fails: go-zpkg/zpkb#524) resolves the versions of every recipe that pins a `sha256` — in `distributable`, its list form, or `sources:` — with `versions.Resolve` and `"*"`, as a consumer does, and refuses one whose NEWEST version `build.PinnedDigest` does not find pinned, naming that version and the pinned set: the builder is fail-closed, so such a recipe's default build is a refusal that no other lint can see (go-zpkg/recipes gcc/libstdcxx, tcl-lang.org and llvm.org, 2026-11-20). A recipe that pins nothing is not resolved. `zpkb lint` is the other: `--require-provenance` asks whether a recipe of ours records which of the project's OWN files its build was written from, and `--require-standalone` asks the prior question — whether it is a recipe at all, or an amendment that resolves only because another tree is merged underneath it. ⛔⛔ **And "standalone" is no longer only a count: a recipe of ours that states its own `versions`, `distributable` and `build` is the WHOLE recipe, by default and with no flag** (go-zpkg/zpkb#514). `factory`, `lock` and `sets` build it alone — not the pantry's, not merged, and **without the logical overrides**, which describe edits to upstream's recipe — from the overlay's directory, where its props and fixtures sit; `closure` and resolution read it alone, with no merge. Before, upstream's twin was merged underneath it: a standalone `libpsl` that builds the maintainer's tarball with libidn2 still inherited upstream's `unicode.org` (ICU) as a **runtime** dependency, plus meson, ninja and python to build, and `libgit2.org` inherited a `build.working-directory` its script never expected. A fragment keeps the old merge exactly. The predicate is `artifact.IsStandalone`, the one function `lint --require-standalone` calls, and `artifact`'s own resolver applies the same rule, so a consumer and the builder read one recipe. Over the three trees that hold recipes of ours, **30 of 227 stand alone**; the rest are overlay fragments, correct as overlay entries and unusable as a pantry. `--subdir` exists because 14 of those recipes are not kept under `projects/` and so could not be reached at all. `--fragments-dir <dir>` states the same obligation as a SET instead of a number (exclusive with `--max-fragments`): one empty marker file per fragment at `<dir>/<recipe path>`, the fragments must EQUAL the markers, and both directions are refused by name (a fragment with no marker is a regression; a marker for a recipe that stands alone, or does not exist, says "delete this marker"; a missing directory is an error). A change that completes a recipe deletes its own marker, so concurrent changes touch distinct files and never conflict, which a single shared number cannot promise. `--max-fragments N` is the ratchet that lets the check be switched on before the work is finished: more than `N` fails as a regression and **fewer than `N` fails too**, because a ceiling nobody lowers stops describing the tree and a regression then hides in the slack. ⭐⭐ **And `closure --require-standalone` asks that same question of the set that is actually being built, which is the one the campaign is measured on.** `lint --require-standalone` answers for a whole TREE — over `go-zpkg/recipes` on 2026-11-19, **185 of 253 cannot resolve alone**, a true number about a tree holding recipes for projects no base toolchain needs, so nothing is blocked on most of it. Taken over `closure --build go-zpkg/base-toolchain` instead: **77 projects, of which 51 stand alone, 6 are fragments of ours and 20 have no recipe of ours at all.** That is 26 projects of work rather than 185, and it names them — the fragments (`curl.se`, `libssh2.org`, `llvm.org`, `perl.org`, `rust-lang.org/cargo`, `tcl-lang.org`) with the keys each one lacks, and the absences (`gnu.org/gcc` and `rust-lang.org` among them) as recipes still to be written. ⛔ **It is a three-way split and not a count, because the last two need different work:** a fragment needs completing, an absence needs writing, and "not standalone" hides which. The tree-wide number cannot see the absences at all — a project with no recipe of ours is not in that tree to be counted, so it reads as nothing. ⛔⛔ The first run of this flag made that mistake *itself*, which is why the arithmetic is now asserted by a test: `recipefile.ErrNoRecipe` covers a project directory holding no recipe, while a project with no directory returns a bare `open …: no such file or directory`, so classifying only the sentinel filed **18 of the 20 absences under "unreadable: counted in neither population"** — an absence reported as something else, by the check written to stop exactly that. The populations now partition the closure (51 + 6 + 20 = 77) and a test fails if they ever do not. `--max-fragments` ratchets this one too, and only the fragments: an absent project is not a regression this repository can cause, since the closure decides which projects appear at all. `--max-no-provenance N` is the same ratchet for `--require-provenance`, and it exists because the lane that wanted that check wrote down why it could not have it: `go-zpkg/recipes`' `ci.yml` carried, beside the step it did **not** add, *"--require-provenance is NOT here yet. 14 of 216 record none, and there is no ratchet for it, so turning it on would be the red light this avoids. It belongs here once those 14 are written or once it has a ceiling of its own."* Those are not equal halves: writing the fourteen means reading fourteen projects' build systems — `kernel.org/linux` and `github.com/ggml-org/llama.cpp` among them — so the first is a campaign, and while it runs **nothing at all protects the 208 recipes that already record provenance**, because a new recipe landing without one is invisible. Measured on the overlay at `097fc86`: **14 of 222**, the same answer from the `@main` the lane runs and from the released binary, so the number is not an artefact of which build asked. `--require-hcl` is the third of these per-tree questions and the only one that needs **no** ratchet: our own recipes are HCL only — the owner's decision of 2026-11-15, *"nous n'avons plus besoin YAML, on fait tout en hcl"* — and all three of our trees are already there, measured the same day: `recipes` 222 of 222, `wasip1/recipes` 13, `windows/recipes` 1. Zero is available, so zero is what it asks for; a stated ceiling would be slack where none is needed. ⛔ It judges the file NAMES and names a `package.yml` **sitting beside** a `package.hcl` too, which the obvious implementation misses: `recipefile.Load` prefers the HCL, so asking "what would the loader read here?" answers `package.hcl` and reports a tree clean while an unread yaml sits next to it — the state the overlay was actually in before its last three were converted. And the flag stays per-tree for the reason its two neighbours do: upstream's pantry **is** yaml and must stay readable, since `PantryBase` is still `pkgxdev/pantry` and 195 of our 222 recipes resolve only because it is merged underneath. `--render-scripts` is the fourth, and it asks a question the other three cannot: whether `buildscript.Generate` — **the builder's own renderer, not a rule restating the schema** — can render each recipe's `build` and `test` script at all. ⛔ It exists because `openucx.org` carried two `test` entries that were one-key MAPS rather than strings: a yaml line `- ucx_info -d | grep -q "Transport: posix"` decodes to a mapping, since the `: ` inside the quotes splits the item at `"Transport` / `posix"`, and the HCL conversion carried that structure faithfully. `scriptItem` then found no `run`, `renderRun(nil)` hit its default arm, and **the entire test block was unrenderable** — so `zpkb test openucx.org` could not run, while `lint` was green, because parsing a recipe and rendering its script are different questions. Rendered with ZERO `Options`, so a moustache stays literal and an `if:` guard selects nothing: the only thing asked is whether the shape reads. A/B over `go-zpkg/recipes`, same flag and same 222 recipes: **1 refusal before the repair, 0 after** — one instance in the tree, which is why this one needs no ratchet either. `--require-known-env` is the fifth, and it asks whether a recipe reads a build-environment variable **in our own namespaces that the builder does not export**. ⛔ It exists because four recipes shipped one across three sweeps that each believed they were the last: `kernel.org/linux:75` passed `CC="$ZBK_CC_FREESTANDING"` to `make` after the prefix moved to `ZPKB_` (go-zpkg/recipes#138), and `unbound.net:17`, `llvm.org:184` and `rust-lang.org/cargo` carried `$PKGX_DIR` and `BREWKIT_TARGET` after `ZPKG_DIR` and `ZPKB_TARGET` replaced them (go-zpkg/recipes#86 and go-zpkg/recipes#110). **A shell expands an unset variable to the empty string and exits 0**, so every instance is silent: no build fails and no test looks. The worst was not a dropped flag — unbound's `sed -i -e "s|$PKGX_DIR/|…|g"` ran as `s|/|…|g`, replacing every slash in an installed script, and the next line deleted the `.bak` that would have shown it. go-zpkg/recipes#97, which moved two of these recipes to the *middle* spelling, predicted it in its own description — *"a recipe switched ahead of it reads an UNSET variable, and for these two that is silent"* — and it happened again to one of the two, because the prefix it moved them to was renamed afterwards; prose cannot close that, which is the argument for a check. ⭐ **The authority is the exporter itself**: `buildscript.ExportedNames()` renders `Wrap`/`WrapTest` across every mode and reads the names back out of them, and `build.PassThroughEnv` names what `SanitizedEnv` forwards — so a rename moves the valid set in the same commit, where a written list would have been a *fifth* copy of information that had already drifted four times. `TestExportedNamesCoversEveryExport` parses this package's own sources and fails on any `export NAME=` the matrix does not reach, so a variable added behind a new flag fails the test that owns it rather than a recipe in another repository; it caught a real gap on its first run (`RANLIB`, emitted only for darwin *and* `HasBinutils`). ⚠ The namespace filter — `ZPKB_`, `ZPKG_`, and the dead `ZBK_`, `BK_`, `BREWKIT_`, `PKGX_` — is what keeps this from being a shell linter with an opinion about other people's build systems: `$ACLOCAL_PATH` in a recipe is the project's business, while a misspelt name under one of those is always ours. A variable the recipe assigns itself is exempt, read from the rendered text so that an `env` block (`export K=…`) and a bare `KERNEL_IMAGE=vmlinux` both count. Per tree, like its three neighbours, and for a sharper reason: upstream's pantry is pkgx's, where `$PKGX_DIR` is **correct**. A/B over `go-zpkg/recipes`, 233 recipes: **1 refusal at `d8ea26b`, naming `kernel.org/linux: build: $ZBK_CC_FREESTANDING`, and 0 at `afade87`** — the gate shown red before it was believed, so no ratchet. `--overrides <dir>` is the sixth, and it points `lint` at go-zpkg/packages' `overrides/`: it names every logical override whose project has a **standalone** recipe in the tree being linted. ⛔ Since v0.90.0 a standalone overlay recipe is the whole recipe and `set.ApplyTo` is not applied to it (go-zpkg/zpkb#514), so such an override is **dead** — it parses, it is reviewed, nothing applies it — and was silently so until go-zpkg/zpkb#516. The judge is `artifact.IsStandalone` through `missingEssentials`, the one `--require-standalone` calls. Each dead override carries a verdict from running its operations against a *copy* of the recipe with the builder's own applier: **fix already in the recipe** (nothing is lost), or **fix MISSING** (a defect to carry over), or **premise gone** (the text it edits is not there; read it). It is a **warning** (exit 0) and `--require-live-overrides` makes it a refusal, because measured on 2026-11-20 — `go-zpkg/recipes@24b1667`, `go-zpkg/packages@8af0314` — 29 of 217 overrides are dead, so a refusal would be a red light on day one. An empty or unreadable overrides directory fails rather than reporting none. `lint --require-pinned-fetches` (go-zpkg/zpkb#487) fails a recipe whose **build script fetches a remote artifact** — `curl`, `wget`, `git clone`, `svn checkout`, `hg clone` — outside `distributable` and `sources`, where no digest can reach it; `--max-script-fetches N` is its ratchet (it implies the check, refuses an increase and refuses a stale ceiling, like `--max-fragments`). What counts is the issue's own measurement: `build.script` and `build.env` are counted; the `test` block is reported apart (an unpinned artifact in the build ships, one in a test is a flake); `pip`/`npm`/`go`/`cargo install` are **not** fetches (they build the source already pinned — the first detector counted them and read 549 recipes, 5x too high); a line naming the loopback, `--version` or `--help` is not one; and a shell comment is not one (added here: it removed one false positive in `go-zpkg/recipes`, and none on the pantry). Each finding names its shape — `floating` (a `blob/main` URL), `patch`, `archive`, `other` — because the remedies differ. Measured 2026-11-20: `pkgxdev/pantry@3af085f` **113 recipes, 156 lines** in the build (62 recipes, 69 lines in a test only) — the issue's 113/156 again; `go-zpkg/recipes@a942db9` **2 recipes, 3 lines** (`nvidia.com/cuda-cudart`, `rust-lang.org/cargo`), so `--max-script-fetches 2` is its ceiling. |
| `cmd/venvlaunch` | the entry point `zpkvenv seal` installs as `$PREFIX/bin/<cmd>` for a Python application, and **a binary rather than a script because a script has no `$ORIGIN`**: the kernel resolves a shebang by ordinary path lookup, so a script cannot find anything relative to itself, while `os.Executable` can. It execs the venv's interpreter with the entry point as an *argument*, so the venv's own shebangs are never read — which is what removes the need for `/usr/bin/env`, for `env -S` (absent from busybox, so the old form could not start on Alpine), for a shell, and for rewriting every console script in the tree. `CGO_ENABLED=0` gives it no `PT_INTERP` and no `DT_NEEDED`, measured on linux/amd64, s390x and loong64, so it runs in a literally empty image where **1 513 of 1 870 installed scripts cannot**. **It writes nothing — not "little", nothing.** `seal` makes `venv/bin/python` a *relative* symlink into the store, the same way `@loader_path/../../..` already reaches the store root for an rpath, so a relocated store needs no repair at all: no lock, no temporary file, no `rename`, nothing for NFS to refuse and nothing for two hosts sharing a home to fight over, and every signature stays valid because nothing is rewritten. `pyvenv.cfg` is never touched either — measured: a venv with a stale `home` still resolves to the venv, so only the file's presence is load-bearing. |

`zpkb build` runs the whole pipeline — resolve version → fetch source → parse
recipe → dependency closure → generate + wrap the build script → run it in a
sanitized env → fix-up → package an artifact. `zpkb factory` drives that over a whole
list of projects: it expands them to their topologically-ordered runtime-dependency
closure, skips any `(project, version, platform)` already published, applies the
overrides, and publishes each artifact signed with an SBOM and provenance. After
each publish it runs that package's own `test:` block and RECORDS the outcome in
`tests.txt` — four states, one line each — without ever changing the chunk's
result: measured over 120 packages, only 2 of 12 test failures were a package
that does not work, so a gate would stop a run over a missing host config file.
`--test=false` turns it off, `--test-timeout` bounds one package's test, and
`--test-only` builds nothing and tests what the registry already holds — the
factory tests what it publishes once, and that is how an artifact which stopped
working gets noticed afterwards.

`zpkb depsplit` finds the recipes that name ONE project in BOTH dependency
lists with constraints that select DIFFERENT versions. The two lists are kept
apart on purpose — the runtime list is the set a build LINKS against, the
build list is the set it RUNS — and that is what lets qt build with
`unicode.org ^71` to link and `^73` for nodejs. The case the separation does
not cover is the same project in both: two versions of one library then land
in one build environment, and which supplies headers and which supplies
libraries is decided by search order. `protobuf.dev` declared
`abseil.io: "*"` to link and `^20260526` to build, and on darwin/aarch64 the
link died on `absl::lts_20260817::Mutex::AssertHeld()` after 34 minutes.
When the same disagreement happens to link instead of failing it is worse —
the artifact ships an `@rpath` reference to the version its headers came from
while declaring the constraint a consumer will resolve differently.

Two things decide whether its answer is worth anything. The verdict is
**different VERSION, not different text**: `*` and `>=1` differ as strings
and almost never as answers, so both constraints are resolved against what
the registry actually carries **for that platform** — without the platform
check it reported `github.com/awslabs/dynein` as linking openssl 1.1.1w on
linux/x86-64, a version published for darwin/aarch64 alone. And it reads the
OVERRIDDEN recipe, because the fix for the one confirmed instance is an
override, and an operator who finds a repaired defect in a defect list stops
reading the list. A pair it prints is a **candidate**: harmful when the
doubly-named project is linked, normal when it is a tool.

`zpkb test` runs a recipe's own `test:` block against the INSTALLED package, in an
emptied sandbox holding that package, its `test.dependencies` and the recipe's
own files (recipes name fixtures by bare relative name: `cc test.c -lz`) — and a
compiler when the test's own script calls one, which 260 of them do. What it does
not get is the build's flags, its dependencies or its source tree, because the
question is whether what we published works and not whether the build did. It answers in four states, not
two: `0` passed, `1` ran and failed, `3` the recipe declares no test, and `4`
the test never ran (an unresolvable version, an unreachable version source, a
sandbox that could not be made). A 503 from a version source is not a broken
package, and a sweep that cannot tell the two apart files bugs for an outage.

## Building artifacts that owe nothing to the build container

`--libc=zpkx` retargets the compiler at the pkgx `gnu.org/glibc` artifact — its crt
objects, its libc, its dynamic linker — instead of the build container's, so the
output runs `FROM scratch`. `--glibc <version>` pins that sysroot to an exact
glibc line, and `zpkb builder` stages the sovereign rootfs itself: static Go
binaries plus toolchain artifacts from the signed registry, nothing else.

⛔ **Both flags are RECORDED in the build's identity**, and until 2026-11-18
neither was. They are per-run flags that append `"+gnu.org/glibc@<v>"` to the
generated script's environment eval, which never passes through the recipe's
dependencies — so three materially different builds of one recipe all hashed
to `v1.2.3-hhhrjzyh2dk56y7tc`: the container's own glibc, the artifact, and the
artifact pinned to 2.27.0. One identity for three ABIs, on the flag whose whole
purpose is to choose an ABI. It is recorded as an ordinary entry in
`Concrete.Deps`, so `artifact.VerifySpec` is unchanged and a consumer
recomputing the hash from the manifest now sees the libc listed. ⛔ And the
project recorded follows **the target's libc** — `musl.libc.org` for a
`linux-musl/…` target, `gnu.org/glibc` otherwise — from one table in `target`.
Writing the literal instead made a musl build record a glibc dependency, which
is worse than recording nothing: the manifest and the hash agree with each
other and both are wrong about the ABI, so the bottle VERIFIES. A libc with no
project is a refusal, never a dropped field. ⚠ With no
`--glibc`, the version is left EMPTY, because "newest at eval time" is not
knowable before the compiler runs and the identity must be: two `--libc=zpkx`
builds either side of a glibc release still share one. That edge degrades to
*the artifact was used* and no further — stated, not hidden. ⚠ Builds that
passed these flags get NEW hashes from here on; builds that did not are
byte-identical to before.

[`docs/from-scratch-toolchain.md`](docs/from-scratch-toolchain.md) is the design
note behind it, kept because its hazard list is still the one that bites.

⛔ **A tool that does not go through the compiler driver sees none of this.**
The sysroot, the `-isystem` dirs and the runtime choice reach a build through
`cc` — the shim that re-execs `$ZPKB_CC` — or through `$CC`. **bindgen** drives
libclang in-process instead, so a Rust crate that generates bindings got the
container's idea of a libc, or none:

```
/pkgx/openssl.org/v3.6.4/include/openssl/asn1.h:27:10:
  fatal error: 'stdio.h' file not found
```

openssl 3.6.4 had been found and configured correctly in that build; the
first `#include` of a C library was simply unreachable. Sovereign mode
therefore also exports `BINDGEN_EXTRA_CLANG_ARGS` — the variable bindgen's
own documentation names for exactly this — with the header-finding flags
only, appended to whatever the recipe set. It is **not** exported outside
sovereign mode, where an empty `--sysroot` would hide the host headers a
build is entitled to use.

A scratch tree has nothing underneath it, so `zpkb builder` answers three
questions a build would otherwise answer hours later and attributed to the
wrong thing:

- `--dry-run` resolves the toolchain for `--platform` and stages nothing, so
  "does this architecture have the artifacts" costs a round trip rather than a
  runner. On a refusal it names **every** blocked root, not the first — on an
  architecture being brought up, one gap per build is one build per gap — and
  it tells a CONFLICT between roots apart from a missing artifact.
- after staging, it reports every `NEEDED` soname the tree does **not**
  contain, naming who asks. A binary that wants one cannot start, and it says
  so only when something runs it. The s390x second generation met
  `libselinux.so.1` twice, a full build apart, before this existed.
- it says when a prefix is **already** on disk and will not be re-installed.
  `artifact.InstallFor` treats the existence of `<project>/v<ver>-h<hash>` as
  "already present", so a tree left half-written by a run that died — and
  inherited by the next job on a self-hosted runner — is indistinguishable
  from a complete one. Three runs reported "42 packages" and installed none.

None of the three refuses anything: the build that follows is the verdict.

### Recipes in YAML or HCL2

The `package.yml` schema (`schema/package.schema.json`) doubles as editor
autocompletion — add to a recipe:

```yaml
# yaml-language-server: $schema=https://go-zpkg.github.io/zpkb/package.schema.json
```

The same recipe in HCL2 (`package.hcl`) decodes to the identical `Recipe`:

```hcl
distributable {
  url              = "https://curl.se/download/curl-{{version}}.tar.bz2"
  strip-components = 1
}
dependencies = { "openssl.org" = "^1.1", "zlib.net" = "^1.2.11" }
build {
  script = ["./configure $ARGS", "make --jobs {{ hw.concurrency }} install"]
  env    = { ARGS = ["--prefix={{prefix}}", "--with-openssl"] }
}
provides = ["bin/curl", "bin/curl-config"]
```

## A seed pass: somebody else's toolchain as a build environment, named

The first build of our own toolchain needs something that runs. A SEED pass uses another registry's signed artifacts (go-pkgx's) as the build environment of ONE pass, and records that it did:

```sh
zpkx --seed-from oci://ghcr.io/go-pkgx/packages --seed-ledger seed.jsonl -- \
  zpkb factory --stage-only --seed-ledger seed.jsonl ...
zpkb builder --seed-from oci://ghcr.io/go-pkgx/packages --seed-ledger seed.jsonl --out rootfs
```

- `factory --seed-ledger` needs `--stage-only` and a seed in force (`$ZPKX_SEEDED`, a marker zpkx sets for the command it runs and never reads to start a seed). The factory reads the ledger once at its start, before any recipe has run, and signs that reading; `--seed-ledger-sha256` names the digest the outside of the build recorded for it, and a ledger that does not match is refused. A seed in force without the flag is refused, and the flag without a seed is refused, so an artifact built from a seed is never signed unmarked. `--mirror-from` is refused with it.
- The ledger goes into the stage plan (`seed`: the ledger digest and every entry). `publish-stage` writes the seed into the provenance (`externalParameters.seed`, `seed-source`, and one material per seed artifact with its digest) and into the SIGNED claim `zpkb-seed`, so the fact cannot be stripped afterwards.
- A seed-built artifact is NEVER promotable: `--mirror-from ... --require-origin` refuses a signed `zpkb-seed`. Only a second pass that builds from our own outputs, with no seed, produces artifacts that promote.
- `builder --seed-from` installs the rootfs from the seed (signatures verified, HTTP and unverified refused); it refuses `--dist` beside it, which would replace the seed as the source.
- go-pkgx stays refused as a dependency source and as a publish target.
- `origin --seeded` compares the installed tree with the artifact the signature vouches for: the pulled bytes must hash to the signed digest (a registry that re-points the tag between the digest read and the pull is refused), and every file and directory must match in kind, permission, setuid, setgid and sticky bits, content and link target.
- The provisioner's per-call ledger is a pipe handed to zpkx as descriptor 3 (`--seed-ledger-fd 3`, no path is passed or opened): nothing is left in a directory to be edited between zpkx's write and the factory's read, and nothing in the build root's filesystem can redirect it. The plan-phase ledger must still be empty when the seed is signed. A pipe is not a proof, so the factory also checks what it read. A record must name the seed registry that was asked for, a valid project name and keys that belong to the seed trust set, and two lines for one artifact must agree. Every record must match a seed in the store (its prefix and the digest in its install marker, found by walking the store, at any project depth), and every seed in the store that no earlier call accounted for must have a record, including one staged between two calls, so an injected record, a removed one or an empty ledger beside a staged seed is refused. A read that ended on the 200 ms deadline because something still held the pipe open is refused, not accepted, and so is a pipe that cannot have a read deadline. What this is: a detector of accidents (a zpkx that died, a lost or doubled record) and of a forgery by a writer that does not control the store. What it is not: a barrier against the same uid, or root. A process of the factory's own user can write to the descriptor and can also write the install markers, so it can make a forged record match. Where the platform cannot pass a descriptor the provisioner refuses to run.

## Pinning every artifact a build needs: `sources`

A build script that runs `curl` fetches bytes nothing pins. `sources` is the
place for them: a list in which **every** entry is fetched, each with a
mandatory `sha256`, and a digest mismatch (or a missing `sha256`) fails the
build.

```hcl
distributable {
  url              = "https://downloads.sourceforge.net/project/tcl/Tcl/{{version}}/tcl{{version}}-src.tar.gz"
  strip-components = 1
}
sources = [
  # an archive: unpacked into dest, relative to the build directory
  { url = "https://downloads.sourceforge.net/project/tcl/Tcl/{{version}}/tk{{version}}-src.tar.gz",
    sha256 = { "9.0.3" = "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23" },
    dest = "tk", "strip-components" = 1 },
  # a plain file: copied, not unpacked, under the last segment of the URL's path
  { url = "https://example.org/fix-themechanged-error.patch",
    sha256 = "cc0b4e42510d49c6decd464123ecf3b14ae9b47f9b4ed2ee64893e2d6520a264",
    dest = "patches", extract = false },
]
```

| key | meaning |
|---|---|
| `url` | required; `{{version}}` moustaches apply |
| `sha256` | required; a digest, or a map version → digest (fail-closed: a version absent from the map is refused), as for `distributable` |
| `dest` | directory relative to the build directory, default `.`; absolute paths and `..` are refused |
| `strip-components` | leading path components dropped when an archive is unpacked; refused with `extract: false` |
| `extract` | `false` copies the URL as one file (mode 0644; a script that needs it executable says so). Asked for, never inferred: an unknown archive extension still fails loudly, so a misspelt `.tar.gzz` is not silently staged as a file |

`platforms` is optional and takes the recipe-level key's spelling: an OS
(`linux`) or `os/arch` (`linux/x86-64`), one string or a list. An entry with
`platforms` is fetched only when the build target matches; an entry without it
is fetched everywhere, as before. If any entry is platform-restricted and none
of them covers the target, the build is refused with a message naming the
target. An unknown spelling is refused when the recipe is loaded. Provenance
materials list only the entries actually fetched. This is how a per-host
bootstrap compiler is pinned: one entry per host, each with its own digest.

```hcl
sources = [
  { url = "https://go.dev/dl/go1.26.11.linux-amd64.tar.gz", sha256 = "...",
    dest = ".bootstrap", "strip-components" = 1, platforms = ["linux/x86-64"] },
  { url = "https://go.dev/dl/go1.26.11.darwin-arm64.tar.gz", sha256 = "...",
    dest = ".bootstrap", "strip-components" = 1, platforms = ["darwin/aarch64"] },
]
```

A plain file never overwrites a file already in the build directory. Sources
are fetched after `distributable`, in the order listed, and each lands in the
build's provenance as a material (URI and SHA-256) after the main source.

**`distributable`'s list form is unchanged: it is fallback mirrors of ONE
source.** The entries are tried in order and the first that answers wins, so it
cannot carry a second artifact — use `sources` for that. `distributable`
itself accepts `extract = false` too, for a package that is one plain file
(a CA bundle): `sha256` is then required, and `strip-components` and `ref` are
refused.

Not covered: `sources` takes no git `ref` (a commit is not a hash of bytes),
and an unpinned `curl` in a build script is still not detected: refusing those is the lint
asked for in go-zpkg/zpkb#487. (The digests above are illustrative.)

## Why

Completes the pure-Go [`go-zpkg`](https://github.com/go-zpkg) family (artifact / zpkm /
zpkx / mirror) with the last Deno piece — a single static binary that builds pantry
recipes with no Deno/Ruby/patchelf runtime, and cross-builds cleanly.

## A dependency may be scoped to the package's own version

*Since **v0.81.0**. A recipe cannot use a key the judge reading it does not
know, so a pantry whose CI pins an older `zpkb` must move its pin first.*

A recipe resolves many versions and states one `dependencies` block, so every
bound in it has to satisfy all of them. In practice that means the most
restrictive requirement of the **oldest** resolvable version, which the newest
then pays for forever — because nothing re-measures a bound once it is written.
Measured over the upstream pantry:

| recipe | bound | versions excluded | stated reason |
| --- | --- | --- | --- |
| `llvm.org` | `cmake.org: '>=3<3.29'` | **69 of 71** | *"doesn't **seem** to install a bunch of the libs"* |
| `llvm.org` | `python.org: '>=3<3.12'` | **50** | none |
| `perl.org` | `llvm.org: <19` | **41** | none |

LLVM contradicts the second one itself — `llvm/CMakeLists.txt:1102-1111` sets
`LLVM_MINIMUM_PYTHON_VERSION 3.8` and calls `find_package(Python3 3.8
REQUIRED)`: a floor and **no ceiling**. The bound plausibly belonged to a
`distutils`-era llvm, which python 3.12 removed — correct for llvm ≤ 17, wrong
for llvm 23, and the recipe had no way to say both. Now it does: a key in a
dependency map that carries a version operator scopes its sub-map to the
package's own version.

```hcl
build {
  dependencies = {
    "python.org" = ">=3"

    # distutils, removed in python 3.12, is what the old ceiling was about
    "<18" = { "python.org" = ">=3<3.12" }
  }
}
```

**Why a predicate is unambiguous as a key, and why no new syntax was needed.**
The schema's `depKey` admits only `[A-Za-z0-9._+-]` segments, so a key carrying
any of `< > = ^ ~ *` **cannot** be a project name or a platform key. The
discriminator is this format's own grammar rather than a second one invented
beside it, which is why it cannot drift from what the schema accepts. The
predicate grammar is the one `if:` conditions already use on script steps, so a
recipe has **one** way to say "at these versions".

⚠ A bare `5.40` **is** a legal `depKey`, so it reads as a *project*. A scope
must carry an operator: write `=5.40`, not `5.40`.

⛔ More specific wins, in a fixed order — plain keys, then platform keys, then
version scopes — so a project named both plainly and under a key reduces the
same way every time. It was a single pass before, which let Go's randomised map
iteration decide the winner; that affected **platform** sub-maps already, and
adding a third kind of key only made the collision easy to write down.

⛔ Two answers, because the callers ask different questions. A build knows which
version it is building and gets the exact reduction. `closure`, `catalog`,
`depgaps` and `spechash` walk a recipe set asking *"what does this project
depend on?"* **before** any version is resolved, and for them a scoped
dependency has one answer per version — so an unknown version **unions** the
scopes and lets the stricter constraint win. A closure that over-constrains
fails loudly at resolution (*"no version of X satisfies A and B"*); one that
under-constrains resolves cleanly and ships an artifact linked against
something the recipe never asked for.

## Naming a tree, not only a package

A recipe describes one package: `versions`, `distributable`, `build`, `test`,
`provides`, `dependencies`. Until recently the only way to name a **group**
was a flat text file beside the format — `seed/order.txt`, 106 lines, and
`builder/toolchain.txt`, 95 — which could not be versioned, published,
installed or depended on.

A recipe carrying `members` is a **set**:

```hcl
# go-zpkg/base-toolchain
members = {
  # clang, lld, compiler-rt — the compiler itself
  "llvm.org" = "*"

  # libc, crt objects and the dynamic loader
  "gnu.org/glibc" = "*"
}
```

`zpkb closure go-zpkg/base-toolchain` resolves it. So does `zpkb factory
--recipes go-zpkg/base-toolchain`, and so would anything else that takes a
project name — a set is expanded **at the root**, before the dependency walk
looks at it, so nothing downstream learns the word.

### Why a recipe and not a new kind of file

The three systems that solved this agree on the shape:

| | |
| --- | --- |
| **Nix** | a tree *is* a derivation. `buildEnv` takes a list of packages and its output is a tree of symlinks. No new kind of object. |
| **Guix** | a manifest names packages; a **profile** is the tree it makes. |
| **Spack** | `spack.yaml` is the abstract set, `spack.lock` the concrete one — the same root specs *"may concretize differently"*. |

Nix's answer is the one taken. A set is an ordinary recipe, so it is signed,
attested, published and installed by everything that already does those
things for a package — rather than a second kind of artefact to keep in step.

### A set is UNORDERED, and that is the point

All three of those manifests are. The order comes out of resolution, not out
of the file, and `zpkb closure` produces it from the dependency graph.

Which is why **`seed/order.txt` is not a set and must not become one**. That
file is a *build order*: inside a dependency cycle the topological order is a
guess, and `order.txt` is the hand-tuned guess that works — `zpkb closure
--check-order` exists to judge it. `builder/toolchain.txt` is a different
thing, an *install* list, where order carries nothing; that is the one that
moved.

### `zpkb sign` — a second builder's word

`reproduce` answers *are these two artifacts the same artifact?* locally. `sign`
is the half that makes the answer travel.

Two people who build the same inputs get the **same** artifact — deliberately,
since an identity that varied with the builder could never be compared. So
the artefact stays one artefact and what differs is the *attestation*: each
builder attaches their own signature referrer to the published artifact, and a
client counts how many distinct trusted keys it can verify
(`ZPKG_TRUST_THRESHOLD`).

```
$ zpkb build …                                   # your own build
$ zpkb reproduce yours.tar.gz theirs.tar.gz      # do they agree?
$ zpkb sign -key you.sec -project fftw.org \
    -version 3.3.11-h27o3ysxva6swayci yours.tar.gz
signed fftw.org 3.3.11-h27o3ysxva6swayci (linux/x86-64) sha256:… with key 9f2c…
add it to a client's trust set with:
  ZPKG_EXTRA_TRUSTED_KEYS='<name>:RWQ…'
```

It **pushes no artifact**. Re-publishing to add a signature is how you end up
with two objects where the entire point was that there is one.

And it **refuses when the digests differ**, which is the interesting case —
`guix challenge` exists to report exactly that, and the report *is* the
finding: either the recipe is not reproducible or one of the two machines is
not what it claims. Both digests are printed, because "they differ" is not
something anyone can act on. `-force` exists and says what it does: it signs
bytes this build did not produce, which is the one claim a threshold must
never be able to make.

The referrer carries the signer's **key id** and no name. A name would be
written by whoever pushed it, and the line it would appear in — `signed by: …`
— is the one a reader uses to decide whether to trust the artefact. The name
a user sees comes from their own trust set.

### `zpkb lock` — the concrete half

Guix's manual puts it plainly: *"to reproduce a profile bit-for-bit,
manifests alone might not be enough"* — the same names resolve differently
against a different package set, so a manifest needs the channel revisions
beside it. Spack names the two halves: an environment from `spack.yaml` has
*"the same root specs... may concretize differently"*, one from `spack.lock`
has *"the same concrete specs"*.

`members` is the abstract half. `zpkb lock` is the concrete one:

```
$ zpkb lock --platform linux/x86-64 -o base-toolchain.lock.hcl go-zpkg/base-toolchain
set: go-zpkg/base-toolchain names 25 member(s)
lock: 41 project(s) pinned → base-toolchain.lock.hcl
```

```hcl
lockfile_version = 1
zpkb               = "v0.7.0"
platform         = "linux/x86-64"
generated        = "2026-10-05T09:10:39Z"
pantry           = "fd646990024e22f5752578cfdcfe2518b20c0797"
overlay          = "f8f6dcfd7b17410a6de780bdd58c81fbbb38d1b3"
roots            = ["go-zpkg/base-toolchain"]

locked = {
  "curl.se" = { version = "8.17.0", spec = "sha256:5284d597c180…" }
  "gnu.org/bash" = { version = "5.3", spec = "sha256:…" }
  …
}
```

**And it matters more here than in Guix.** A Guix manifest resolves
deterministically once the channel revision is pinned, because the version is
*in* the checkout. A pkgx recipe's `versions:` asks GitHub for tags **at
resolve time**, so pinning the pantry commit is not enough: the same pantry
resolves `gnu.org/binutils` to whatever the newest tag is the day you ask. The
resolved version has to be written down or it is not pinned at all.

The platform is in the header because it changes the answer: the same set
locks to **41** projects on `linux/x86-64` and **40** on `darwin/aarch64`,
`github.com/besser82/libxcrypt` being the difference. A lock that did not say
which platform it was taken on would be read as the other one's.

Two deliberate shapes:

- **Sorted by project, not in build order.** A lock is read as a diff, and a
  topological order makes every line move when one dependency does.
- **An unresolved project exits non-zero** and is named on stderr. A lock with
  a hole in it that reads as a success is a lock somebody commits.

### `-runnable` — build locks and run locks are different files

`zpkb lock` resolves each version from the recipe's `versions:` block, so it
pins **what the recipes can build**. That is exactly right for
`zpkb factory --lock`, which is about to build them, and wrong for
`zpkx --lock`, which can only install what the factory has already
**published**. The two run ahead of each other by construction.

Measured 2026-10-09, by generating a lock and running it in a `FROM scratch`
container rather than by reading the code:

```
$ zpkb lock -platform linux/aarch64 -o curl.lock.hcl curl.se
lock: 1 of 5 pin(s) NOT published for linux/aarch64 — `zpkb factory --lock` can
      build this file, `zpkx --lock` cannot run it:
    curl.se/ca-certs             2026.09.25     (published here: 2026.8.13)
    `zpkb lock -runnable` pins what is published instead.
lock: 5 project(s) pinned → curl.lock.hcl
```

Before this, that lock was written in silence and `zpkx --lock` refused it
with a message about a version nobody had chosen.

`-runnable` pins the newest **published** version that satisfies every demand
the closure places on each project — `PickVersionForAll`, the same function
the resolver itself asks, so the lock answers the question pkgx will ask of
it. A per-project "newest published" is **not** a closure: the first version
of this flag asked for `*`, pinned openssl 4.0.2 where `curl.se` demands
`^3`, and produced a file that could not resolve under a line saying it
could.

The mode is written into the file as `pinned = "recipes" | "published"`,
because `zpkb lock --check` re-resolves — and re-resolving by the other
question reports every pin as having moved.

The verdict is printed **every time**, including when everything is fine:
the defect being fixed was a silence, and a message that appears only on
failure leaves the clean case looking exactly like a `zpkb` that does not
check at all. It also refuses to endorse a lock with a **hole** in it: a
project that could not be pinned at all leaves the remaining pins all
installable and the file still not a closure.

### `spec` — because a version is not enough either

Spack's packaging guide says what goes into a spec hash: *"`build`, `link`,
and `run` dependencies all affect the hash of Spack packages (along with
`sha256` sums of patches and archives used to build the package, and a
**canonical hash of the `package.py` recipes**)"*.

The last clause is the one worth copying. Pinning a version catches an
upstream that moved; hashing the **recipe** catches the other half — a build
script edited in the pantry resolves to the same version and produces a
different package. A lock with versions alone calls those two builds the same,
which is the thing a lock exists not to do.

`spec` is a Merkle hash over the platform, the project, the resolved version,
the **parsed** recipe (every half of it the closure read) and the spec hashes
of the dependencies. It is taken over the parsed value, not the file, so
reformatting a recipe or rewriting its comments does not move it and changing
what it says does — Spack's "canonical", by a different route.

Measured: of **2091 recipes** in the pantry and the overlay, **0** fail to
serialise. The property that matters is tested both ways round — a change to a
leaf moves the leaf and everything above it; a change at the top moves the top
alone — and that test was checked against a deliberately broken hash, which
fails it, so it is not passing for free.

### The install prefix carries the build's identity

An artifact is installed at

```
<store>/<project>/v<version>-h<hash>
```

and never at `<store>/<project>/v<version>`. The hash is the short form of the
same Merkle identity `spec` takes — platform, project, resolved version,
canonical recipe, and the resolved prefix of every dependency — so a build is
addressed by **what it is** rather than by the version it claims.

Three things follow, and the first two are why pkgx's unhashed path had to go:

- **Two builds of one version are siblings.** `openssl.org@3.5.8` built against
  two different zlibs are two directories, both reachable, neither shadowing
  the other. Under `v<version>` the second install overwrote the first.
- **The prefix is baked into the binaries.** `otool -l` on a published
  `zlib.net` 1.3.2 shows `@rpath/zlib.net/v1.3.2/lib/libz.1.dylib`: the path
  is in every dependent, so a path that does not say which build it is makes
  the dependent unable to say either.
- **Dependencies make the hash Merkle for free.** An input is identified by
  its resolved prefix, and once that prefix carries its own hash, hashing it
  carries the whole dependency transitively — the mechanism Nix uses when a
  derivation references its inputs by store path.

The hash is a function of the **inputs**, computed before the compiler runs;
hashing the output into the output would be circular, which is why Nix hashes
the derivation and Spack the concrete DAG rather than the result.

#### The registry carries the same address, and the description to check it

An artifact is published under `<version>-h<hash>`, with the glibc flavour still
readable in between where there is one (`8.20-glibc2.27.0-h<hash>`), and its
per-platform manifest carries the spec it was hashed from:

```
io.github.go-zpkg.spec = {"v":1,"platform":"linux/x86-64","deps":[…],"recipe":"sha256:…"}
```

**The tag carries the address, the annotation carries the meaning**, and
`artifact.VerifySpec` recomputes the first from the second. That is what makes
the identity checkable rather than merely asserted: a reader does not have to
trust that the hash describes this build, it can recompute it. An identity
hashed over inputs the artifact does not carry — which is what `zpkb` briefly
did — cannot be checked at all.

It also settles a question Nix leaves open. A store path says *which* build
and never *what* build, so "the one with CUDA?" needs a second index; Spack
keeps the spec queryable (`spack find libdwarf +debug`) and conda writes its
hash inputs to `info/hash_input.json`. Readability here is a tooling property,
not a naming one.

An artifact `zpkb publish` only mirrored gets **neither**: no hash in the tag and no
annotation. We do not know how it was built, and a tag claiming an address
would say we do.

Because the tag is an address, `zpkb factory`'s "already published?" check asks
about the **build**: it plans first — resolving the version and the closure,
which is what the identity is a function of — and only then consults the
registry. Asking about the bare version, which is what it did while a version
was an address, skipped every package whose *recipe* had changed, because the
version had not.

Because the directory name can no longer be composed from a version, a reader
**asks** the store (`artifact.ResolveBuild`) instead of building the path. It
answers with the one installed build, or refuses when two are installed —
refuses rather than taking the newest, since two builds of one version are
exactly the case that has no order to take the first of.

A default version is **not** a property of the store: it lives in a view
(`artifact.LinkView`), which is what lets a shared read-only NFS export hold the
builds while each user, environment or container rootfs computes its own links
from it.

### `zpkb lock --check` — a lock nobody reads is a wish too

Cargo's `--locked` and npm's `ci` exist because a lock nobody verifies is a
lock nobody can rely on: both refuse to run when the lock and a fresh
resolution disagree.

```
$ zpkb lock --check base-toolchain.lock.hcl
lock: linux/x86-64 · 2026-10-05T09:10:39Z · 41 pinned, 2 hour(s) old · pinned from the recipes
lock: pantry revision differs: fd64699… → 9ab12cd…
  gnu.org/binutils                   2.47 → 2.48
  zlib.net                           spec 6a2d499db9ab → spec 90fae00e667c — same version, so something it is built FROM changed
lock: 2 of 41 moved
```

Exit **0** when nothing moved, **1** when something did, **2** when the check
could not be made at all.

**The second line of that diff is the one a version-only lock cannot
produce.** Measured on the real `zlib.net` recipe: a comment added to its
build block moves nothing, and one flag added to its `./configure` line moves
the spec hash while the version stays `1.3.2`.

It takes its roots, its platform, the revisions it expects **and how it was
pinned** from the file. Naming any of them again on the command line would let
the two disagree, and the check would then be of a different question from the
one the file answers — so it refuses a project name, and `-runnable`, beside
`--check`.

A **revision that moved is said and is not fatal**: a pantry can move without
moving any answer, and calling that drift would make the check cry wolf until
nobody ran it. An **unresolved project is kept apart from drift** for the
mirror-image reason — a registry outage must not read as a pantry that
changed.

### The header is data, not a comment

The first version wrote the platform, the roots and the revisions as `#`
lines. Right facts, wrong place: a comment cannot be read back. They are
attributes now, with `lockfile_version` beside them — Spack's lockfile carries
a `lockfile-version` and records which spack wrote it, and the compatibility
rule that comes with it (new readers read old locks; old readers refuse new
ones) is worth copying before it is needed rather than after.

### `zpkb version` — because a lock names a zpkb you have to be able to find

Every lock records which zpkb wrote it:

```hcl
zpkb = "v0.15.0"
```

Until now there was no way to ask a binary whether it was that one.
`zpkb --version` answered `flag provided but not defined: -version` and
`zpkb version` answered `unknown command: version`, so the question could only
be settled with `go version -m`, and only if you still had the binary rather
than a `zpkb` on your `PATH`.

```console
$ zpkb version
zpkb v0.15.0
```

Both spellings exist and are asserted to give the same answer, because two
code paths that can drift apart are how a tool starts reporting two versions
of itself.

It prints **exactly** what a lock carries, leading `v` included. A prettier
rendering would make the two disagree, and reading a lock and asking *"do I
have that bk?"* is the whole use of the command.

There is **no `-ldflags` stamp**. The sibling tools inject
`-X main.version=<tag>`, which can be set to anything regardless of what was
compiled — that is how a release workflow re-run published binaries labelled
with a tag they were not built from. This reads `debug.ReadBuildInfo`, so it
cannot disagree with the binary it is in, and the release workflow checks it
against the tag by equality alongside the build info of every binary it ships.

### `zpkb buildenv` — what a published artifact says it was built with

A rebuild for a toolchain vulnerability needs a **before**. When a Go patch
release fixes a standard-library defect, nothing about the recipe or the
upstream version changes — only the compiler in the build environment does. So
"should this be rebuilt?" is "was it built with the fixed one?", and that
question needs the artefact to have recorded an answer.

Until v0.17.0 it recorded nothing. Measured on the published
`stedolan.github.io/jq`, whose **signed** SLSA statement carried:

```json
"builder": { "id": "https://github.com/go-zpkg/zpkb" },
"buildDefinition": { "externalParameters": {}, "internalParameters": {} }
```

— the same two constants every artifact in the registry holds. `DepTokens`
resolved the whole build and runtime closure on every build and threw the list
away.

Now the provenance carries it, and this reads it back:

```console
$ zpkb buildenv --platform linux/aarch64 stedolan.github.io/jq 1.8.2
github.com/kkos/oniguruma 6.9.10
go.dev 1.27.2
…
```

**`--list` sweeps**, and counts the three outcomes separately:

```
8 read · 0 record a build environment · 8 record none · 0 unreadable
```

⛔ Those three are never folded together. "Records nothing" is every artifact
published before v0.17.0; "unreadable" is a registry that told us nothing, and
counting it as an absence would be the same defect as a census that could not
read reporting zero. An empty list is a failure rather than a clean registry,
and a line the reader cannot use is named rather than skipped — a silent skip
makes the totals smaller for a reason nobody can see.

That first sweep is the answer to "can a rebuild counter be derived?": **not
from what is published today.** Nothing in the registry is comparable yet, so
the counter starts at zero for everything and becomes meaningful only after a
rebuild under v0.17.0 or later. Debian's rule — *"the absence of a
debian_revision is equivalent to a debian_revision of 0"* — is not a
convention here, it is the literal state of the registry.

#### `--needs` — which artifacts a security release obsoletes

The operator's real question after a Go patch release is not "what was this
built with" but **"which of these need rebuilding"**:

```console
$ zpkb buildenv --platform linux/aarch64 --needs go.dev@1.27.2 --list recipes.txt
STALE   acme.org/tool 1.2.3: go.dev 1.27.1, want >=1.27.2
n/a     zlib.net 1.3.2: does not use go.dev
ok      other.org 2.0.0: go.dev 1.27.2

3 read · 3 record a build environment · 0 record none · 0 unreadable
of those: 1 need rebuilding for go.dev>=1.27.2 · 1 already have it · 1 never used it
```

⛔ **"Does not use it" is its own column.** A C package has no `go.dev`:
counted as stale it would rebuild the whole registry for a Go release, counted
as ok it would make the figure meaningless. That is the mistake a denylist
makes when it inherits a taxonomy's blind spot.

⛔ **And a rebuild of the compiler counts as the compiler.** `go.dev 1.27.1_1`
is 1.27.1 built again, which does not contain a fix that landed in 1.27.2 — so
it is stale, and the version comparison has to see the rebuild suffix to say
so.

The judgement is reported **beside** the reading, never instead of it. Run
against the registry as it stands today:

```
8 read · 0 record a build environment · 8 record none · 0 unreadable
of those: 0 need rebuilding for go.dev>=1.27.2 · 0 already have it · 0 never used it
and 8 record nothing, so this says nothing about them
```

`0 need rebuilding` would read as an all-clear on its own. The last line is
what stops it being one.

### `--rebuild` — a new build of a version that is already published

A recipe fix can change the binary without changing the upstream version.
Measured on 2026-11-02: go-zpkg/packages#399 gave `fftw.org` its SIMD
codelets, the darwin lane rebuilt it, and the result went out as **`3.3.11`**
— the same tag the scalar build had. `nm` on the two shows 0 → **207**
`_neon` symbols, so they are plainly different artifacts; nothing in the
registry said so, and anyone holding the old one kept it.

`--rebuild` publishes such a build as the next **`_N`** instead:

```console
$ zpkb factory --platform darwin/aarch64 --recipes fftw.org --force --rebuild
rebuild: fftw.org 3.3.11 is already published for darwin/aarch64 — publishing as 3.3.11_1
```

`_N` is Homebrew's `rebuild` and Debian's `+bN`. artifact already understood it
— it parses, it sorts **after** the build it supersedes, and an exact pin
tells the two apart — and nothing produced it. This is the half that mints
it.

⛔ **The number comes from the REGISTRY, per platform.** A tag listing spans
every platform, so counting tags rather than publications would let a darwin
rebuild take its number from a linux one — a gap on one and a collision on
the other. And a read that fails **refuses**: a guessed number is a
collision, and falling through to "no counter" would quietly replace the tag
`--rebuild` exists to preserve.

⛔ **Opt-in, and deliberately not folded into `--force`.** Every manual
dispatch of the darwin lane already sets `FORCE=1` unconditionally. A counter
minted on every forced run would bump `N` each time a lane was retried after
failing at the publish step, littering the registry with tags nobody asked
for. A rebuild that *supersedes* is a decision about meaning, so it is stated.

⛔ **pkgx cannot read a `_N` tag.** libpkgx's `SemVer` constructor
(`src/utils/semver.ts:26-41`, read 2026-11-02) splits on `.` and accepts a
part only on `/^(\d+)([a-z])$/` — last part only — or `/^\d+$/`, else throws
`invalid version`. `3.3.11_1` has the part `11_1`, which matches neither. So
**pointing a pkgx client at this registry is unsupported** once a
project carries a rebuild. That was weighed and accepted: it throws rather
than resolving the wrong artifact, which is the better of the two failures. The
alternatives are in artifact's README, with why each was rejected.

### `zpkb origin` — may this artifact be promoted?

Bringing up an architecture from nothing needs two registries. The first
generation takes its compiler and shell from the host distribution, because on
an architecture with no artifacts there is nothing else to take them from, so it
publishes to a **throwaway** registry on the runner and never leaves it. The
question that gets anything out of there is one fact per artifact: *was the
host's toolchain involved?*

Measured 2026-11-01, the registry could not answer it:

```console
$ zpkb buildenv --platform linux/s390x lz4.org 1.10.0
buildenv: lz4.org 1.10.0 (linux/s390x): the provenance records no build environment
```

⛔ **An empty build environment is a hint, not a statement.** A `--bootstrap`
build resolves no artifacts, so its environment is empty — but so is a mirrored
artifact's, and so is every artifact published before zpkb recorded one. Three
situations, one silence, and a gate cannot read a silence.

So the factory now states it, and this reads it back:

```console
$ zpkb origin --platform linux/s390x lz4.org 1.10.0
lz4.org 1.10.0 linux/s390x
  host toolchain used: no — built from artifacts
  inputs resolved from: oci://ghcr.io/go-zpkg/packages
```

`--promotable` turns it into a gate: silent and exit 0 only when the
provenance **proves** the host toolchain was not used.

```console
$ zpkb origin --platform linux/s390x --promotable lz4.org 1.10.0
origin: lz4.org 1.10.0 (linux/s390x) is NOT promotable: its provenance does
not say whether the host toolchain was used, and an unstated answer is not a "no"
```

⛔ **It requires an explicit `0`, and treats every other answer as no** —
including silence. Not because unrecorded artifacts are suspect, but because the
two failures do not cost the same: refusing a good artifact costs a rebuild,
while promoting a host-built one puts an unpinned distribution compiler's
output into the production registry under our signature. That is also why the
recorded value is a tri-state and not a boolean: a `bool` zero is `false`,
which would read as "not a bootstrap", and every artifact published before this
existed would have claimed to be promotable.

A mirrored artifact records where it was **put** and nothing about who compiled
it, so it fails the gate on purpose: recording a field is not the same as
answering the question.

#### `--require-origin` — promoting, as opposed to copying

`zpkb factory --mirror-from` already copies an artifact from one dist and
republishes it signed and attested. Adding `--require-origin` turns that into
a **promotion**: every artifact is refused unless its *source* provenance proves
the host toolchain was unused.

```console
$ zpkb factory --platform linux/s390x --mirror-from oci://127.0.0.1:5000/seed \
    --to oci://ghcr.io/go-zpkg/packages --require-origin --recipes "lz4.org"
❌ FAIL lz4.org 1.10.0: origin: not promotable: it was built with --bootstrap,
   so its compiler and shell came from the host distribution rather than from
   artifacts
```

Three properties worth stating, because each one is a way this could have been
written wrong:

- **The check runs before the download.** Nothing about having the tarball in
  hand makes an artifact more promotable.
- **The verdict is carried, not restated.** The facts belong to the *build*,
  and copying an artefact between registries does not change what built it.
  Re-stating them as this run's own would launder a verdict it did not make,
  and would overwrite `inputs-from` — the only record that the artifact was
  built against the seed rather than against the production registry.
- **"I could not ask" is not "the answer was no."** An unreachable source
  registry is reported as a read failure naming the registry, never as a
  judgement about the artifact. A gate that folds the two together turns every
  network blip into a permanent verdict.

`--require-origin` without `--mirror-from` is refused at argument-parsing
time, beside the other argument checks rather than further into the run: there
is no source provenance to read, and a gate the operator believes ran is worse
than no gate.

#### What the gate authenticates

The provenance a registry serves is not evidence on its own: whoever can write
to the registry can write a provenance. `--require-origin` and
`zpkb origin --promotable` therefore read the origin only through a signature:

- the source must be an `oci://` registry and signature verification must be on
  (`ZPKG_VERIFY` not `0`); `--mirror-from` keeps verification on for an `oci://`
  source and a static dist is refused outright;
- the artifact must be signed by a trusted key (the seed registry's key goes in
  `ZPKG_EXTRA_TRUSTED_KEYS`), and that signature must name the sha256 of the
  provenance it vouches for, so a provenance swapped or added later is ignored;
- the provenance subject must be this artifact's digest, and the bytes
  republished must be the bytes whose origin was authenticated.

`bootstrap=0` only records that a flag was absent. The factory now also measures
whether it runs in the sovereign rootfs (`--libc zpkx`, not `--bootstrap`, no
system headers, and every compiler or linker on the standard paths one of
zpkb's shell stubs) and signs the result as the `sovereign` fact. A promotion
requires `sovereign=1` under the signature. Artifacts published before this
change carry no signed `sovereign` fact and are refused until rebuilt; the
refusal names the missing fact.

### What is still missing, named rather than left out

The spec hash covers the **inputs**, as Nix's derivation hash and Spack's spec
hash do. It does not cover the **output bytes** of the built artifact. `artifact`
can *verify* a digest but has no exported way to be *asked* for one, and a lock
taken before anything is built has no output to name. The header of every lock
says so, rather than letting a reader assume a guarantee that is not there.

## `zpkb unresolved` — can what we published actually load?

It installs a project's closure into a store of its own and reports every
reference the store cannot answer: an ELF names a **soname** and the
loader searches for it, so the question is whether anything in the closure
provides that name; a Mach-O names a **path**, so the question is a stat.
Each project gets its own store, because a shared one rescues a missing
reference by accident — `gpgme`'s undeclared `libgpg-error` resolved for
months because something else in the same closure happened to bring it.

```console
zpkb unresolved -platform linux/aarch64 gnu.org/bash curl.se
```

⛔ **`-platform` exists because an audit that can only ask about its own
machine covers one platform of six.** Wired into CI (`sonames.yml` in
go-zpkg/packages) this found **967 unresolvable references over 259 of
1407 packaged projects** on linux/x86-64 — and said nothing about the other
five, which were not clean but **unasked**. The reader was never the
problem: it walks ELF and Mach-O in one pass precisely because a store
built on one platform is read on another. Only the install half was
host-bound, until `artifact.CompleteClosureFor` (artifact v0.55.0).

A half-parsed platform is refused before anything is fetched: resolved
against an empty arch, every artifact is absent, every closure is empty, and
the audit would report a flawless platform it never installed.

## `zpkb vulnid` — under what name does a CVE database know this package?

Rebuilding an artifact to fix a vulnerability needs a vulnerability to point at,
and pointing at one needs a name both sides agree on. `pkg:pkgx/openssl.org@4.0.2`
is a name **no database knows**: OSV answers `{}` to a `pkg:generic/…` purl, and
NVD's CPE route answers for anything and answers badly — measured on
2026-10-11, `cpeName=…openssl:3.5.7` returned **27 CVEs, four of them from
2009**, because every openssl criterion in the reply reads `openssl:*` with no
upper bound at all.

A recipe usually already names something better, in its `versions:` block.
`zpkb vulnid` reads it:

```
$ zpkb vulnid -dir ~/Library/Caches/pkgx/pantry
1563 recipe(s) read from …/pantry/projects
  declared  0
  derived   1241
  none      322
by database:
  GitHub         1186
  crates.io      114
  GitLab         40
  npm            14
  RubyGems       1
```

Three sources, and they rank. **derived** costs nothing: it is read off the
recipe's `versions:` block and off the project's own name. **declared** is an
entry a person wrote in an identity table, and wins, because it exists only
where the derivation was judged wrong or absent. **none** is the honest answer
for the rest — `zpkb vulnid -list none` names them, and they cluster on a handful
of upstream hosts (`ftp.gnu.org`, `www.x.org`, `sourceforge`), so the table that
fixes them is short.

### The project's own name is a source too

Measured: `crates.io/bpb`, `crates.io/huniq`, `crates.io/stego` and
`crates.io/albion_terminal_rpg` were reported as having **no identity at all**,
while their own names say both the registry and the package. That is four
projects the derivation could answer for and did not.

The larger half is the **110** `crates.io/*` projects that *do* derive a GitHub
repository from their recipe. For those this adds a second, better key rather
than a first one: OSV keys Rust advisories (RUSTSEC) by `crates.io` with
curated version ranges, where a repository-keyed advisory carries whatever
range its filer wrote. Both keys are emitted — two keys mean two databases can
be asked and neither has to be guessed.

This is **not** the same trick as reading a `url:`. A distributable URL says
where the source came from, which is a host and not a package name; that is the
322-project CPE case, and inventing a package name from it is what produced 27
openssl CVEs. A project called `crates.io/bpb` is different in kind: the
pantry's naming convention put the registry and the package name there, and the
package is what the registry calls it.

The host and the ecosystem are not always the same word — `npmjs.com` is the
host and `npm` is the OSV ecosystem — and getting that backwards produces a
query that matches nothing, silently. A test compares the two maps, because
`CPAN` and `CocoaPods` were in the first version of the host map and are not
OSV ecosystems at all.

No network call, ever. The alternative — one query per project — is 1908
requests against a budget this fleet shares with Renovate, and the question
"can this be asked at all?" is answered by the recipes.

### The identity table

```yaml
schema-version: 1
projects:
  openssl.org:
    cpe: [openssl:openssl]
  oracle.com/berkeley-db:
    cpe: [oracle:oracle_berkeley_db, oracle:berkeley_db]
```

Two rules it refuses to bend:

- **A `cpe` name must carry its vendor.** Yocto's documentation gives the reason
  from the other end: *"'tar' has been matching CVEs for the GNU tar package and
  also the node-tar node.js extension. To avoid this problem, use the vendor
  name as a prefix"*. A bare `openssl` is the 27-CVE answer above.
- **A database key is checked against an allowlist**, which is OSV's own list of
  defined ecosystems copied whole, spelling and case included — plus `cpe`,
  `GitHub` and `GitLab`, which are not ecosystems but repository-keyed
  advisories. A typo (`githb:`) in a denylist world is not a typo, it is a
  project that silently has no identity, indistinguishable from one nobody has
  looked at yet.

Several names per database is deliberate, not a mistake: NVD files Berkeley DB
under two product names, and dropping one loses the advisories filed there.

Note also what is **not** in OSV's ecosystem list: `zpkx`. It has `Homebrew`,
`Alpine`, `Wolfi`, `Chainguard` and `vcpkg`. The long-term answer for this fleet
is to become one of those rather than to keep translating into someone else's.

### `zpkb attest` — what a published artifact actually carries

Four kinds of thing are attached to an artifact as OCI referrers. Nothing could be
asked **which of them a given artifact has**.

```
$ zpkb attest --platform linux/x86-64 bitwarden.com 1.22.1
bitwarden.com 1.22.1 linux/x86-64: 4 referrer(s)
  application/vnd.cyclonedx+json       3412 bytes  pkg:pkgx/bitwarden.com@1.22.1
  application/vnd.in-toto+json         1890 bytes  https://github.com/go-zpkg/zpkb@v0.26.0
  application/vnd.openvex+json         1204 bytes  1 statement(s): MAL-2026-3020=not_affected
  application/vnd.dev.cosign…          …           signed
```

That gap was not academic. `zpkb publish --advisories` attaches the VEX document
only when the tree holds a record for the project, and the factory passes the
tree through six lanes — one of which **mounts it into a chroot**. Every one of
those is a place the document can silently fail to appear, and an artifact with no
document looks exactly like an artifact nobody had anything to say about.
`zpkb source` and `zpkb buildenv` both *read* the provenance; neither **enumerates**.

**`--require` turns the report into a gate**, which is the point: a report is
what you read after something went wrong, a gate is what tells you.

```sh
zpkb attest --require application/vnd.openvex+json bitwarden.com 1.22.1
```

Two details that are not decoration. The summary **reads the blob**, not the
artifactType — a referrer that says OpenVEX and carries `{"statements":[]}`
reports `0 statement(s) — an empty document says nothing`, which `--require`
cannot see, because the type *is* present. And the output is ordered by
artifactType: a registry promises no order, and a report whose lines move
between runs cannot be diffed.

## `zpkb advisories` — what the answer was, and what we decided

Identity is half of it. The other half is the finding itself, and the record
that **justifies a rebuild**: one file per project, at
`advisories/<project>/advisories.yaml`.

```yaml
schema-version: 1
project: openssl.org
advisories:
  - id: CVE-2026-0001
    aliases: [GHSA-xxxx-xxxx-xxxx]
    events:
      - timestamp: 2026-10-10T12:00:00Z
        type: detection
      - timestamp: 2026-10-11T09:00:00Z
        type: fixed
        fixed-version: 3.5.8_1
```

### Events, not a state

The shape is Wolfi's, and the reason is that a state cannot be superseded.
Wolfi's measured `curl.advisories.yaml` holds **59 advisories and 71 events** —
so most have one and some have three, which is exactly the history a single
`status:` field throws away. OpenVEX says the same from the other end:
`timestamp` is a required field, and a statement's timestamp is "the time at
which the information expressed in the Statement was known to be true". Two
contradictory undated statements cannot be ordered, so neither can be believed.

So: events, each **required** to carry a timestamp, and the last one in time
decides. They are sorted on read, so a rebase that reorders two appends cannot
change what a record means.

The vocabulary is Wolfi's too — `detection`, `true-positive-determination`,
`false-positive-determination`, `fixed`, `fix-not-planned`,
`pending-upstream-fix` — because each maps onto a VEX status, and a record that
cannot be emitted as VEX is a record only this fleet can read.

### `fixed-version` is where the rebuild counter earns its keep

`fixed-version: 3.5.8_1` says the **rebuild** carries the fix, not plain
`3.5.8`. `Advisory.FixedBy` asks `artifact` through the constraint language the
resolver already uses, so `3.5.8` does **not** satisfy it and `3.5.7_9` does
not either. Wolfi's own `fixed-version: 8.5.0-r0` carries the same counter, in
their spelling.

Which is why a Debian-style `3.5.8-1` is **refused**: that is how Debian and
Alpine spell the same thing, `artifact` splits a rebuild on `_`, and the record
would otherwise claim that plain `3.5.8` carries a fix it does not have.

### ⛔ `detected-version` is why a decision does not outlive its subject

A purl names a version, so the OpenVEX document we publish is a statement
**about a version**. A `false-positive-determination` carries none and reads
as "not affected, full stop" — so a determination made about 1.0.0 would be
re-emitted, unchanged, about every later version we publish.

```yaml
      - timestamp: 2026-10-10T12:00:00Z
        type: detection
        detected-version: 1.0.0        # what OSV was asked about
      - timestamp: 2026-10-11T09:00:00Z
        type: false-positive-determination
        justification: component_not_present
```

A known id reported at a version no event covers is **detected again**, as a
second event on the same record, and `vulnfetch -fail-on-new` then asks for a
decision about *that* version. Measured with a stub OSV that answers the same
id whatever version is asked:

| the record names | the catalogue publishes | gate |
|---|---|---|
| 1.0.0 | 1.0.0 | exit 0 — that is what was examined |
| 1.0.0 | **2.0.0** | exit **1** |
| *nothing* | 2.0.0 | exit 0 — a record written before this field keeps the old behaviour |

That last row is deliberate: reading "names no version" as "does not cover
2.0.0" would re-detect every legacy record at once — 90 over the real pantry
— and a gate that goes red for everything on its first run is one people
learn to scroll past.

Practitioner guidance on VEX is explicit that a "not affected" goes **stale**
when the component changes, and that a consumer-facing statement which is
stale is worse than none at all: it stops the reader looking. Wolfi's
`fixed-version` carries a version for the same reason; this is the field a
*determination* was missing.

### ⛔ The gate and the document read the same silence in opposite directions

`detected-version` is now meaningful on **every** event, not only a detection:
for a decision it says which version the decision was made for. And the two
readers of that field disagree on purpose about what an *absent* one means.

| | a record that names no version | why |
|---|---|---|
| the gate (`vulnfetch -fail-on-new`) | covers every version — stays green | it interrupts **us**, and 90 legacy records going red at once is a gate people learn to scroll past |
| the document (`EncodeVEX`) | covers no version — downgrades | it reassures a **stranger**, and a stale "not affected" stops them looking |

The harms are not symmetric, so the defaults are not either: *when in doubt do
not interrupt ourselves; when in doubt do not reassure somebody else.*

What the emitter does, for the two statuses that tell a reader to stop
looking — `not_affected` and `fixed`:

```
record determines not_affected for 1.0.0, artifact is 1.0.0  → not_affected + justification
record determines not_affected for 1.0.0, artifact is 2.0.0  → under_investigation, status_notes names 1.0.0
record names no version at all,           artifact is 1.0.0  → under_investigation, status_notes says so
```

Neither the `justification` nor the `impact_statement` travels onto a
downgraded statement: the prose was written about another artefact, and
carrying it over would put the reassurance back in by the side door — in the
one field a human actually reads.

`affected` is deliberately **not** downgraded. Restating it for an unexamined
version over-warns, which costs noise; downgrading it would turn a warning
into "we are looking into it", and nothing should move that way by itself.

A product therefore has to say which version it is, and `EncodeVEX` refuses
one that does not rather than guessing from the purl:

```
vuln: vex: demo: product pkg:pkgx/demo@1.0.0 has no version — a statement
names a version, so one cannot be written for an artefact that has none
```

One record can now produce **two** statements, when the versions it was handed
are not all covered. That is what #340 could not express: a single statement
for every product is only correct while every product is the same version.

### The path and the file must agree

`zpkb advisories` refuses a file whose `project:` disagrees with its directory. A
file copied from a neighbouring project and edited in part would otherwise
attach its findings to the wrong package, and nothing else in the record says
which project it is about.

```
$ zpkb advisories -dir advisories
2 project(s) read from advisories, 3 advisory(ies)
  detection                    2
  true-positive-determination  0
  false-positive-determination 0
  fixed                        1
  fix-not-planned              0
  pending-upstream-fix         0
```

### OpenVEX out

`vuln.EncodeVEX` writes the records as an OpenVEX v0.2.0 document, which is the
form a scanner already reads. The mapping is the design decision, so it is a
table and not a chain of ifs:

| event | VEX status | |
|---|---|---|
| `detection` | `under_investigation` | a database said our NAME matched |
| `true-positive-determination` | `affected` | + an action statement |
| `false-positive-determination` | `not_affected` | + the justification **label** |
| `fixed` | `fixed` | a version of ours carries it |
| `fix-not-planned` | `affected` | + why nothing is coming |
| `pending-upstream-fix` | `affected` | + what is being waited on |

`detection` becoming `under_investigation` rather than `affected` is the one
worth defending: a detection is a database saying our *name* matched, and the
27-CVE openssl measurement above says what that is worth. Emitting those as
`affected` would publish 23 false alarms with our signature on them.

A `not_affected` statement carries the machine-readable `justification` label
and puts the prose in `impact_statement` beside it, never instead of it —
OpenVEX allows the text form and then says it "breaks VEX automation and
interoperability".

Each statement is dated with **its own event's** timestamp, not the document's,
so a publish does not re-date the whole history to today. The encoding is
deterministic — subjects by project, statements by id — because a document that
differed run to run could not be compared with the one already attached to a
artifact.

### The process that runs recipes never holds the keys

A recipe is a shell script from a third-party pantry, run with network access as
the same user as the factory, so whatever is in that process's environment is
readable by it, signing key and registry token included. The factory therefore
splits in two:

```
zpkb factory --stage-only --to oci://ghcr.io/go-zpkg/packages --platform linux/x86-64 \
             --artifacts dist  --recipes "…"          # no key, no token
zpkb publish-stage dist --to oci://ghcr.io/go-zpkg/packages \
             --sign key.sec                            # no recipe code runs here
```

`--stage-only` builds and stages every artifact and writes `publish-plan.json`
beside them: per artifact its file, `sha256`, size, tag, spec, source and build
environment. It is refused with `--sign`, with `$SIGNING_KEY` set, and with
`--mirror-from` (a mirror runs no recipe). Runs into the same `--artifacts`
directory extend one plan; a plan the run cannot read is refused, never replaced.

`publish-stage` treats the plan as input from the untrusted side. Before anything
is pushed it checks the destination (`--to` is mandatory, has no environment
default and must equal the plan's), every file against its recorded digest and
size (read through `os.OpenRoot`, so a path or symlink cannot leave the stage),
and every tag against the spec it claims, and it refuses the whole stage on any
mismatch. It then signs and pushes exactly what `factory --to` would have, with
the same attestations: `TestPublishStageEqualsFactoryTo` compares the two
byte for byte. What it cannot re-derive (the source URI, the build environment)
is what the build says about itself, as it always was. A hostile recipe can still
lie inside its own artifact, and signing still vouches for the build, not for the
recipe. What it can no longer do is take the key or the token.

Under `--stage-only` the recipe's `test:` block runs against the staged build
itself: its installed prefix plus its runtime and test dependencies, nothing
asked of any registry for the package under test, nothing published. The verdict
(`pass`, `fail`, `not-run`, `no-test`, or `skipped` under `--test=false`) is
recorded per artifact in `publish-plan.json`. `publish-stage` refuses, per
artifact and with exit status 1, a `fail`, a `not-run`, and a plan with no
verdict or an unknown one; the other artifacts still publish. A recipe with no
`test:` block, and a run with `--test=false`, publish as `factory` always did.

### The artifact carries its own justification

```
zpkb publish --to oci://ghcr.io/go-pkgx/packages --project openssl.org \
           --version 3.5.8_1 --platform linux/x86-64 \
           --advisories ./advisories  openssl.org-3.5.8_1.tar.xz
```

`zpkb factory --advisories` takes the same flag and passes it to **every** publish
it makes — the artifacts it builds and the ones it mirrors, because what is known
about a package is not a property of who compiled it.

The factory also **validates the whole tree once, before the first build**.
`vexReferrer` refuses to publish an artifact whose record does not parse, which is
the right answer in the wrong place: a chunk of fifty runs for hours, and the
fortieth artifact is where that refusal would land. The check runs before the
pantry is read and before the closure walk resolves a single version over the
network, and says what it loaded:

```
advisories: 1 project(s) with records, from advisories
```

The count is there because a run that loaded the tree and one pointed at the
wrong path otherwise print the same thing — and an **empty** tree is an error,
for the same reason `zpkb advisories` makes it one.

With `--advisories`, the artifact gets a third referrer beside its CycloneDX SBOM
and its in-toto SLSA provenance:

| referrer | says |
|---|---|
| `application/vnd.cyclonedx+json` | what is inside |
| `application/vnd.in-toto+json` | how it was built, and by which `zpkb` |
| `application/vnd.openvex+json` | which vulnerabilities were considered, and what was decided |

This is what makes a rebuild **self-justifying**. Until now an artifact rebuilt
for a security fix looked exactly like one rebuilt for any other reason: the
version string said `_1` and nothing said why.

Three details earn their keep:

- The statement is bound to the **tarball digest**, the same anchor the SBOM,
  the provenance and the cosign payload use. Four attestations about one
  artefact, not four descriptions that happen to agree.
- The document is dated with the build timestamp, which honours
  `SOURCE_DATE_EPOCH`, and its `@id` carries no date or counter. So re-publishing
  an unchanged artifact produces a byte-identical document — the same referrer
  digest, an idempotent re-push rather than a second referrer beside the first.
  The `@id` *does* carry the platform, because two platforms' artifacts are two
  artefacts.
- **A broken advisory file stops the publish.** A file that exists and cannot be
  parsed must not become a silent omission: the artifact would be pushed, look
  complete and assert nothing — and an absent VEX document reads as "nothing was
  ever found", which is the opposite of what a broken record means. A file that
  is simply *absent* is fine and attaches nothing, because most projects have
  never been triaged.

## `zpkb vulnfetch` — asking a database, once

```
$ zpkb vulnfetch -dir ~/Library/Caches/pkgx/pantry
1563 recipe(s) read from …/pantry/projects
129 identity(ies) asked, 1207 not answerable by OSV (repository- or CPE-keyed)
55 finding(s) across 14 project(s)
  bitwarden.com
    MAL-2026-3020            npm:@bitwarden/cli
  crates.io/bat
    GHSA-p24j-h477-76q3      crates.io:bat
    RUSTSEC-2021-0106        crates.io:bat
  …
nothing written — pass -write to record these as detections
```

**One HTTP request.** OSV's `/v1/querybatch` takes a list and answers in order,
so 129 questions cost one round trip and no API key. Nothing here touches the
GitHub API, so nothing here competes with Renovate.

It **reports by default**. A sweep that writes on its first run writes whatever
that run happened to find into files a person then has to audit; and the thing
worth knowing before writing anything is the scale.

### ⛔ Ask at the version we publish, or the number means nothing

Without `-catalog` the question is about the package **as a whole**, so the
answer is every advisory it has ever carried — including ones fixed long
before the version we ship. The two questions over the same pantry, the same
run, on **2026-10-17**:

```
$ zpkb vulnfetch -dir pantry
171 identity(ies) asked, 1500 not answerable by OSV (repository- or CPE-keyed)
748 finding(s) across 21 project(s)

$ zpkb vulnfetch -dir pantry -catalog catalog/darwin-aarch64.json
137 of them asked AT the version the catalogue publishes; the rest as a whole package
171 identity(ies) asked, 1500 not answerable by OSV (repository- or CPE-keyed)
90 finding(s) across 5 project(s)
```

**658 of the 748 do not affect anything we publish.** A list that large with
no decision behind any line is read once and then never again.

### ⛔ And read the remaining 90 carefully — it is not what it looks like

Every one of those five projects — `coder.com/code-server`, `nx.dev`,
`pi.dev`, `snyk.io`, `vercel.com/next` — answers **`no artifact here`** on
darwin/aarch64. They have no published version, so `-catalog` had none to
pin, and they fell back to being asked as **whole packages**. The 90 are the
unfiltered question surviving for the projects the filter could not reach.

Against what we actually ship on this platform the count is **zero**:
`bitwarden.com` is published at 1.22.1 and OSV returns nothing for it, which
is right — `MAL-2026-3020` affects 2026.4.0.

Checked with `zpkx ls <project>` on each of the six, after reading the
written records and finding **no `detected-version` in any of them** — the
field only appears when a version was asked about, so its absence was the
tell. The first version of this paragraph called the 90 "a list someone can
work", which was wrong: they are about packages this platform does not carry.

The honest next step is therefore not to triage them but to **skip a project
with no artifact for the platform**, so the unfiltered question is not asked at
all.

The output says **which** question it asked, in both modes, because the same
count means a different thing in each.

⛔ **It will not guess.** Two projects can carry one identity; if they publish
different versions there is no single version to ask about, and picking either
would under-report for the other. Under-reporting hides a vulnerability, so
the question widens back to the whole package and the count says so.

### `-fail-on-new` — a verdict, not just a report

`vulnfetch` returned 0 whatever it found. With `-fail-on-new` it exits
non-zero when a finding has **no decision recorded** in the advisory tree:

```
vulnfetch: 1 finding(s) with no decision in advisories —
  rebuild, or record why the published version is not affected
```

⛔ **The gate is on what is NEW, not on what exists.** A job that failed while
any finding existed would be red from its first run — 90 of them on
2026-10-17 — and a check that is red every day is one people learn to scroll
past. That is not hypothetical in this fleet: `versioncheck` on the landing
site was red for eight days running for exactly that reason, fixed by hand
each time rather than noticed.

Red on something **new** is a question with an answer, and the error names
both ways out because either one makes it green again.

### ⛔ OSV cannot be asked about a repository

Measured against the live API on 2026-10-11:

| asked | answered |
|---|---|
| `{"package":{"name":"time","ecosystem":"crates.io"}}` | 4 vulnerabilities |
| `{"package":{"name":"bpb","ecosystem":"crates.io"}}` | `{}` — nothing known |
| `{"package":{"purl":"pkg:github/curl/curl"}}` | `{}` |

The first two are the normal pair. The third is the one that shapes the tool: an
OSV query takes a package in an **ecosystem** (or a commit), and a GitHub
repository is neither — so the `{}` there is *not* "no known vulnerabilities".

Unanswerable identities are therefore **dropped before the request and counted
out loud**, rather than sent and found empty. Of this pantry's identities, 1207
are repository- or CPE-keyed: a sweep that stayed quiet about them would read as
a clean bill of health for three quarters of the fleet. Those need GitHub's own
advisory API, which does cost the shared budget, and that is a separate piece of
work not pretended to here.

### What `-write` does, and what it refuses to do

It adds a `detection` event per new id, whose note records **which key found
it** — with two identities per project that is not recoverable afterwards.

Three things it will not do:

- **Overwrite a decision.** An id already recorded is left entirely alone, and
  the check includes every advisory's `aliases`, because a record filed under
  its CVE is the same record OSV returns under a GHSA. Without this, every run
  would drag a `fixed` back to `under_investigation` and the triage would never
  converge.
- **Trust a positional answer blindly.** OSV answers in the order asked and says
  nothing about which query each result belongs to, so a response with fewer
  results than queries is an **error** — otherwise every finding from that point
  on would be attributed to the wrong package.
- **Replace a file it cannot read.** A file that exists and does not parse stops
  the sweep, rather than being replaced by one holding only today's detections,
  which would delete every decision in it.

### A known overstatement

The finding count counts **ids, not vulnerabilities**. `RUSTSEC-2021-0106` and
the GHSA beside it for `crates.io/bat` are the same defect — verified, its
`aliases` contain `CVE-2021-36753` — and OSV's *batch* answer carries no
aliases. So 55 ids are fewer than 55 distinct vulnerabilities. Resolving them
costs one `/v1/vulns/{id}` request each and is not done yet; `MergeDetections`
already de-duplicates against aliases *already recorded*, which is what keeps a
hand-written record from being doubled on the next run.

## Where the source came from, and whether it changed

`zpkb` extracts tarballs from **233 distinct upstream hosts**, and in the
sovereign lane the build that consumes them runs as root inside a chroot. What
checks that?

Almost nothing, before this. `zpkb` does verify a source checksum when a recipe
declares one — but measured over a fresh `pkgxdev/pantry`, exactly **one recipe
of 904** declares one, and that one (`openssl.org`) points at a `.sha256`
served by the *same host* as the tarball: it detects corruption, not
substitution. ⛔ That is a measurement of **their** corpus, and it is cited
here because it is what this project resolved from when the feature was
written — not as a standard ours is held to. Ours is the opposite rule:
`zpkb lint --require-provenance` refuses a recipe of ours that records no
provenance, and `sourcepin` will not record a digest without naming who signed
it. The same recipe declares `sig: ${{url}}.asc`, and nothing in bk
reads that field at all.

So `--source-mirror` grew a second job. It already kept every archive a build
downloads, addressed by its sha256; now it also records **which digest each URL
served**, and refuses bytes that disagree:

```
source pin: 9f86d0…  matches what https://ftp.gnu.org/…/sed-4.10.tar.xz served before
fetch: this URL has served different bytes before: https://…/x-1.2.tar.gz
  now serves 2c26b4…, and served 9f86d0… before
```

Trust on first use. It does not make an upstream trustworthy — it makes a
**change** visible, which is the part nobody had.

A version bump is not a change here: the version is in the URL, so a new
release asks a question that has never been asked and is recorded rather than
refused. What fires is the *same* URL serving *different* bytes — a re-cut
release, a compromised mirror, a hijacked domain.

The uncomfortable third case is a store that cannot be **asked**. That is not
an absent pin, and treating the two alike is how trust-on-first-use quietly
becomes trust-every-time. They are distinguished, said out loud, and
`--source-pin-strict` decides which one is fatal — warn and continue by
default, because an unreachable registry is not evidence of tampering and a
build must not die because ghcr hiccuped.

Still open (go-zpkg/bk#282): nothing reads `sig:`. Verifying a detached
signature needs a key policy — *whose* key — and that is a decision, not a
patch.

## What bounds an `.xz` source archive

`.tar.xz` sources are decoded with
[`go-compressions/xz`](https://github.com/go-compressions/xz), not
`ulikunitz/xz`. The latter allocates the LZMA2 dictionary whole from the block
header (`DictCap` is a minimum, not a ceiling): a 44-byte `.xz` declaring a
1.5 GiB dictionary allocated 1,610,663,976 bytes. Here the decoder's window
grows with the decoded data: the same kind of input — a stream declaring 1.5 GiB
over a few bytes — allocates about 22 KB (`fetch/xzbomb_test.go`, run in CI as a
compiled binary under `ulimit -v` and `GOMEMLIMIT`). The dictionary a stream may
make the decoder keep is capped at 256 MiB (`fetch.maxXzDictionary`, above the
64 MiB of `xz -9`); data that needs more is refused with `xz.ErrTooLarge`.
`ulikunitz/xz` remains in `go.mod` only for the tests that build `.xz` fixtures
(encode side).

## The ELF RUNPATH rewriter

`fixup.SetRunpath` overwrites an ELF's `DT_RUNPATH`/`DT_RPATH` string **in place**
(pure Go): it locates the string offset in `.dynstr` and rewrites the bytes,
zero-padding slack. It cannot grow `.dynstr`, so the build links binaries with a
long `-Wl,-rpath` placeholder that the final `$ORIGIN`-relative value fits inside —
the same budget model `patchelf --set-rpath` sidesteps by rewriting the file.

## Where it is proven to work

A build tool whose whole premise is *Target ≠ Host* has to be right about
widths and byte order, because that is exactly what it is manipulating: ELF
`DT_RUNPATH` strings rewritten in place, `.dynstr` offsets, tar and xz streams,
OCI manifests. None of that is checked by a compiler. So CI builds eight
targets — linux on amd64, arm64, riscv64, ppc64le, s390x and loong64, plus
darwin/arm64 and windows/amd64, all `CGO_ENABLED=0` — and then **runs the
suite** on five of them under `qemu-user`:

```
test (arm64, qemu)  test (riscv64, qemu)  test (ppc64le, qemu)
test (s390x, qemu)  test (loong64, qemu)
```

`s390x` is there because it is big-endian and nothing else here is; an ELF
header read through the host's byte order instead of `encoding/binary` is wrong
on that machine and on no other. `-count=1`, so a cached PASS from the host
architecture cannot stand in for a run that never happened. The same job holds
the 100% statement-coverage gate: below it, CI prints the uncovered blocks and
fails.

## `zpkb catalog`

Builds the catalogue a browser (`zpkx ls`, `<TAB>`) reads: every project named
by the pantry and the overlay, with its runtime dependencies, and — with
`--versions` — the newest version the registry really carries for
`--platform`. `--publish` pushes it signed.

`--recipes DIR` (repeatable) names a **flat** recipe tree
(`<DIR>/<project>/package.yml`, the layout of `go-zpkg/packages/wasip1/recipes`)
whose projects are listed too. A platform lane can build a project that neither
the pantry nor the overlay carries — `github.com/simdjson/simdjson` for
`wasip1/wasm` — and without this flag its published artifact was missing from
that platform's catalogue (go-zpkg/packages#387).

**The lane's recipe wins** for a project both trees have (since go-zpkg/bk#376;
v0.45.0 had the pantry winning). A recipe in a platform lane's tree is the
recipe *for that lane*: its `provides` and `dependencies` describe the artifact
that was actually built, whereas the pantry's describe the host build. With the
pantry winning, the published `wasip1/wasm` catalogue gave `zlib.net` no command
although its artifact ships `bin/minigzip.wasm`, listed `age-keygen` for
`filippo.io/age` although the lane builds `./cmd/age` only, and made `lua.org`
depend on `gnu.org/readline`, which the lane does not build against and which
is not published for that platform. The recipe is read whole, never merged key
by key, so a catalogue entry never mixes two builds. The rule for a caller:
pass `--recipes` **only** for a platform whose tree is its authoritative recipe
set (the packages workflow does so for `wasip1/` alone). A tree that is not
would now override the pantry for every project it shares; there is no merge
mode, by design.

## `zpkb provides` — does the artifact say what the catalogue says?

```
zpkb provides --catalog catalog.json --platform wasip1/wasm [--fail] [project...]
```

Installs each project for `--platform` (every published project of the
catalogue when none is named), lists the commands in the artifact's `bin/`
(`.wasm` stripped on `wasip1`, `.exe` on `windows`) and compares them with the
`provides` the catalogue states. The two differences are reported **apart**,
because they are different failures:

- **LISTED, NO FILE**: `zpkx -Q age-keygen` names a package that cannot supply
  the command.
- **FILE, NOT LISTED**: the command exists and is invisible to `zpkx -Q`,
  `zpks search` and the `<TAB>` index (`minigzip` in the zlib.net artifact).

`--catalog` takes `catalog.json` or the catalogue artifact's `.tar.gz`. `--fail`
exits 1 on any finding or on a project that could not be checked. It lives in
`zpkb` because it needs the catalogue types, the platform-explicit closure
install and the same `provides` reduction `zpkb catalog` applies; a workflow runs
it right after `zpkb catalog`. Found by running every published wasm module, not
by comparing the two (go-zpkg/bk#376).

## License

BSD-3-Clause. Copyright the bk authors.
