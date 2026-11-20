package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/go-zpkg/zpkb/fetch"
)

// Seams: the command is driven in tests without a network.
var (
	fetchDigest               = fetch.Digest
	fetchVerified             = fetch.DigestVerified
	fetchVerifiedDecompressed = fetch.DigestVerifiedDecompressed
	readKeyFile               = os.ReadFile
)

// runSourcePin implements `zpkb sourcepin <url>`: fetch a source archive and
// print the `sha256` a recipe should pin, in the form the schema wants.
//
// ⛔⛔ IT EXISTS SO THE AUTHOR AND THE BUILD USE THE SAME FETCHER. Every other
// distribution computes a pinned digest with a tool that is not the one its
// build runs — `shasum`, `nix-prefetch-url`, `spack checksum` — so a host quirk
// the build will meet is not met while authoring. fetch.Digest is the
// builder's own download path: non-2xx is an error, a 5xx is retried, a
// truncated body is resumed and length-checked, the User-Agent is ours, and a
// body whose magic bytes are not the archive's is refused.
//
// The hazard is why this is a command and not a line in a runbook. Authoring a
// recipe by hand on 2026-11-08, with GitHub's release CDN flapping 504:
//
//	$ curl -sSL -o xz-5.8.4.tar.gz https://…/xz-5.8.4.tar.gz   # 504
//	$ shasum -a 256 xz-5.8.4.tar.gz
//	bef140a1a96994029153dca8c00b1750b9a5a764fb9db2dc68d7bb40e8a29e8a
//
// 92 bytes of error page, and a digest indistinguishable from a good one. A
// pinned digest is FAIL-CLOSED by design, so a wrong pin is worse than none:
// every later build of that version fails, and the pin looks authoritative
// while doing it. Printing the size beside the digest is part of the point —
// 92 bytes is visible in a way a hex string is not.
func runSourcePin(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("sourcepin", flag.ContinueOnError)
	fset.SetOutput(stderr)
	version := fset.String("version", "", "the version this URL serves; prints only the keyed form")
	// ⛔⛔ THREE FLAGS, AND THE SECOND TWO HAVE NO DEFAULTS ON PURPOSE. --sig
	// asks who signed the bytes; --key says against which key, and --key-source
	// says how the author came to trust that key. Not one of Gentoo, Arch,
	// Debian or Guix records the last one — Debian's uscan(1) says "you must
	// verify the downloaded OpenPGP key using its full fingerprint value WHICH
	// YOU KNOW IS THE TRUSTED ONE", which is unauditable by construction. A
	// fingerprint nobody can trace back to a page and a date is a fingerprint
	// the next reader has to trust on your word.
	sig := fset.String("sig", "", "the detached signature's URL, or `auto` to try <url>.asc then <url>.sig")
	keyFile := fset.String("key", "", "the author's public key file (armored or binary); required with --sig")
	keySource := fset.String("key-source", "", "where that key's fingerprint came from — a URL, a page, a person; required with --sig")
	// ⛔⛔ WITHOUT THIS, A KEYRING IS A SET AND NOT A CHOICE. Measured against
	// the real thing on 2026-11-08: https://ftp.gnu.org/gnu/gnu-keyring.gpg is
	// 3 700 423 bytes and holds every GNU maintainer's key, so `--key` pointed
	// at it would accept a signature from ANY of them — the same degradation
	// Guix's `--key-download=always` produces in CI. Arch's `validpgpkeys` is
	// the answer and `PKGBUILD(5)` states it plainly: makepkg "will only accept
	// signatures from the keys listed here and will ignore the trust values
	// from the keyring". It is optional because a key FILE holding exactly one
	// key is already a choice; it is strongly advised for anything else, and
	// the output says how many keys the file held so the author can tell which
	// case they are in.
	fingerprint := fset.String("fingerprint", "", "the fingerprint the signing key must have (spaces and colons ignored); without it, any key in --key is accepted")
	// ⛔⛔ THE DEFAULT IS TODAY'S BEHAVIOUR, SO NOTHING ALREADY RECORDED CHANGES
	// MEANING. kernel.org signs the UNCOMPRESSED tar — its signature.html says
	// "the signature is made against the uncompressed version of the archive …
	// so there is only one signature required for .gz and .xz compressed
	// versions" — and a recipe's url names the .tar.xz, so the verifier was fed
	// bytes the signature never covered (go-zpkg/zpkb#492). It is a flag and
	// not a fallback: retrying the other stream after a failure would make
	// "it verified the other way" indistinguishable from "somebody signed a
	// different archive", and a refusal that can be shrugged off is not one.
	covers := fset.String("sig-covers", fetch.CoversServed,
		"which bytes the signature covers: `served` (the file at <url>) or decompressed (the .tar inside it, as kernel.org signs)")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if fset.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: zpkb sourcepin [--version V] [--sig URL|auto --key FILE --key-source TEXT [--sig-covers served|decompressed]] <url>")
		return 2
	}
	url := fset.Arg(0)

	// ⛔ A FLAG THAT SILENTLY DOES NOTHING IS WORSE THAN A MISSING ONE, and
	// here the something it would silently not do is the verification. --sig
	// without a key would print a digest that looks checked.
	if *sig != "" && (*keyFile == "" || *keySource == "") {
		fmt.Fprintln(stderr, "sourcepin: --sig needs --key (nothing is ever fetched from a "+
			"keyserver, so the key comes from a file you chose) and --key-source (where that "+
			"key's fingerprint came from, which is the one thing no other distribution records)")
		return 2
	}
	if *sig == "" && (*keyFile != "" || *keySource != "" || *fingerprint != "" || *covers != fetch.CoversServed) {
		fmt.Fprintln(stderr, "sourcepin: --key, --key-source, --fingerprint and --sig-covers only mean something with --sig")
		return 2
	}
	// ⛔ A MISSPELLED VALUE MUST NOT FALL BACK TO THE DEFAULT. --sig-covers
	// decompresed would otherwise verify the served bytes and print a pin that
	// says `covers served`, which is the one wrong answer this flag exists to
	// prevent somebody writing into a recipe by hand.
	if *covers != fetch.CoversServed && *covers != fetch.CoversDecompressed {
		fmt.Fprintf(stderr, "sourcepin: --sig-covers %q is neither %q nor %q — it says which bytes "+
			"the project signed, and guessing it wrong is how a digest gets a warrant that "+
			"never covered it\n", *covers, fetch.CoversServed, fetch.CoversDecompressed)
		return 2
	}

	if *sig != "" {
		return pinSigned(url, *sig, *keyFile, *keySource, *fingerprint, *version, *covers, stdout, stderr)
	}

	digest, size, err := fetchDigest(url)
	if err != nil {
		fmt.Fprintf(stderr, "sourcepin: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "%s\n  %d bytes, fetched with the builder's own fetcher\n", url, size)
	if *version != "" {
		// The keyed form is the one a recipe wants: the url interpolates
		// {{version.raw}}, so one scalar would serve exactly one of the
		// versions it can resolve.
		fmt.Fprintf(stdout, "\n  sha256 = {\n    %q = %q\n  }\n", *version, digest)
		return 0
	}
	fmt.Fprintf(stdout, "\n  sha256 = %q                 # only for a recipe that resolves ONE version\n", digest)
	fmt.Fprintf(stdout, "  sha256 = { \"<version>\" = %q }   # what you almost certainly want\n", digest)
	// ⛔ SAID EVERY TIME, because almost nothing upstream carries either field.
	// Measured over pkgxdev/pantry at 4eb778f with this repository's own loader
	// counting the recipes: 1932 recipes, 1 naming `sha:` (openssl.org), 1
	// naming `sha256:` (github.com/Virviil/oci2git), 3 naming `sig:`
	// (ffmpeg.org, libuv.org, openssl.org). An author who never hears that a
	// signature might exist will not go looking for one.
	//
	// ⛔ go-zpkg/zpkb#282 says "1 of 904" and "the one `sig:`". The denominator
	// was an older pantry and the `sig:` count was simply wrong — checked here
	// rather than relayed, which is why these lines name the projects: a count
	// nobody can follow back to a name is a count nobody can refute.
	fmt.Fprintf(stdout, "\n  Nothing says WHO produced these bytes. If the project publishes a\n"+
		"  detached signature, --sig <url>|auto --key <file> --key-source <text>\n"+
		"  records that too, and prints the provenance block to paste.\n")
	return 0
}

// autoCandidates is what `--sig auto` tries, and it depends on which bytes the
// signature covers.
//
// ⛔⛔ `auto` COULD NOT FIND KERNEL.ORG'S SIGNATURE EVEN IN PRINCIPLE, and
// appending to the compressed URL is why. go-zpkg/zpkb#492 measured the four
// names on 2026-11-16: `linux-7.2.15.tar.xz.asc` 404, `.tar.xz.sig` 404,
// `.tar.xz.sign` 404, `linux-7.2.15.tar.sign` **200**. A signature names the
// bytes it covers, so when it covers the DECOMPRESSED archive its URL derives
// from the decompressed name — strip the compression suffix first.
//
// `.sign` leads for that shape because it is the name kernel.org publishes;
// `.asc` and `.sig` follow because [fetch.DigestVerified] moves on from a 404
// and some projects do use them. For the served shape nothing changes.
func autoCandidates(url, covers string) []string {
	if covers != fetch.CoversDecompressed {
		return []string{url + ".asc", url + ".sig"}
	}
	plain := url
	for _, ext := range []string{".xz", ".gz", ".bz2"} {
		if strings.HasSuffix(plain, ext) {
			plain = strings.TrimSuffix(plain, ext)
			break
		}
	}
	return []string{plain + ".sign", plain + ".asc", plain + ".sig"}
}

// pinSigned is `sourcepin --sig`: the digest, plus who vouched for the bytes
// and how the author came to trust them.
//
// It prints a `provenance` block rather than a new schema field, deliberately.
// The schema's `provenance { read / consulted / note }` already exists for
// exactly this kind of claim — what the recipe was written from — and a key is
// that kind of claim. Adding a field before any recipe carries one would be an
// API written against a guess.
func pinSigned(url, sig, keyFile, keySource, fingerprint, version, covers string, stdout, stderr io.Writer) int {
	key, err := readKeyFile(keyFile)
	if err != nil {
		fmt.Fprintf(stderr, "sourcepin: %v\n", err)
		return 1
	}

	// `auto` mirrors Debian's `Pgp-Mode: auto`, documented as "uscan checks
	// possible URLs for the signature file". Both names are tried because both
	// are in the wild, and the one that answered is printed: a recipe should
	// record the URL that worked rather than the guess that produced it.
	cands := []string{sig}
	if sig == "auto" {
		cands = autoCandidates(url, covers)
	}

	verify := fetchVerified
	if covers == fetch.CoversDecompressed {
		verify = fetchVerifiedDecompressed
	}
	pin, err := verify(url, cands, key, fingerprint)
	if err != nil {
		fmt.Fprintf(stderr, "sourcepin: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "%s\n  %d bytes, fetched with the builder's own fetcher\n", url, pin.Size)
	fmt.Fprintf(stdout, "  signed by %s\n  %s\n  verified against %s — no keyserver was asked\n",
		pin.Fingerprint, pin.Identity, keyFile)
	// ⛔⛔ PRINTED BECAUSE THE FIELD'S OWN DOC SAID IT WAS AND IT WAS NOT.
	// go-zpkg/zpkb#506 added SourcePin.SignedAt with the comment "it is
	// reported because it is now part of the verdict … a reader of a pull
	// request cannot tell those apart unless the instant is printed" — and
	// nothing printed it. The test asserted the field was populated, which is
	// not the same claim. "Verified" now means "the key was valid WHEN IT
	// SIGNED", and that is a different verdict from "the key is valid", so the
	// clock it was judged at belongs in the output. gpg prints it for the same
	// reason.
	// ⛔ AND IT SAYS WHICH INSTANT THE CHECKS RAN AT WHEN THAT IS NOT THE
	// SIGNATURE'S. Since go-zpkg/zpkb#512 a key refreshed after it signed is
	// judged at its newest self-signature; the sentence below used to claim the
	// signature's own instant unconditionally, and on gnu.org/libidn2 2.3.8 it
	// printed exactly that while the checks had run fourteen months later.
	judged := pin.JudgedAt
	if judged.IsZero() {
		judged = pin.SignedAt
	}
	switch {
	case pin.SignedAt.IsZero():
		fmt.Fprintf(stdout, "  ⚠ the signature carries no creation time, so the key's expiry "+
			"was judged at this instant — the strict clock\n")
	case judged.Equal(pin.SignedAt):
		fmt.Fprintf(stdout, "  signed at %s, and that is the instant the key's expiry was judged at\n",
			pin.SignedAt.UTC().Format(time.RFC3339))
	default:
		fmt.Fprintf(stdout, "  signed at %s; judged at %s, the key's newest self-signature, "+
			"because the key was refreshed after it signed (go-zpkg/zpkb#512)\n",
			pin.SignedAt.UTC().Format(time.RFC3339), judged.UTC().Format(time.RFC3339))
	}
	// ⭐ WHICH BYTES, SAID OUT LOUD, BECAUSE THE DIGEST AND THE WARRANT NO
	// LONGER DESCRIBE THE SAME ONES. Only said for the uncommon answer: a line
	// on every invocation repeating the default is noise that trains the eye to
	// skip the line that matters.
	if pin.Covers == fetch.CoversDecompressed {
		fmt.Fprintf(stdout, "  the signature covers the DECOMPRESSED archive, not the file above; "+
			"the digest below is still the file's, which is what a build downloads\n")
	}
	// ⛔ THE KEYRING'S REAL SHAPE, SAID OUT LOUD. An author who passed a file
	// holding one key and an author who passed every GNU maintainer's key get
	// the same "signed by" line otherwise, and only the second needs
	// --fingerprint. Skipped entities are reported for the same reason: a key
	// this cannot read is a key nothing can verify against, which is safe, and
	// silence about it would not be.
	if pin.KeysScanned > 0 {
		fmt.Fprintf(stdout, "  the named key, found after walking %d primary key(s) in the file\n",
			pin.KeysScanned)
	} else {
		fmt.Fprintf(stdout, "  %d key(s) read from the file\n", pin.KeysRead)
	}
	if fingerprint == "" && pin.KeysRead > 1 {
		fmt.Fprintf(stdout, "  ⛔ %d keys and no --fingerprint: this says \"somebody in that "+
			"file signed it\". Re-run with --fingerprint %s to say which.\n",
			pin.KeysRead, pin.Fingerprint)
	}

	if version != "" {
		fmt.Fprintf(stdout, "\n  sha256 = {\n    %q = %q\n  }\n", version, pin.SHA256)
	} else {
		fmt.Fprintf(stdout, "\n  sha256 = { \"<version>\" = %q }\n", pin.SHA256)
	}
	// ⛔⛔ NOT `sig = …`, WHICH IS WHAT THIS PRINTED AND WHAT IT COST.
	//
	// It sat directly under the `sha256 = {…}` block above, in output that reads
	// as HCL to paste — and `sig` is read by NOTHING (go-zpkg/zpkb#282). So the
	// three signed recipes written against this output moved it to the nearest
	// key that did exist, `sha`, which means "where the expected SHA-256 of the
	// archive is published" (schema/package.schema.json:141) and which the build
	// FETCHES and compares. Measured with this repository's own reader:
	//
	//	fetch.DeclaredSHA256(".../grep-3.12.tar.xz.sig", "grep-3.12.tar.xz")
	//	→ no line names grep-3.12.tar.xz — the server returned text, not an
	//	  archive: "-----BEGIN PGP SIGNATURE----- …"
	//
	// and an unreadable checksum file is a build failure by design
	// (build/runner.go:746-749). All three would have failed at the fetch, and
	// `zpkb lint` cannot see it because linting does not fetch
	// (go-zpkg/recipes#89 removed them).
	//
	// So it is printed as a COMMENT, which cannot be pasted as a field, and it
	// says where the URL does belong. When #282 gives the signature a field this
	// becomes that field's name — and not before.
	fmt.Fprintf(stdout, "  # the signature URL is NOT a recipe field: `sig` is read by nothing\n"+
		"  # (go-zpkg/zpkb#282), and `sha` means \"where the expected SHA-256 is\n"+
		"  # published\" — a .sig there FAILS the build. It belongs in provenance:\n"+
		"  #   %s\n", pin.SigURL)

	// ⛔⛔ THE PASTED BLOCK IS THE ONLY PART THAT SURVIVES, so every fact the
	// terminal printed above has to be in it too. The lines above are read once
	// by whoever ran the command; this is what the next reader of the recipe
	// has. A verdict that exists only in a scrollback was not recorded.
	var extra string
	switch {
	case pin.SignedAt.IsZero():
	case judged.Equal(pin.SignedAt):
		extra += fmt.Sprintf("  signed at  %s — the instant the key's expiry was judged at,\n"+
			"             not the moment this was run, so a key that has lapsed since does\n"+
			"             not retract the warrant (go-zpkg/zpkb#484)\n",
			pin.SignedAt.UTC().Format(time.RFC3339))
	default:
		extra += fmt.Sprintf("  signed at  %s\n"+
			"  judged at  %s — the signing key's newest self-signature: it was\n"+
			"             refreshed after it signed, and a self-signature newer than\n"+
			"             the instant judged would count as expired (go-zpkg/zpkb#512)\n",
			pin.SignedAt.UTC().Format(time.RFC3339), judged.UTC().Format(time.RFC3339))
	}
	if pin.Covers == fetch.CoversDecompressed {
		extra += "  covers     the DECOMPRESSED archive, which is what this project signs:\n" +
			"             one signature serves every compression of one release. The sha256\n" +
			"             below is the COMPRESSED file's, because that is what a build\n" +
			"             downloads — two byte streams, one operation (go-zpkg/zpkb#492)\n"
	}

	// The block to paste. The fingerprint is uppercase hex with no separators,
	// which is Arch's documented rule and the strictest of the three read.
	fmt.Fprintf(stdout, "\nprovenance {\n  note = <<EOT\n"+
		"The source archive is signed, and the signature was checked when this\n"+
		"digest was recorded rather than at every build: the signature's job is to\n"+
		"justify WRITING the hash, and the hash is the durable pin. That is Guix's\n"+
		"division (its `origin` record has no signature field; `guix refresh` does\n"+
		"the checking) and it is why nothing here needs the key at build time.\n\n"+
		"  signature  %s\n"+
		"  key        %s\n"+
		"  identity   %s\n"+
		"%s"+
		"  fingerprint came from: %s\n\n"+
		"No keyserver was consulted. Guix's --key-download defaults to `auto`,\n"+
		"which it documents as `interactive` on a TTY and \"else always\" — so in CI\n"+
		"an unknown key is fetched and accepted, and the check degrades to\n"+
		"\"somebody signed it\". Here an unknown key is a refusal.\nEOT\n}\n",
		pin.SigURL, keyFile, pin.Identity, extra, keySource)
	return 0
}
