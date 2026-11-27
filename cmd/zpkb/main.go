// Command zpkb is a pure-Go recipe build tool, written from scratch and
// Target≠Host by design (first-class cross-compile, notably Windows PE
// artifacts built on a linux/darwin host).
//
// ⛔ IT IS NOT "a brewkit". That word is pkgx's name for its own build tool and
// carries its imagery; this command reads a recipe, builds it in a zpkx
// environment, relocates the install tree and packages an artifact, and those
// are the words for what it does. pkgx's brewkit is credited in the README's
// bibliography, where naming it is the point.
//
// ⛔ AND THE COMMAND IS `zpkb`, NOT `bk`. Every line below said `bk` until
// 2026-11-15 — the whole published godoc page told a reader to run a binary
// that no longer exists. The rename was deliberate and `version_test.go` holds
// the reason: `bk` is now free for upstream's brewkit to sit on the same PATH,
// which is also why `BREWKIT_TARGET` is not read and `ZPKB_TARGET` is
// (target.go). A renamed command whose own documentation keeps the old name is
// the generation nobody updated.
//
// This entrypoint currently exposes the pieces implemented so far:
//
//	zpkbtarget            print the resolved build target (honours ZPKB_TARGET / --platform)
//	zpkbfixup <prefix>    run the post-build relocatability fix-ups on an install prefix
//	zpkbversions          list a recipe's candidate versions
//	zpkbbuild             build a recipe into an artifact
//	zpkbpublish           push a built artifact to an OCI registry
//	zpkb publish-stage    sign and push what `factory --stage-only` staged, from a process that ran no recipe
//	zpkbclosure           print a project set's transitive runtime closure (topological)
//	zpkbcatalog           build (and publish, signed) the catalogue pkgx ls
//	                     and <TAB> read
//	zpkbrunlog            read a factory job log: counts, stages, and whether
//	                     the parse agrees with zpkb's own totals
//	zpkblock              resolve a set to the versions it means today, write them down, and --check them later
//	                     (-runnable pins what is PUBLISHED, so `zpkx --lock` can run the file)
//	zpkbfactory           build a recipe set's whole closure and publish every artifact
//	zpkbsource            fetch the source a published artifact attests it was built from
//	zpkbvulnid            say, per project, the name a vulnerability database will
//	                     accept — derived from the recipe, or declared in a table
//	zpkbadvisories        validate a tree of per-project advisory records and say
//	                     what state each one is in
//	zpkbvulnfetch         ask OSV what it knows about a pantry, in one request,
//	                     and (with -write) record it as dated detections
//	zpkbeol               whether a version is on an upstream release line that
//	                     is still supported — the question OSV cannot answer,
//	                     because an abandoned line has no advisories YET
//	zpkbattest            say what a PUBLISHED artifact carries — SBOM, provenance,
//	                     signature, OpenVEX — and --require it
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/config"
	"github.com/go-zpkg/zpkb/fixup"
	"github.com/go-zpkg/zpkb/target"
)

// trustEmbeddedCAs makes every HTTPS call zpkb performs — version listings,
// source downloads, go-git clones — trust the Mozilla bundle artifact embeds,
// on top of the system store. A FROM-scratch builder image has NO system trust
// store, so without this zpkb cannot even list a version there:
//
//	versions: ls-remote https://github.com/lz4/lz4: tls: failed to verify
//	certificate: x509: certificate signed by unknown authority
//
// Setting it on the default transport covers the standard library clients and
// go-git alike, rather than threading a client through every call site.
func trustEmbeddedCAs() {
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return
	}
	tr = tr.Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: artifact.CertPool()}
	// HTTP/1.1 for the same reason artifact pulls use it: these are long,
	// single-stream transfers (a source tarball, or github's ref advertisement
	// for a repo the size of openssl's), and h2 flow control makes them stall —
	// `ls-remote https://github.com/openssl/openssl: context deadline exceeded`
	// from inside the builder, where every byte goes through this transport.
	tr.ForceAttemptHTTP2 = false
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	http.DefaultTransport = tr
	http.DefaultClient.Transport = tr
	// go-git does NOT go through http.DefaultTransport — it keeps its own
	// protocol client — so the version listing (`ls-remote` over smart HTTP)
	// needs the store installed separately, or it keeps failing on its own.
	client.InstallProtocol("https", githttp.NewClient(&http.Client{Transport: tr}))
}

var osExit = os.Exit

func main() {
	trustEmbeddedCAs()
	installWarnSink(os.Stderr)
	// Multi-call ("busybox-style") dispatch: zpkb is materialised into a build's
	// libexec dir as symlinks named after brewkit shims. When a recipe execs one
	// (e.g. `fix-shebangs.ts bin/*`), argv[0] is the symlink path, so its
	// basename selects the pure-Go helper — no shell interpreter is involved.
	switch filepath.Base(os.Args[0]) {
	case "fix-shebangs.ts":
		osExit(fixShebangs(os.Args[1:], os.Stderr))
		return
	case "zpkvenv":
		osExit(zpkvenv(os.Args[1:], os.Stderr))
		return
	case "python-venv.sh":
		osExit(pythonVenvSh(os.Args[1:], os.Stderr))
		return
	case "python-venv.py":
		osExit(pythonVenvPy(os.Args[1:], os.Stderr))
		return
	case "python-venv-stubber.sh":
		osExit(pythonVenvStubber(os.Args[1:], os.Stderr))
		return
	case "libtool":
		osExit(libtoolShim(os.Args[1:], os.Stderr))
		return
	}
	// The compiler shims, including the triple-prefixed spellings autoconf
	// reaches for first (`x86_64-pc-linux-gnu-gcc`). Matched by SUFFIX so one
	// case covers every triple rather than a list that has to be kept level
	// with the one in buildscript.
	if isCompilerShim(filepath.Base(os.Args[0])) {
		osExit(ccShim(filepath.Base(os.Args[0]), os.Args[1:], os.Stderr))
		return
	}
	osExit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// printVersion writes the one line both spellings produce.
//
// It prints exactly what bkVersion() returns — WITH the leading "v" — because
// that is the string zpkb writes into a lock's `bk = "…"` field. A prettier
// rendering here would make the two disagree, and the whole use of this
// command is reading a lock and asking "do I have that version?".
//
// ⛔ THE FIELD IS SPELLED `bk` AND MUST STAY THAT WAY. It is a published data
// format: every lock already written carries that key, and renaming it to
// match the command would make this tool unable to read its own output. The
// COMMAND was renamed; the field was not, and the two are different kinds of
// name. A sweep that replaced `bk` with `zpkb` everywhere would break every
// existing lock — which is why this says so here rather than leaving the next
// reader to guess.
//
// There is no -ldflags stamp. The siblings inject `-X main.version=<tag>`,
// which can be set to anything regardless of what was compiled; this reads
// debug.ReadBuildInfo, so it cannot disagree with the binary it is in.
func printVersion(w io.Writer) {
	// ⛔ THE BINARY SAYS ITS OWN NAME. The command is `zpkb` since the rename,
	// and `bk` is now free for upstream's brewkit to occupy on the same PATH
	// — which is what renaming ours was for. Measured: `zpkb --version`
	// answered `bk v0.59.0`.
	fmt.Fprintln(w, "zpkb", bkVersion())
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("zpkb", flag.ContinueOnError)
	fs.SetOutput(stderr)
	platform := fs.String("platform", "", "cross-build target, eg. windows/x86-64 (also ZPKB_TARGET)")
	version := fs.Bool("version", false, "print the version this zpkb writes into every lock")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// ⛔ BOTH SPELLINGS, BECAUSE NEITHER WORKED. Measured 2026-10-09, when the
	// binary was still called `bk` — ⚠ THE TRANSCRIPT BELOW IS VERBATIM AND
	// MUST NOT BE RENAMED. It is what was typed and what came back; rewriting
	// it to say `zpkb` would make the record describe a run that never
	// happened. The command is `zpkb` now, and the measurement is still from
	// the day it was not.
	//
	//	$ bk --version
	//	flag provided but not defined: -version
	//	$ bk version
	//	unknown command: version
	//
	// It could not say which build of itself it was, which matters more here
	// than in its siblings: it writes its own version into every lock it
	// produces (`bk = "v0.15.0"`), so "which build wrote this lock" was a
	// question only `go version -m` could answer, and only if you still had
	// the binary.
	//
	// The flag form is parsed BEFORE the empty-args check so that
	// `bk --version` on its own is not a usage error.
	if *version {
		printVersion(stdout)
		return 0
	}
	// ⛔⛔ BEFORE ANY SUBCOMMAND, because the failure it catches is SILENT and
	// every subcommand has it. The `pantry` environment variables were renamed
	// with the repository (go-zpkg/pantry-overlay is go-zpkg/recipes now); a
	// caller still exporting one does not fail, it builds WITHOUT what the
	// variable named — no overlay, no recipe checkout — and says nothing.
	//
	// Placed after --version on purpose: asking a binary which build it is must
	// work in any environment, including a broken one.
	if err := config.CheckRetiredEnv(nil); err != nil {
		fmt.Fprintf(stderr, "zpkb: %v\n", err)
		return 2
	}
	if *platform != "" {
		os.Setenv("ZPKB_TARGET", *platform)
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "usage: zpkb [--platform p] <version|buildenv|origin|target|fixup|versions|build|test|publish|publish-stage|closure|lock|tools|tohcl|lint|vulnid|advisories|vulnfetch|attest|overrides|depgaps|builder|factory|source|reproduce|sign> [args]")
		return 2
	}

	// The TARGET is resolved by the two subcommands that use one, not before
	// the switch. Resolving it here meant `zpkb lint`, `zpkb overrides` and
	// `zpkb tohcl` — none of which builds anything — refused to run on a
	// machine whose ZPKB_TARGET named a platform zpkb does not support:
	//
	//	error: unsupported target platform: "plan9"
	//
	// The factory SETS that variable, so a CI lane checking recipes beside a
	// build would inherit it.
	switch rest[0] {
	case "version":
		printVersion(stdout)
		return 0
	case "buildenv":
		return runBuildEnv(rest[1:], stdout, stderr)
	case "origin":
		return runOrigin(rest[1:], stdout, stderr)
	case "target":
		tgt, err := target.Resolve()
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		// Slug, so `zpkb target` names the libc when one was asked for. This is
		// the line an operator reads to find out what a run is about to build,
		// and it is the cheapest place for a wrong ZPKB_TARGET to be caught.
		fmt.Fprintf(stdout, "%s triple=%s cross=%v\n", tgt.Slug(), tgt.Triple, tgt.Cross())
		return 0
	case "fixup":
		if len(rest) < 2 {
			fmt.Fprintln(stderr, "usage: zpkb fixup <prefix>")
			return 2
		}
		tgt, err := target.Resolve()
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		err = fixup.FixUp(fixup.Options{
			Prefix:   rest[1],
			Platform: tgt.Platform,
			ZpkgDir:  config.ZpkgDir(),
			Log:      func(s string) { fmt.Fprintln(stdout, s) },
		})
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		return 0
	case "versions":
		return runVersions(rest[1:], stdout, stderr)
	case "build":
		return runBuild(rest[1:], stdout, stderr)
	case "test":
		return runTest(rest[1:], stdout, stderr)
	case "publish":
		return runPublish(rest[1:], stdout, stderr)
	case "publish-stage":
		return runPublishStage(rest[1:], stdout, stderr)
	case "closure":
		return runClosure(rest[1:], stdout, stderr)
	case "catalog":
		return runCatalog(rest[1:], stdout, stderr)
	case "runlog":
		return runRunlog(rest[1:], stdout, stderr)
	case "lock":
		return runLock(rest[1:], stdout, stderr)
	case "depgaps":
		return runDepgaps(rest[1:], stdout, stderr)
	case "depsplit":
		return runDepsplit(rest[1:], stdout, stderr)
	case "undeclared":
		return runUndeclared(rest[1:], stdout, stderr)
	case "unlinked":
		return runUnlinked(rest[1:], stdout, stderr)
	case "provides":
		return runProvides(rest[1:], stdout, stderr)
	case "unresolved":
		return runUnresolved(rest[1:], stdout, stderr)
	case "overrides":
		return runOverrides(rest[1:], stdout, stderr)
	case "lint":
		return runLint(rest[1:], stdout, stderr)
	case "vulnid":
		return runVulnID(rest[1:], stdout, stderr)
	case "advisories":
		return runAdvisories(rest[1:], stdout, stderr)
	case "vulnfetch":
		return runVulnFetch(rest[1:], stdout, stderr)
	case "eol":
		return runEOL(rest[1:], stdout, stderr)
	case "attest":
		return runAttest(rest[1:], stdout, stderr)
	case "tohcl":
		return runToHCL(rest[1:], stdout, stderr)
	case "tools":
		return runTools(rest[1:], stdout, stderr)
	case "sonames":
		return runSonames(rest[1:], stdout, stderr)
	case "bakedpaths":
		return runBakedPaths(rest[1:], stdout, stderr)
	case "weather":
		return runWeather(rest[1:], stdout, stderr)
	case "builder":
		return runBuilder(rest[1:], stdout, stderr)
	case "factory":
		return runFactory(rest[1:], stdout, stderr)
	case "source":
		return runSource(rest[1:], stdout, stderr)
	case "sourcepin":
		return runSourcePin(rest[1:], stdout, stderr)
	case "reproduce":
		return runReproduce(rest[1:], stdout, stderr)
	case "sign":
		return runSign(rest[1:], stdout, stderr)
	case "copy":
		return runCopy(rest[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "unknown command:", rest[0])
		return 2
	}
}
