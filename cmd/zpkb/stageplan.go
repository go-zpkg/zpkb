package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/moustache"
)

// The build/publish split.
//
// ⛔ THE PROCESS THAT RUNS RECIPE CODE MUST NOT HOLD THE KEYS. A recipe is a
// shell script from a third-party pantry, run with network access, as the same
// user as the factory. Anything in that process's environment is readable by
// it — the signing key and the registry token included. `zpkb factory
// --stage-only` builds and stages with neither; it writes everything a publish
// needs to publish-plan.json beside the artifacts, and `zpkb publish-stage`,
// which runs no recipe, signs and pushes from that plan.
//
// The plan is DATA FROM THE UNTRUSTED SIDE, so publish-stage re-derives what it
// can instead of believing it: the artifact's bytes against their recorded
// digest and size, the tag against the spec, the destination against --to. What
// it cannot re-derive (the source URI, the build environment) is what the build
// claims about itself, which is exactly what an unsigned `--no-publish` build
// always claimed — a hostile recipe can still lie in its own artifact and its
// own provenance, and signing happens after the fact. What it can no longer do
// is take the key or the token.
const (
	stagePlanName   = "publish-plan.json"
	stagePlanSchema = 1

	maxStagePlanBytes = 16 << 20
	maxStageEntries   = 20000
	maxStageArtifact  = 4 << 30
	maxStageExtras    = 256
	maxStageEnv       = 4096
	maxStageString    = 4096
	maxStageTime      = 4102444800 // 2100-01-01
)

type stageSource struct {
	URI    string        `json:"uri"`
	SHA256 string        `json:"sha256"`
	Commit string        `json:"commit"`
	Extra  []stageSource `json:"extra,omitempty"`
}

type stageDep struct {
	Project string `json:"project"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

type stageEntry struct {
	Project   string      `json:"project"`
	Version   string      `json:"version"`
	Tag       string      `json:"tag"`
	OS        string      `json:"os"`
	Arch      string      `json:"arch"`
	File      string      `json:"file"`
	SHA256    string      `json:"sha256"`
	Size      int64       `json:"size"`
	Glibc     string      `json:"glibc"`
	Spec      string      `json:"spec"`
	Source    stageSource `json:"source"`
	BuildEnv  []stageDep  `json:"build_env"`
	Bootstrap string      `json:"bootstrap"`
	// Sovereign is what the build measured about its own machine (see
	// sovereignClaim). Like Bootstrap it is the untrusted side's statement.
	Sovereign string `json:"sovereign,omitempty"`
}

type stagePlan struct {
	Schema    int          `json:"schema"`
	Dist      string       `json:"dist"`
	Platform  string       `json:"platform"`
	Builder   string       `json:"builder"`
	Time      int64        `json:"time"`
	Artifacts []stageEntry `json:"artifacts"`
}

var (
	reStageProject = regexp.MustCompile(`^[a-z0-9][a-z0-9._+/-]*$`)
	reStageVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]*$`)
	reStageGlibc   = regexp.MustCompile(`^[0-9][0-9.]*$`)
	reStageOS      = regexp.MustCompile(`^[a-z0-9]+$`)
	reStageArch    = regexp.MustCompile(`^[a-z0-9_-]+$`)
	reStageHex     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func cleanStageString(what, s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("%s: %d bytes, limit %d", what, len(s), max)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s: control character", what)
		}
	}
	return nil
}

func stageSourceOf(s build.SourceRef) stageSource {
	out := stageSource{URI: s.URI, SHA256: s.SHA256, Commit: s.Commit}
	for _, e := range s.Extra {
		out.Extra = append(out.Extra, stageSource{URI: e.URI, SHA256: e.SHA256, Commit: e.Commit})
	}
	return out
}

func (s stageSource) ref() build.SourceRef {
	out := build.SourceRef{URI: s.URI, SHA256: s.SHA256, Commit: s.Commit}
	for _, e := range s.Extra {
		out.Extra = append(out.Extra, build.SourceRef{URI: e.URI, SHA256: e.SHA256, Commit: e.Commit})
	}
	return out
}

func (s stageSource) validate(what string, nested bool) error {
	for _, f := range [...]struct{ n, v string }{{"uri", s.URI}, {"commit", s.Commit}} {
		if err := cleanStageString(what+" "+f.n, f.v, maxStageString); err != nil {
			return err
		}
	}
	if s.SHA256 != "" && !reStageHex.MatchString(s.SHA256) {
		return fmt.Errorf("%s: sha256 is not 64 lowercase hex digits", what)
	}
	if nested && len(s.Extra) > 0 {
		return fmt.Errorf("%s: nested extra sources", what)
	}
	if len(s.Extra) > maxStageExtras {
		return fmt.Errorf("%s: %d extra sources, limit %d", what, len(s.Extra), maxStageExtras)
	}
	for i, e := range s.Extra {
		if err := e.validate(fmt.Sprintf("%s extra[%d]", what, i), true); err != nil {
			return err
		}
	}
	return nil
}

func stageKey(e stageEntry) string {
	return e.Project + "\x00" + e.Tag + "\x00" + e.OS + "\x00" + e.Arch
}

// concrete rebuilds the entry's artifact.Concrete from its spec string,
// refusing a spec that does not round-trip: the string is what the tag's hash
// was derived from, so two spellings of one spec would be two addresses.
func (e stageEntry) concrete() (artifact.Concrete, error) {
	if e.Spec == "" {
		return artifact.Concrete{}, nil
	}
	c, err := artifact.UnmarshalSpec(e.Spec)
	if err != nil {
		return artifact.Concrete{}, fmt.Errorf("spec: %w", err)
	}
	if artifact.MarshalSpec(c) != e.Spec {
		return artifact.Concrete{}, errors.New("spec: not in canonical form")
	}
	return c, nil
}

func (e stageEntry) validate(plan *stagePlan) error {
	label := e.Project + " " + e.Version
	for _, f := range [...]struct {
		n, v string
		re   *regexp.Regexp
		max  int
		opt  bool
	}{
		{"project", e.Project, reStageProject, 200, false},
		{"version", e.Version, reStageVersion, 128, false},
		{"glibc", e.Glibc, reStageGlibc, 32, true},
		{"os", e.OS, reStageOS, 32, false},
		{"arch", e.Arch, reStageArch, 32, false},
	} {
		if err := cleanStageString(label+" "+f.n, f.v, f.max); err != nil {
			return err
		}
		if f.v == "" && f.opt {
			continue
		}
		if !f.re.MatchString(f.v) {
			return fmt.Errorf("%s: bad %s %q", label, f.n, f.v)
		}
	}
	if strings.Contains(e.Project, "..") {
		return fmt.Errorf("%s: bad project %q", label, e.Project)
	}
	if want := e.OS + "/" + e.Arch; want != plan.Platform {
		return fmt.Errorf("%s: platform %s, plan is for %s", label, want, plan.Platform)
	}
	if !reStageHex.MatchString(e.SHA256) {
		return fmt.Errorf("%s: sha256 is not 64 lowercase hex digits", label)
	}
	if e.Size < 0 || e.Size > maxStageArtifact {
		return fmt.Errorf("%s: size %d out of range", label, e.Size)
	}
	if err := cleanStageString(label+" file", e.File, 1024); err != nil {
		return err
	}
	if e.File == "" || !fs.ValidPath(e.File) || e.File == "." || strings.Contains(e.File, `\`) {
		return fmt.Errorf("%s: file %q is not a clean relative path", label, e.File)
	}
	if e.File == stagePlanName {
		return fmt.Errorf("%s: file names the plan itself", label)
	}
	switch {
	case strings.HasSuffix(e.File, ".tar.gz"), strings.HasSuffix(e.File, ".tar.xz"), strings.HasSuffix(e.File, ".tar.zst"):
	default:
		return fmt.Errorf("%s: file %q is not a .tar.gz, .tar.xz or .tar.zst", label, e.File)
	}
	if err := cleanStageString(label+" spec", e.Spec, maxStageString); err != nil {
		return err
	}
	c, err := e.concrete()
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if want := buildTag(e.Project, e.Version, e.Glibc, c); e.Tag != want {
		return fmt.Errorf("%s: tag %q is not the one its spec and glibc give (%q)", label, e.Tag, want)
	}
	if err := e.Source.validate(label+" source", false); err != nil {
		return err
	}
	if len(e.BuildEnv) > maxStageEnv {
		return fmt.Errorf("%s: %d build_env entries, limit %d", label, len(e.BuildEnv), maxStageEnv)
	}
	for i, d := range e.BuildEnv {
		for _, s := range [...]string{d.Project, d.Version, d.Path} {
			if err := cleanStageString(fmt.Sprintf("%s build_env[%d]", label, i), s, maxStageString); err != nil {
				return err
			}
		}
	}
	switch e.Bootstrap {
	case "", "0", "1":
	default:
		return fmt.Errorf("%s: bootstrap %q is not \"\", \"0\" or \"1\"", label, e.Bootstrap)
	}
	switch e.Sovereign {
	case "", "0", "1":
	default:
		return fmt.Errorf("%s: sovereign %q is not \"\", \"0\" or \"1\"", label, e.Sovereign)
	}
	return nil
}

// parseStagePlan is pure: bytes in, a validated plan or a refusal out.
func parseStagePlan(data []byte) (*stagePlan, error) {
	if len(data) > maxStagePlanBytes {
		return nil, fmt.Errorf("plan is %d bytes, limit %d", len(data), maxStagePlanBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p stagePlan
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("plan: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("plan: trailing data after the document")
	}
	if p.Schema != stagePlanSchema {
		return nil, fmt.Errorf("plan: schema %d, this zpkb reads %d", p.Schema, stagePlanSchema)
	}
	if err := cleanStageString("plan dist", p.Dist, maxStageString); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(p.Dist, "oci://") {
		return nil, fmt.Errorf("plan: dist %q is not an oci:// destination", p.Dist)
	}
	if err := cleanStageString("plan builder", p.Builder, maxStageString); err != nil {
		return nil, err
	}
	if err := cleanStageString("plan platform", p.Platform, 64); err != nil {
		return nil, err
	}
	if _, _, ok := splitPlatform(p.Platform); !ok {
		return nil, fmt.Errorf("plan: bad platform %q", p.Platform)
	}
	if p.Time < 0 || p.Time > maxStageTime {
		return nil, fmt.Errorf("plan: time %d out of range", p.Time)
	}
	if len(p.Artifacts) > maxStageEntries {
		return nil, fmt.Errorf("plan: %d artifacts, limit %d", len(p.Artifacts), maxStageEntries)
	}
	seen := make(map[string]bool, len(p.Artifacts))
	for _, e := range p.Artifacts {
		if err := e.validate(&p); err != nil {
			return nil, err
		}
		k := stageKey(e)
		if seen[k] {
			return nil, fmt.Errorf("plan: %s %s listed twice", e.Project, e.Tag)
		}
		seen[k] = true
	}
	return &p, nil
}

// loadStagePlan returns the plan already in dir, to be added to, or a new empty
// one. A plan this run cannot accept is an error and never overwritten.
func loadStagePlan(dir, dist, platform string, when time.Time) (*stagePlan, error) {
	fresh := &stagePlan{Schema: stagePlanSchema, Dist: dist, Platform: platform, Builder: builderWithVersion(), Time: when.Unix()}
	data, err := readCapped(filepath.Join(dir, stagePlanName), maxStagePlanBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return fresh, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stage plan: %w", err)
	}
	old, err := parseStagePlan(data)
	if err != nil {
		return nil, fmt.Errorf("existing %s is not one this run can extend: %w", stagePlanName, err)
	}
	if old.Dist != dist || old.Platform != platform || old.Time != fresh.Time {
		return nil, fmt.Errorf("existing %s is for %s on %s at %d, this run is for %s on %s at %d",
			stagePlanName, old.Dist, old.Platform, old.Time, dist, platform, fresh.Time)
	}
	old.Builder = fresh.Builder
	return old, nil
}

// The calls below are named so a test can make each one fail: none of them can
// be made to fail through the file system alone, and a guard nothing can reach
// is a guard nothing holds.
var (
	stageMarshal = json.MarshalIndent
	stageWrite   = func(f *os.File, b []byte) (int, error) { return f.Write(b) }
	stageClose   = func(f *os.File) error { return f.Close() }
	stageChmod   = os.Chmod
	stageStat    = func(f *os.File) (fs.FileInfo, error) { return f.Stat() }
	stageReadAll = func(f *os.File, limit int64) ([]byte, error) { return io.ReadAll(io.LimitReader(f, limit)) }
)

func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, nil
}

// writeStagePlan replaces the plan atomically, so a run killed mid-write leaves
// the previous plan and not half of one.
func writeStagePlan(dir string, p *stagePlan) error {
	if p.Artifacts == nil {
		p.Artifacts = []stageEntry{}
	}
	data, err := stageMarshal(p, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	// What is written must be what publish-stage will accept: a plan that only
	// this side can read is found out at publish time, after the build.
	if _, err := parseStagePlan(data); err != nil {
		return fmt.Errorf("refusing to write a plan publish-stage would refuse: %w", err)
	}
	// A run that built nothing (all skipped, all failed) has not created the
	// directory yet, and an empty plan is still the answer publish-stage reads.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, stagePlanName+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := stageWrite(tmp, data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := stageClose(tmp); err != nil {
		os.Remove(name)
		return err
	}
	if err := stageChmod(name, 0o644); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, filepath.Join(dir, stagePlanName)); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// addBuilt records one staged artifact, replacing an earlier entry for the same
// address (a re-run of the same build).
func (p *stagePlan) addBuilt(dir string, o publishOptions) error {
	rel, err := filepath.Rel(dir, o.Path)
	if err != nil {
		return err
	}
	rel = filepath.ToSlash(rel)
	sum, size, err := hashFile(o.Path)
	if err != nil {
		return err
	}
	e := stageEntry{
		Project: o.Project, Version: o.Version,
		Tag: buildTag(o.Project, o.Version, o.Glibc, o.Concrete),
		OS:  o.OS, Arch: o.Arch,
		File: rel, SHA256: sum, Size: size, Glibc: o.Glibc,
		Source:    stageSourceOf(o.Source),
		BuildEnv:  []stageDep{},
		Bootstrap: o.Origin.Bootstrap,
		Sovereign: o.Origin.Sovereign,
	}
	if !o.Concrete.IsZero() {
		e.Spec = artifact.MarshalSpec(o.Concrete)
	}
	for _, d := range o.BuildEnv {
		e.BuildEnv = append(e.BuildEnv, stageDep{Project: d.Project, Version: d.Version, Path: d.Path})
	}
	if err := e.validate(p); err != nil {
		return err
	}
	for i := range p.Artifacts {
		if stageKey(p.Artifacts[i]) == stageKey(e) {
			p.Artifacts[i] = e
			return nil
		}
	}
	p.Artifacts = append(p.Artifacts, e)
	return nil
}

// readStaged reads one staged artifact through root, so a path or a symlink in
// the plan cannot leave the stage directory, and checks it against the plan.
func readStaged(root *os.Root, e stageEntry) ([]byte, error) {
	f, err := root.Open(e.File)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := stageStat(f)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", e.File)
	}
	if st.Size() != e.Size {
		return nil, fmt.Errorf("%s is %d bytes, the plan says %d", e.File, st.Size(), e.Size)
	}
	b, err := stageReadAll(f, e.Size+1)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != e.Size {
		return nil, fmt.Errorf("%s changed size while being read", e.File)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != e.SHA256 {
		return nil, fmt.Errorf("%s does not match the plan's sha256", e.File)
	}
	return b, nil
}

// runPublishStage signs and pushes what `zpkb factory --stage-only` staged.
func runPublishStage(args []string, stdout, stderr io.Writer) int {
	dir := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir, args = args[0], args[1:]
	}
	f := flag.NewFlagSet("publish-stage", flag.ContinueOnError)
	f.SetOutput(stderr)
	to := f.String("to", "", "oci:// destination; REQUIRED and with no environment default, and it must be the one the plan was built for")
	signKey := f.String("sign", "", "go-attest/sign secret key file (else $SIGNING_KEY)")
	allowUnsigned := f.Bool("allow-unsigned", false, "publish without a signature. ⛔ A client verifies fail-closed by default, so an unsigned artifact is one nobody can install")
	advisories := f.String("advisories", envOr("ADVISORIES_DIR", ""), "advisory tree to attach an OpenVEX document from, as `zpkb factory --advisories`")
	if err := f.Parse(args); err != nil {
		return 2
	}
	if dir == "" && f.NArg() == 1 {
		dir = f.Arg(0)
	} else if f.NArg() != 0 {
		dir = ""
	}
	if dir == "" || *to == "" {
		fmt.Fprintln(stderr, "usage: zpkb publish-stage <stage-dir> --to oci://… [--sign key] [--advisories dir]")
		return 2
	}
	if !strings.HasPrefix(*to, "oci://") {
		fmt.Fprintf(stderr, "publish-stage: --to %q is not an oci:// destination\n", *to)
		return 2
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		fmt.Fprintln(stderr, "publish-stage:", err)
		return 1
	}
	defer root.Close()
	pf, err := root.Open(stagePlanName)
	if err != nil {
		fmt.Fprintln(stderr, "publish-stage:", err)
		return 1
	}
	data, err := io.ReadAll(io.LimitReader(pf, maxStagePlanBytes+1))
	pf.Close()
	if err != nil {
		fmt.Fprintln(stderr, "publish-stage:", err)
		return 1
	}
	plan, err := parseStagePlan(data)
	if err != nil {
		fmt.Fprintln(stderr, "publish-stage:", err)
		return 1
	}
	if plan.Dist != *to {
		fmt.Fprintf(stderr, "publish-stage: the plan was built for %s, not %s — refusing to publish somewhere it did not choose\n", plan.Dist, *to)
		return 1
	}
	if plan.Builder != builderWithVersion() {
		fmt.Fprintf(stderr, "publish-stage: warning: plan written by %s, this is %s\n", plan.Builder, builderWithVersion())
	}
	kp, err := factorySigningKey(*signKey)
	if err != nil {
		fmt.Fprintln(stderr, "publish-stage:", err)
		return 1
	}
	if kp == nil && !*allowUnsigned {
		fmt.Fprintln(stderr, "publish-stage: no signing key (--sign or $SIGNING_KEY); pass --allow-unsigned to publish without one")
		return 2
	}
	if *advisories != "" {
		if _, err := checkAdvisories(*advisories); err != nil {
			fmt.Fprintln(stderr, "publish-stage:", err)
			return 1
		}
	}
	// Everything is checked BEFORE anything is pushed: a stage that was tampered
	// with must refuse whole, not publish its first half.
	for _, e := range plan.Artifacts {
		if _, err := readStaged(root, e); err != nil {
			fmt.Fprintf(stderr, "publish-stage: %s %s: %v\n", e.Project, e.Tag, err)
			return 1
		}
	}
	when := time.Unix(plan.Time, 0).UTC()
	var pushed []published
	ok, failed := 0, 0
	for _, e := range plan.Artifacts {
		b, err := readStaged(root, e) // again: what is pushed is what is checked
		if err != nil {
			fmt.Fprintf(stderr, "publish-stage: %s %s: %v\n", e.Project, e.Tag, err)
			failed++
			continue
		}
		// parseStagePlan has already refused any entry whose spec does not round-trip
		// (validate calls concrete), and the same string cannot parse differently
		// a second time, so there is no error left to report here.
		c, _ := e.concrete()
		env := make([]moustache.Dep, 0, len(e.BuildEnv))
		for _, d := range e.BuildEnv {
			env = append(env, moustache.Dep{Project: d.Project, Version: d.Version, Path: d.Path})
		}
		tag, desc, err := factoryPublish(publishOptions{
			Dist: *to, Project: e.Project, Version: e.Version,
			OS: e.OS, Arch: e.Arch, Path: filepath.Join(dir, filepath.FromSlash(e.File)), Tarball: b,
			Glibc: e.Glibc, Key: kp, Time: when,
			Source: e.Source.ref(), BuildEnv: env,
			Advisories: *advisories,
			Origin:     provOrigin{Bootstrap: e.Bootstrap, Sovereign: e.Sovereign, Dist: *to},
			Concrete:   c,
		})
		if err != nil {
			fmt.Fprintf(stderr, "publish-stage: %s %s: publish: %v\n", e.Project, e.Tag, err)
			failed++
			continue
		}
		fmt.Fprintln(stdout, pushedLine(e.Project, tag, *to, desc, kp != nil))
		fmt.Fprintf(stdout, "✅ OK %s %s %s\n", e.Project, tag, plan.Platform)
		ok++
		pushed = append(pushed, published{project: e.Project, tag: tag, desc: desc})
	}
	if n := repairIndexes(*to, pushed, stdout, stderr); n > 0 {
		fmt.Fprintf(stdout, "=== %d index(es) repaired after a concurrent publisher dropped a platform ===\n", n)
	}
	fmt.Fprintf(stdout, "=== publish-stage (%s): %d published, %d failed ===\n", plan.Platform, ok, failed)
	if failed > 0 {
		return 1
	}
	return 0
}
