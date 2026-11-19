package fetch

import (
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

// Which bytes a detached signature was made over, for [SourcePin.Covers].
//
// ⛔⛔ THIS IS NOT A PREFERENCE, IT IS A FACT ABOUT THE PROJECT, AND THE AUTHOR
// HAS TO STATE IT. kernel.org signs the UNCOMPRESSED tar and says why on its
// own signature.html:
//
//	You will notice that the signature is made against the uncompressed
//	version of the archive. This is done so there is only one signature
//	required for .gz and .xz compressed versions of the release.
//
// Every one of its .sign files repeats it in the armour header, naming the
// exact bytes — `Comment: This signature is for the .tar version of the
// archive`. A recipe's distributable.url names the .tar.xz, so until this
// existed `sourcepin` hashed and verified those bytes and the two never
// matched: measured on linux-7.2.15, `d0f6b1d7…` served against `1ade1a3b…`
// signed, refused as `openpgp: invalid signature: RSA verification failure`
// with a good key and a good signature (go-zpkg/zpkb#492).
//
// ⛔ AND IT IS NOT INFERRED, WHICH THE ISSUE ASKED FOR AND IS WORTH RESTATING.
// Retrying over the decompressed stream whenever the served bytes fail would
// turn a refusal into a shrug: "it verified the other way" is indistinguishable
// from "somebody re-signed a different archive", and the whole value of this
// check is that a failure means something. The author says which, once, and the
// recipe records the answer.
const (
	// CoversServed is the signature over the bytes the URL served. It is what
	// almost every project signs, and the default everywhere.
	CoversServed = "served"
	// CoversDecompressed is the signature over the archive's decompressed
	// stream — the .tar inside a .tar.xz, .tar.gz or .tar.bz2.
	//
	// ⚠ THE DIGEST PINNED IS STILL THE COMPRESSED FILE'S, because that is what
	// a build downloads. This is one operation over two byte streams: verify
	// the contents, pin the file.
	CoversDecompressed = "decompressed"
)

// decompressor opens f as the plain stream a project signing its uncompressed
// tarball made its signature over. The format comes from the URL's extension,
// which [digestKept] has already checked against the file's own magic bytes —
// so there is one authority on what this file is, and it ran before this did.
//
// ⛔ MEMORY IS BOUNDED HERE; TIME IS NOT. Every decoder below streams: gzip's
// window is 32 KiB, bzip2's is 900 KiB, and xz's is capped by
// [maxXzDictionary], which [TestXzDeclaredDictionaryIsNotAllocated] holds to
// kilobytes against a stream declaring 1.5 GiB. Nothing is buffered, because
// the verifier only hashes. What a decompression bomb can still cost is wall
// clock, and that is accepted rather than capped: a total-bytes ceiling would
// be a number with no upstream meaning — the real tar is 1.69 GB for a 160 MB
// linux-7.2.15.tar.xz, a 10.5× ratio, and any cap that passes a real kernel
// passes most bombs. `sourcepin` is a tool an author runs on a URL they chose,
// never the factory, and ^C is available. Said here so the next reader knows
// the bound was weighed and named, not missed.
func decompressor(f *os.File, url string) (io.Reader, error) {
	switch kind := detect(url); kind {
	case kindTarGz:
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, undecompressible(url, "gzip", err)
		}
		return gz, nil
	case kindTarXz:
		xr, err := newXzReader(f)
		if err != nil {
			return nil, undecompressible(url, "xz", err)
		}
		return xr, nil
	case kindTarBz2:
		// compress/bzip2 has no eager constructor — NewReader always succeeds
		// and corruption surfaces mid-read. It arrives at the verifier as a
		// read error rather than a bad signature, which is the right shape:
		// CheckDetachedSignature reports what it could not read.
		return bzip2.NewReader(f), nil
	case "":
		return nil, fmt.Errorf("fetch: %s: this name does not say what archive format it is, "+
			"so there is no decompressor to choose — a signature over the decompressed "+
			"archive needs one", url)
	default:
		return nil, fmt.Errorf("fetch: %s is a %s, which is not a compressed stream: there is "+
			"nothing to decompress, so a signature over \"the decompressed archive\" cannot "+
			"exist for it — verify it over the bytes served instead", url, kind)
	}
}

// undecompressible says that the archive could not be decompressed, and says
// in the same breath that this is NOT the signature failing.
//
// ⛔ THE TWO READ IDENTICALLY OTHERWISE, AND THAT WAS WORTH A FUNCTION. The
// caller is a signature check; a `read xz` error surfacing from inside it looks
// like "the signature is bad" to anyone skimming, and the advice that follows a
// bad signature — do not pin this until you know who signed it — is the wrong
// advice for a truncated download.
func undecompressible(url, format string, err error) error {
	return fmt.Errorf("fetch: %s: read %s: %w — the signature was to be checked over the "+
		"DECOMPRESSED archive and the archive could not be decompressed, so this is a "+
		"broken or mis-served download and NOT a signature failure", url, format, err)
}
