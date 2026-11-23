package buildscript

import (
	"fmt"
	"strings"
)

// onlyVersionBody is the shell function behind onlyVersionScript, kept as one
// constant so a test can run exactly the text a test script carries.
//
// Arguments: $1 the project (`lz4.org`), $2 the prefix of the build under test.
//
// It uses nothing but POSIX `case`, `for` and the ${!var} indirection that bash
// and mvdan.cc/sh share, and it never fails under `set -e`: every conditional is
// an `if`, so a missing directory is not an abort.
const onlyVersionBody = `__zpkb_only_version() {
  __ov_dropped=""
  __ov_ifs="$IFS"
  set -f
  for __ov_var in PATH LD_LIBRARY_PATH LIBRARY_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH PKG_CONFIG_PATH CMAKE_PREFIX_PATH XDG_DATA_DIRS ACLOCAL_PATH; do
    __ov_val="${!__ov_var}"
    if [ -z "$__ov_val" ]; then continue; fi
    __ov_kept=""
    IFS=:
    for __ov_d in $__ov_val; do
      case "$__ov_d" in
        "$2"|"$2"/*) __ov_kept="${__ov_kept:+$__ov_kept:}$__ov_d" ;;
        */"$1"/v*)
          case " $__ov_dropped " in
            *" $__ov_d "*) ;;
            *) __ov_dropped="${__ov_dropped:+$__ov_dropped }$__ov_d" ;;
          esac ;;
        *) __ov_kept="${__ov_kept:+$__ov_kept:}$__ov_d" ;;
      esac
    done
    IFS="$__ov_ifs"
    if [ -n "$__ov_kept" ]; then export "$__ov_var=$__ov_kept"; else unset "$__ov_var"; fi
  done
  set +f
  IFS="$__ov_ifs"
  for __ov_pair in CPATH:include LIBRARY_PATH:lib LIBRARY_PATH:lib64 PKG_CONFIG_PATH:lib/pkgconfig PKG_CONFIG_PATH:lib64/pkgconfig PKG_CONFIG_PATH:share/pkgconfig; do
    __ov_var="${__ov_pair%%:*}"
    __ov_dir="$2/${__ov_pair#*:}"
    if [ -d "$__ov_dir" ]; then
      __ov_val="${!__ov_var}"
      export "$__ov_var=$__ov_dir${__ov_val:+:$__ov_val}"
    fi
  done
  if [ -n "$__ov_dropped" ]; then
    echo "zpkb: test environment: $1 is the build under test ($2); other versions of it were taken off every search path: $__ov_dropped" >&2
  fi
  unset __ov_dropped __ov_ifs __ov_var __ov_val __ov_kept __ov_d __ov_pair __ov_dir
}
`

// onlyVersionScript makes the package under test the ONLY version of its
// project on the environment's search paths.
//
// ⛔ THE ENVIRONMENT CAN HOLD TWO VERSIONS OF THE PROJECT UNDER TEST. Measured on
// smoke run 45085969313: the staged lz4.org 1.11.1 ran its own test and printed
// `header 11000 but library 11101`. The header was another version's — the test
// environment's closure (the compiler and its libraries) carries an older
// lz4.org, whose include directory sits on CPATH, while the build under test
// reached the loader through LD_LIBRARY_PATH alone. A compile-and-link test then
// compiled against one version and linked against the other, which says nothing
// about the artifact.
//
// So after the eval, every search-path entry that lies under another version
// directory of this project (`…/<project>/v…`, other than the prefix under test)
// is removed, the prefix's own include, lib and pkg-config directories are put
// FIRST, and what was removed is said on stderr: a dependency that really needs a
// different version at runtime is reported, not mixed in silently.
func onlyVersionScript(project, prefix string) string {
	return onlyVersionBody + fmt.Sprintf("__zpkb_only_version %s %s\n", shQuote(project), shQuote(prefix))
}

// shQuote single-quotes s for a shell.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
