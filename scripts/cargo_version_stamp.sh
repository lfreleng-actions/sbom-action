#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Tag-based versioning for the cyclonedx backend's Cargo path. A
# tag-versioned project keeps the placeholder version 0.0.0 in every
# workspace member's Cargo.toml and in Cargo.lock; the cargo_version
# input names the release. This rewrites one file in place.
#
# lfreleng-actions/rust-build-action and rust-crate-publish-action
# apply the same rewrite from the same shared specification (revision
# 3), and all three test it against the same vectors
# (tests/fixtures/version-stamp*/), so an SBOM names the crates those
# actions build and publish. The awk programs below are copied byte for
# byte from rust-crate-publish-action's scripts/version-stamp.sh, the
# specification's reference shell implementation; change them there
# first, and copy them back.
#
# Text processing alone: it runs no Cargo command and no project code.
#
# Usage:
#   cargo_version_stamp.sh manifest <version> <Cargo.toml>
#   cargo_version_stamp.sh lockfile <version> <Cargo.lock> <member>...
#   cargo_version_stamp.sh check <version>
#
# 'check' exits 0 when <version> is SemVer 2.0 without a leading 'v'.
# The rewrite writes through the existing file, keeping its mode, and
# prints the file's path when anything changed.

set -euo pipefail

readonly stamp_placeholder="0.0.0"
# SemVer 2.0, without a leading 'v'; a numeric pre-release identifier
# carries no leading zero.
readonly stamp_semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'

# Line endings: every line keeps exactly its own ending, CRLF, LF or
# none for a final line without a newline, and the rules match the
# line without it. This rule, put before both programs below, strips
# a CR ending from each record and notes it in 'cr'. The record that
# 'unterminated' numbers ends the file without a newline, so a CR
# there is content, not an ending.
# shellcheck disable=SC2016 # awk, not shell, expands these
readonly stamp_awk_line='
{ cr = (NR != unterminated && sub(/\r$/, "")) }'

# Print each record followed by its ending, adding the final newline
# only when the input ended with one, so no byte changes besides the
# version. Appended to both programs below.
readonly stamp_awk_emit='
function emit(line, cr) {
  printf "%s%s%s", (emitted++ ? "\n" : ""), line, (cr ? "\r" : "")
}
END { if (emitted && final_nl) printf "\n" }'

# Manifest rule: on every line, replace each match of
#   (^|[[:space:]{,])(version[[:space:]]*=[[:space:]]*"(=|\^|~)?)0\.0\.0"
# with \1\2<version>". A leading space stands in for '^', so one
# expression serves every match; it is removed again before printing.
# shellcheck disable=SC2016 # awk, not shell, expands these
readonly stamp_manifest_awk='
{
  rest = " " $0
  out = ""
  while (match(rest, /[[:space:]{,]version[[:space:]]*=[[:space:]]*"[=^~]?0\.0\.0"/)) {
    out = out substr(rest, 1, RSTART + RLENGTH - 7) version "\""
    rest = substr(rest, RSTART + RLENGTH)
  }
  emit(substr(out rest, 2), cr)
}'

# Lockfile rule: a section runs from one line starting with '[' to the
# next, so [[patch.unused]], [metadata] and any other header end a
# [[package]] section, and only [[package]] sections change. In one
# whose first name line names a workspace member, and which has no
# source line, each line reading exactly version = "0.0.0" takes the
# new version. On every line of every [[package]] section, so in a
# dependencies array on one line or several, an entry "<member> 0.0.0"
# does too. Nothing else changes.
# shellcheck disable=SC2016 # awk, not shell, expands these
readonly stamp_lock_awk='
BEGIN {
  count = split(members, list, " ")
  for (i = 1; i <= count; i++) member[list[i]] = 1
  held = 0
}
function deps(line,   i, from, to, out, at) {
  for (i = 1; i <= count; i++) {
    from = "\"" list[i] " " placeholder "\""
    to = "\"" list[i] " " version "\""
    out = ""
    while ((at = index(line, from)) > 0) {
      out = out substr(line, 1, at - 1) to
      line = substr(line, at + length(from))
    }
    line = out line
  }
  return line
}
function flush(   i, stamp) {
  stamp = in_block && named && (name in member) && !sourced
  for (i = 1; i <= held; i++) {
    if (stamp && buf[i] == "version = \"" placeholder "\"")
      buf[i] = "version = \"" version "\""
    emit(buf[i], buf_cr[i])
  }
  held = 0
  named = 0
  sourced = 0
}
/^\[/ {
  flush()
  in_block = ($0 == "[[package]]")
}
{
  line = $0
  if (in_block && !named && line ~ /^name = "[^"]*"$/) {
    name = substr(line, 9, length(line) - 9)
    named = 1
  }
  if (in_block && substr(line, 1, 9) == "source = ") sourced = 1
  if (in_block) line = deps(line)
  buf[++held] = line
  buf_cr[held] = cr
}
END { flush() }'

usage() {
  echo "usage: ${0##*/} manifest|lockfile <version> <file> [member...]" >&2
  echo "       ${0##*/} check <version>" >&2
  exit 2
}

[ "$#" -ge 2 ] || usage
mode="$1"
version="$2"
shift 2
if [ "$mode" = "check" ]; then
  [ "$#" -eq 0 ] || usage
  [[ "$version" =~ $stamp_semver_re ]]
  exit
fi
[ "$#" -ge 1 ] || usage
file="$1"
shift
case "$mode" in
  manifest)
    [ "$#" -eq 0 ] || usage
    program="$stamp_manifest_awk"
    ;;
  lockfile)
    [ "$#" -ge 1 ] || usage
    program="$stamp_lock_awk"
    set -- -v members="$*"
    ;;
  *) usage ;;
esac
if [[ ! "$version" =~ $stamp_semver_re ]]; then
  echo "${0##*/}: the version is not SemVer 2.0" >&2
  exit 1
fi
if [ ! -f "$file" ] || [ -L "$file" ]; then
  echo "${0##*/}: not a regular file" >&2
  exit 1
fi

# As the reference does: a file ending in a newline sets final_nl;
# otherwise the record after the last newline is the unterminated one,
# where a CR is content rather than a line ending.
final_nl=0
unterminated=0
if [ -z "$(tail -c 1 -- "$file")" ]; then
  final_nl=1
else
  unterminated=$(($(wc -l < "$file") + 1))
fi
tmp="$(mktemp "${TMPDIR:-/tmp}/cargo-version-stamp.XXXXXX")"
trap 'rm -f -- "$tmp"' EXIT
LC_ALL=C awk -v version="$version" -v final_nl="$final_nl" \
  -v unterminated="$unterminated" -v placeholder="$stamp_placeholder" \
  "$@" "$stamp_awk_line$program$stamp_awk_emit" "$file" > "$tmp"
if ! cmp -s -- "$tmp" "$file"; then
  cat -- "$tmp" > "$file"
  printf '%s\n' "$file"
fi
