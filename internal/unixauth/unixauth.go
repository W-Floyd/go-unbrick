// Package unixauth reads /etc/passwd, /etc/shadow, /etc/gshadow and PPP secrets
// files (chap-secrets, pap-secrets) out of a rootfs: who has a usable password,
// what scheme protects it, and (via Fingerprint) whether two accounts share one,
// without the value itself ever needing to leave this package.
package unixauth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Scheme is the crypt algorithm a hash identifies itself as.
type Scheme string

const (
	SchemeNone     Scheme = "none"         // empty field: no password required
	SchemeLocked   Scheme = "locked"       // "*", "!", "!!", or "!"-prefixed: login disabled
	SchemeDES      Scheme = "des-crypt"    // traditional crypt(3): 13 chars, no $id$, ~weak
	SchemeMD5      Scheme = "md5-crypt"    // $1$
	SchemeBlowfish Scheme = "bcrypt"       // $2a$ $2b$ $2x$ $2y$
	SchemeSHA256   Scheme = "sha256-crypt" // $5$
	SchemeSHA512   Scheme = "sha512-crypt" // $6$
	SchemeYescrypt Scheme = "yescrypt"     // $y$
	SchemeScrypt   Scheme = "scrypt"       // $7$
	SchemeUnknown  Scheme = "unknown"
)

// Weak reports whether the scheme is fast enough to brute-force at scale: every
// scheme but a proper KDF with a cost factor (SHA-256/512 crypt, bcrypt, yescrypt,
// scrypt). DES crypt also truncates to 8 significant password characters.
func (s Scheme) Weak() bool {
	switch s {
	case SchemeDES, SchemeMD5:
		return true
	}
	return false
}

// ShadowEntry is one line of /etc/shadow (or /etc/gshadow, same shape).
type ShadowEntry struct {
	User    string
	Hash    string // the raw field, as stored — never printed by a report; see Fingerprint
	Scheme  Scheme
	LastChg string // field 3, days since epoch; kept as text since 0 and "" differ
}

// HasPassword reports whether Hash is a password a login could succeed against:
// not empty, and not one of the locked markers.
func (e ShadowEntry) HasPassword() bool {
	return e.Scheme != SchemeNone && e.Scheme != SchemeLocked
}

// Fingerprint is a short, one-way tag for comparing hashes without exposing them:
// two entries with the same Fingerprint hold the same stored value. "" for a hash
// that carries nothing to compare (empty or locked).
func (e ShadowEntry) Fingerprint() string {
	if !e.HasPassword() {
		return ""
	}
	sum := sha256.Sum256([]byte(e.Hash))
	return hex.EncodeToString(sum[:])[:12]
}

// classify names a shadow hash field's scheme.
func classify(hash string) Scheme {
	switch {
	case hash == "":
		return SchemeNone
	case hash == "*" || hash == "!" || hash == "!!" || hash == "x":
		return SchemeLocked
	case strings.HasPrefix(hash, "!"):
		// A locked account keeps its old hash behind a leading '!' so it can be
		// restored; what is behind it still identifies the scheme.
		if inner := classify(hash[1:]); inner != SchemeUnknown {
			return inner
		}
		return SchemeLocked
	case strings.HasPrefix(hash, "$1$"):
		return SchemeMD5
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2x$"), strings.HasPrefix(hash, "$2y$"):
		return SchemeBlowfish
	case strings.HasPrefix(hash, "$5$"):
		return SchemeSHA256
	case strings.HasPrefix(hash, "$6$"):
		return SchemeSHA512
	case strings.HasPrefix(hash, "$y$"):
		return SchemeYescrypt
	case strings.HasPrefix(hash, "$7$"):
		return SchemeScrypt
	case len(hash) == 13 && isCryptAlphabet(hash):
		return SchemeDES
	}
	return SchemeUnknown
}

// cryptAlphabet is what crypt(3)'s base64-like alphabet uses.
const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func isCryptAlphabet(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune(cryptAlphabet, r) {
			return false
		}
	}
	return true
}

// ParseShadow reads a shadow or gshadow file's entries. A malformed or comment
// line is skipped.
func ParseShadow(data []byte) []ShadowEntry {
	var out []ShadowEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 2 {
			continue
		}
		e := ShadowEntry{User: f[0], Hash: f[1]}
		e.Scheme = classify(e.Hash)
		if len(f) > 2 {
			e.LastChg = f[2]
		}
		out = append(out, e)
	}
	return out
}

// PasswdEntry is one line of /etc/passwd: who exists and what shell they get.
type PasswdEntry struct {
	User, Shell string
	UID, GID    int
}

// ParsePasswd reads a passwd file's entries.
func ParsePasswd(data []byte) []PasswdEntry {
	var out []PasswdEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		out = append(out, PasswdEntry{User: f[0], UID: uid, GID: gid, Shell: f[6]})
	}
	return out
}

// PPPSecret is one line of a chap-secrets or pap-secrets file: client, server,
// secret and the IP addresses it is valid from (secrets(5) format; "*" = any). A
// field double-quoted to hold whitespace is unquoted but not re-split: a secret
// containing a literal space is not pppd's common case and is not specially
// handled here.
type PPPSecret struct {
	Client, Server, Secret, IPs string
}

// Fingerprint compares a PPP secret's value without exposing it, as ShadowEntry does.
func (p PPPSecret) Fingerprint() string {
	if p.Secret == "" || p.Secret == "*" {
		return ""
	}
	sum := sha256.Sum256([]byte(p.Secret))
	return hex.EncodeToString(sum[:])[:12]
}

// ParsePPPSecrets reads a chap-secrets or pap-secrets file.
func ParsePPPSecrets(data []byte) []PPPSecret {
	var out []PPPSecret
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		p := PPPSecret{Client: unquote(f[0]), Server: unquote(f[1]), Secret: unquote(f[2])}
		if len(f) > 3 {
			p.IPs = f[3]
		}
		out = append(out, p)
	}
	return out
}

func unquote(s string) string { return strings.Trim(s, `"`) }

// Identify names a passwd/shadow/gshadow/chap-secrets/pap-secrets file for recon
// and browse: a type label, and report lines (one-line summary first) for a
// fuller report. ok is false unless the base name is exactly one of these —
// that alone is specific enough to claim it, even one with no entries (a stock
// pppd template, just its header comments). Never a hash or secret value, only
// Scheme and Fingerprint.
func Identify(name string, data []byte) (label string, lines []string, ok bool) {
	switch filepath.Base(name) {
	case "shadow", "gshadow":
		label = "shadow file"
		if filepath.Base(name) == "gshadow" {
			label = "group shadow file"
		}
		entries := ParseShadow(data)
		if len(entries) == 0 {
			return label, []string{"no accounts (empty or not parseable)"}, true
		}
		return label, shadowLines(entries), true
	case "passwd":
		entries := ParsePasswd(data)
		if len(entries) == 0 {
			return "passwd file", []string{"no accounts (empty or not parseable)"}, true
		}
		return "passwd file", []string{fmt.Sprintf("%d account(s)", len(entries))}, true
	case "chap-secrets", "pap-secrets":
		label = "PPP " + filepath.Base(name)
		secrets := ParsePPPSecrets(data)
		if len(secrets) == 0 {
			return label, []string{"no secrets configured (template only)"}, true
		}
		set := 0
		for _, s := range secrets {
			if s.Fingerprint() != "" {
				set++
			}
		}
		return label, []string{fmt.Sprintf("%d secret(s), %d set", len(secrets), set)}, true
	}
	return "", nil, false
}

// shadowLines is Identify's report body for a shadow/gshadow file: a one-line
// summary of who has a password and in what scheme, then one line per such
// account with its scheme and fingerprint (never the hash itself).
func shadowLines(entries []ShadowEntry) []string {
	var withPW []ShadowEntry
	seen := map[Scheme]bool{}
	var schemes []string
	for _, e := range entries {
		if !e.HasPassword() {
			continue
		}
		withPW = append(withPW, e)
		if !seen[e.Scheme] {
			seen[e.Scheme] = true
			s := string(e.Scheme)
			if e.Scheme.Weak() {
				s += " (weak)"
			}
			schemes = append(schemes, s)
		}
	}
	if len(withPW) == 0 {
		return []string{fmt.Sprintf("%d account(s), all locked or passwordless", len(entries))}
	}
	lines := []string{fmt.Sprintf("%d of %d account(s) have a password: %s", len(withPW), len(entries), strings.Join(schemes, ", "))}
	for _, e := range withPW {
		lines = append(lines, fmt.Sprintf("  %s: %s, fingerprint %s", e.User, e.Scheme, e.Fingerprint()))
	}
	return lines
}
