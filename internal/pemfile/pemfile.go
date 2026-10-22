// Package pemfile reads what a PEM file holds: public keys, certificates, and
// private keys (named, never printed), by the blocks in it.
package pemfile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/rsakey"
)

// Block is one PEM block, described.
type Block struct {
	Type   string   // the block's own type: "PUBLIC KEY", "CERTIFICATE", …
	Detail string   // one line: what it is
	Lines  []string // more, for a report
}

var begin = []byte("-----BEGIN ")

// Is reports whether head starts like a PEM file: optional blank lines or "Bag
// Attributes"-style header text are not accepted, only the armor line itself.
func Is(head []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(head, " \t\r\n"), begin)
}

// Parse describes every PEM block in data. ok is false when there is none.
func Parse(data []byte) (blocks []Block, ok bool) {
	if !Is(data) {
		return nil, false
	}
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		blocks = append(blocks, describe(b))
	}
	return blocks, len(blocks) > 0
}

func describe(b *pem.Block) Block {
	out := Block{Type: b.Type}
	switch b.Type {
	case "PUBLIC KEY", "RSA PUBLIC KEY":
		pub := publicKey(b)
		out.Detail, out.Lines = describePublic("public key", pub)
	case "CERTIFICATE", "TRUSTED CERTIFICATE":
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			out.Detail = "certificate (does not parse: " + err.Error() + ")"
			break
		}
		kind, lines := describePublic("", c.PublicKey)
		out.Detail = fmt.Sprintf("certificate for %s — %s", subject(c), kind)
		out.Lines = append([]string{
			"subject: " + c.Subject.String(),
			"issuer:  " + c.Issuer.String(),
			fmt.Sprintf("valid:   %s to %s", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02")),
		}, lines...)
		if c.Subject.String() == c.Issuer.String() {
			out.Lines = append(out.Lines, "self-signed")
		}
	case "RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		out.Detail, out.Lines = describePrivate(b)
	default:
		out.Detail = strings.ToLower(b.Type)
	}
	return out
}

func publicKey(b *pem.Block) any {
	if b.Type == "RSA PUBLIC KEY" {
		if k, err := x509.ParsePKCS1PublicKey(b.Bytes); err == nil {
			return k
		}
		return nil
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil
	}
	return k
}

// describePublic names a public key; lead is a word for it ("public key") or "".
func describePublic(lead string, pub any) (string, []string) {
	var what string
	var lines []string
	switch k := pub.(type) {
	case *rsa.PublicKey:
		what = fmt.Sprintf("RSA-%d e=%d", k.N.BitLen(), k.E)
		lines = []string{"SPKI sha256 " + rsakey.Fingerprint(k), fmt.Sprintf("modulus %x…", k.N.Bytes()[:min(8, len(k.N.Bytes()))])}
	case *ecdsa.PublicKey:
		what = "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		what = "Ed25519"
	default:
		what = "key (unreadable)"
	}
	if lead != "" {
		what = lead + ": " + what
	}
	if len(lines) > 0 {
		short := lines[0][len("SPKI sha256 "):]
		what += " sha256:" + short[:12] + "…"
	}
	return what, lines
}

// describePrivate names a private key without printing any of it: its type and,
// for RSA, the public half's fingerprint to match against.
func describePrivate(b *pem.Block) (string, []string) {
	if b.Type == "ENCRYPTED PRIVATE KEY" || x509.IsEncryptedPEMBlock(b) { //nolint:staticcheck
		return "private key (encrypted)", nil
	}
	var key any
	switch b.Type {
	case "RSA PRIVATE KEY":
		if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
			key = k
		}
	case "EC PRIVATE KEY":
		if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
			key = k
		}
	default:
		if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
			key = k
		}
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		what, lines := describePublic("", &k.PublicKey)
		return "private key: " + what, lines
	case *ecdsa.PrivateKey:
		return "private key: ECDSA " + k.Curve.Params().Name, nil
	case ed25519.PrivateKey:
		return "private key: Ed25519", nil
	}
	return "private key", nil
}

// subject is a certificate's common name, or its whole subject if it has none.
func subject(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

// Label names the file by its blocks: "PEM public key", "PEM certificate", or the
// count for a bundle.
func Label(blocks []Block) string {
	if len(blocks) != 1 {
		return fmt.Sprintf("PEM bundle (%d blocks)", len(blocks))
	}
	switch t := blocks[0].Type; {
	case strings.Contains(t, "PRIVATE KEY"):
		return "PEM private key"
	case strings.Contains(t, "PUBLIC KEY"):
		return "PEM public key"
	case strings.Contains(t, "CERTIFICATE"):
		return "PEM certificate"
	default:
		return "PEM " + strings.ToLower(t)
	}
}
