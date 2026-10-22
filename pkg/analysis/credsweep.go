package analysis

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/unixauth"
)

// Finding every /etc/shadow, /etc/gshadow and PPP secrets file under an input, and
// reporting what is interesting across all of them together: which accounts have a
// usable password, how weak the scheme is, and — the finding that one file alone
// cannot show — which hashes or secrets are identical across more than one file
// (a fleet-wide fixed credential, not a per-device one). Never the value itself:
// comparison is by ShadowEntry/PPPSecret.Fingerprint, a one-way tag.

// credFiles are the base names this sweep opens and parses.
var credFiles = map[string]bool{
	"shadow": true, "gshadow": true, "passwd": true,
	"chap-secrets": true, "pap-secrets": true,
}

// CredAccount is one account's password, at one path.
type CredAccount struct {
	Path        string // from the input's root, through nested containers
	User        string
	Scheme      unixauth.Scheme
	Fingerprint string // "" when there is nothing to compare (no password, locked)
}

// CredSecret is one PPP secret, at one path.
type CredSecret struct {
	Path                string
	File                string // "chap-secrets" or "pap-secrets"
	Client, Server, IPs string
	Fingerprint         string
}

// CredSweepResult is every account and PPP secret found, plus the groups that
// share a fingerprint across more than one path.
type CredSweepResult struct {
	Accounts []CredAccount
	Secrets  []CredSecret
	// Shared groups a fingerprint (account or secret) found at more than one path,
	// keyed by that fingerprint.
	SharedAccounts map[string][]CredAccount
	SharedSecrets  map[string][]CredSecret
	Files          int
	Unreadable     []string
}

// CredSweepOptions is what to leave out.
type CredSweepOptions struct {
	// Skip leaves out paths matching any of these regular expressions; see SkipPath.
	Skip []string
	// Depth is how many container levels to open. Default: unlimited.
	Depth int
}

// SweepCreds walks input (a file, package, image or directory, local or ssh://,
// through nested containers and decrypted members — a host loads the secrets that
// decrypt first, as for SweepKeys) for passwd/shadow/gshadow/chap-secrets/pap-secrets
// files, parses each, and groups what is shared across more than one of them.
func SweepCreds(ctx context.Context, input string, opt CredSweepOptions) (*CredSweepResult, error) {
	root, err := diffRoot(input)
	if err != nil {
		return nil, err
	}
	depth := opt.Depth
	if depth <= 0 {
		depth = 1 << 20
	}
	c := &credSweeper{ctx: ctx, opt: opt, res: &CredSweepResult{}}
	c.walk(root, "", depth)
	c.group()
	if err := ctx.Err(); err != nil {
		return c.res, err
	}
	return c.res, nil
}

type credSweeper struct {
	ctx context.Context
	opt CredSweepOptions
	res *CredSweepResult
}

func (c *credSweeper) walk(n *carve.Node, p string, depth int) {
	if c.ctx.Err() != nil {
		return
	}
	if n.IsDirNode() {
		_, kids, err := n.Children()
		if err != nil {
			c.res.Unreadable = append(c.res.Unreadable, p+": "+err.Error())
			return
		}
		for _, k := range kids {
			cp := p + "/" + k.Name
			if !SkipPath(c.opt.Skip, cp) {
				c.walk(k, cp, depth)
			}
		}
		return
	}
	base := path.Base(p)
	if credFiles[base] {
		c.parse(n, strings.TrimPrefix(p, "/"), base)
		return // a credentials file is never itself a container worth opening
	}
	if depth <= 0 {
		return
	}
	if _, isContainer := carve.Format(n); !isContainer {
		return
	}
	_, kids, err := n.Children()
	if err != nil {
		return // not readable as the container it looks like: nothing of interest extractable
	}
	for _, k := range kids {
		cp := p + "/" + k.Name
		if !SkipPath(c.opt.Skip, cp) {
			c.walk(k, cp, depth-1)
		}
	}
}

func (c *credSweeper) parse(n *carve.Node, path, base string) {
	data, err := n.Bytes()
	if err != nil {
		c.res.Unreadable = append(c.res.Unreadable, path+": "+err.Error())
		return
	}
	c.res.Files++
	switch base {
	case "shadow", "gshadow":
		for _, e := range unixauth.ParseShadow(data) {
			c.res.Accounts = append(c.res.Accounts, CredAccount{Path: path, User: e.User, Scheme: e.Scheme, Fingerprint: e.Fingerprint()})
		}
	case "passwd":
		// passwd itself carries no secret, but an account with a password hash
		// in shadow that this file's own line marks disabled is worth knowing;
		// kept simple here and left to a caller that wants the shell field.
	case "chap-secrets", "pap-secrets":
		for _, s := range unixauth.ParsePPPSecrets(data) {
			c.res.Secrets = append(c.res.Secrets, CredSecret{Path: path, File: base, Client: s.Client, Server: s.Server, IPs: s.IPs, Fingerprint: s.Fingerprint()})
		}
	}
}

func (c *credSweeper) group() {
	byFP := map[string][]CredAccount{}
	for _, a := range c.res.Accounts {
		if a.Fingerprint != "" {
			byFP[a.Fingerprint] = append(byFP[a.Fingerprint], a)
		}
	}
	c.res.SharedAccounts = map[string][]CredAccount{}
	for fp, as := range byFP {
		if len(as) > 1 {
			c.res.SharedAccounts[fp] = as
		}
	}
	bySec := map[string][]CredSecret{}
	for _, s := range c.res.Secrets {
		if s.Fingerprint != "" {
			bySec[s.Fingerprint] = append(bySec[s.Fingerprint], s)
		}
	}
	c.res.SharedSecrets = map[string][]CredSecret{}
	for fp, ss := range bySec {
		if len(ss) > 1 {
			c.res.SharedSecrets[fp] = ss
		}
	}
}

// Summary is a short, redacted report: counts, weak/shared findings, never a
// hash or secret value.
func (r *CredSweepResult) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d credential file(s) read\n", r.Files)
	var withPW []CredAccount
	for _, a := range r.Accounts {
		if a.Scheme != unixauth.SchemeNone && a.Scheme != unixauth.SchemeLocked {
			withPW = append(withPW, a)
		}
	}
	sort.Slice(withPW, func(i, j int) bool { return withPW[i].Path < withPW[j].Path })
	for _, a := range withPW {
		weak := ""
		if a.Scheme.Weak() {
			weak = " (weak)"
		}
		fmt.Fprintf(&b, "  %s: %s has a password, %s%s\n", a.Path, a.User, a.Scheme, weak)
	}
	if len(r.SharedAccounts) == 0 && len(r.SharedSecrets) == 0 {
		return b.String()
	}
	fmt.Fprintln(&b, "shared across more than one file (same stored value, not shown):")
	var fps []string
	for fp := range r.SharedAccounts {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	for _, fp := range fps {
		as := r.SharedAccounts[fp]
		var paths []string
		for _, a := range as {
			paths = append(paths, fmt.Sprintf("%s (%s)", a.Path, a.User))
		}
		sort.Strings(paths)
		fmt.Fprintf(&b, "  account %s: %s\n", fp, strings.Join(paths, ", "))
	}
	fps = fps[:0]
	for fp := range r.SharedSecrets {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	for _, fp := range fps {
		ss := r.SharedSecrets[fp]
		var paths []string
		for _, s := range ss {
			paths = append(paths, fmt.Sprintf("%s (%s)", s.Path, s.Client))
		}
		sort.Strings(paths)
		fmt.Fprintf(&b, "  PPP secret %s: %s\n", fp, strings.Join(paths, ", "))
	}
	return b.String()
}
