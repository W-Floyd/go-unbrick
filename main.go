// Command unbrick builds a device-specific blankflash by pairing a signed
// programmer harvested from a sibling device on the same SoC family with the
// target device's own stock boot chain.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/internal/linuxdev"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// v holds global config, resolved from flags, env (UNBRICK_*), and an optional
// config file. Persistent flags (--catalog, --library) are bound to it.
var v = viper.New()

func catalogDir() string { return v.GetString("catalog") }
func libraryDir() string { return v.GetString("library") }

func activeCatalog() *catalog.Catalog {
	// Load("dir") glob-matches *.yaml under dir and succeeds with zero files
	// when dir doesn't exist relative to the cwd — the flag's default is the
	// relative "catalog", so running from anywhere but the repo root would
	// otherwise return an empty catalog instead of falling through to
	// Default()'s FindCatalogDir() search.
	dir := catalogDir()
	if files, _ := filepath.Glob(filepath.Join(dir, "*.yaml")); len(files) > 0 {
		if c, err := catalog.Load(dir); err == nil {
			return c
		}
	}
	c, _ := catalog.Default()
	return c
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "unbrick",
		Short:         "Build a device blankflash from a same-SoC sibling's signed loader",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().String("catalog", "catalog", "catalog directory (env UNBRICK_CATALOG)")
	root.PersistentFlags().String("library", "library", "library directory (env UNBRICK_LIBRARY)")

	// Config plumbing: flags < env < config file resolve through viper.
	v.SetEnvPrefix("UNBRICK")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	_ = v.BindPFlag("catalog", root.PersistentFlags().Lookup("catalog"))
	_ = v.BindPFlag("library", root.PersistentFlags().Lookup("library"))
	root.PersistentFlags().String("http-cache", "", "cache for http(s) inputs (env UNBRICK_HTTP_CACHE; default <user cache>/go-unbrick/http)")
	root.PersistentFlags().Bool("debug-http", false, "log every range request made for an http(s) input")
	_ = v.BindPFlag("http-cache", root.PersistentFlags().Lookup("http-cache"))
	_ = v.BindPFlag("debug-http", root.PersistentFlags().Lookup("debug-http"))
	var sshOpts linuxdev.Options
	root.PersistentFlags().StringVar(&sshOpts.Identity, "ssh-identity", "", "private key for ssh:// inputs (default: the agent, then ~/.ssh/id_*)")
	root.PersistentFlags().StringVar(&sshOpts.HostKeys, "ssh-host-keys", linuxdev.HostKeysStrict, "host-key policy for ssh:// inputs: strict, accept-new, off")
	root.PersistentFlags().StringVar(&sshOpts.KnownHosts, "ssh-known-hosts", "", "known_hosts file for ssh:// inputs (default ~/.ssh/known_hosts)")
	cobra.OnInitialize(func() {
		infile.SSHDial = func(target string) (*ssh.Client, error) { return linuxdev.DialSSH(target, sshOpts) }
		infile.CacheDir = v.GetString("http-cache")
		infile.Mirrors = vendor.Mirrors
		if v.GetBool("debug-http") {
			infile.Log = func(format string, args ...any) { fmt.Fprintf(os.Stderr, "[http] "+format+"\n", args...) }
		}
		v.SetConfigName(".unbrick")
		v.AddConfigPath(".")
		if home, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(home)
		}
		if err := v.ReadInConfig(); err != nil {
			if _, notFound := err.(viper.ConfigFileNotFoundError); !notFound {
				fmt.Fprintln(os.Stderr, "warning: config:", err)
			}
		}
	})

	root.AddCommand(
		newUnpackCmd(), newPackCmd(), newIngestCmd(),
		newHarvestCmd(), newForgeCmd(), newInspectCmd(),
		newCatalogCmd(), newLibraryCmd(), newDeriveCmd(),
		newStockCmd(), newEFICmd(), newDiffCmd(),
		newSafeguardCmd(), newFastbootCmd(),
		newEDLCmd(), newUnlockCmd(), newCIDCmd(), newSLCFCmd(),
		newReconCmd(), newSSHCmd(), newADBCmd(), newLsCmd(), newTreeCmd(), newExtractCmd(), newBrowseCmd(), newPortCmd(),
	)
	return root
}
