// Command unbrick builds a device-specific blankflash by pairing a signed
// programmer harvested from a sibling device on the same SoC family with the
// target device's own stock boot chain.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"go-unbrick/internal/catalog"
)

// v holds global config, resolved from flags, env (UNBRICK_*), and an optional
// config file. Persistent flags (--catalog, --library) are bound to it.
var v = viper.New()

func catalogDir() string { return v.GetString("catalog") }
func libraryDir() string { return v.GetString("library") }

func activeCatalog() *catalog.Catalog {
	if c, err := catalog.Load(catalogDir()); err == nil {
		return c
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
	cobra.OnInitialize(func() {
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
	)
	return root
}
