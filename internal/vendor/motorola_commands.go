package vendor

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"go-unbrick/internal/catalog"
	"go-unbrick/internal/fastboot"
	"go-unbrick/internal/library"
)

// Motorola's contributed fastboot subcommands, stacked onto the neutral tree via
// the FastbootCommander seam. Command-layer services arrive through FastbootEnv;
// the vendor never imports the main package.

// motoUnlockPortal is where the token from `oem get_unlock_data` is redeemed.
const motoUnlockPortal = "https://motorola-global-portal.custhelp.com/app/standalone/bootloader/unlock-your-device-a"

func (m *motoFastboot) UnlockPortal() string { return motoUnlockPortal }

// UnlockOutlook predicts whether Motorola's portal will honour this device's CID,
// from its published allow-list and any subsidy lock harvested from firmware.
func (m *motoFastboot) UnlockOutlook(r *fastboot.DeviceRecon, cat *catalog.Catalog, lib *library.Library) string {
	if r.CarrierID == "" {
		return ""
	}
	slcf := lib.CarrierIDs()[library.NormalizeCID(r.CarrierID)]
	name := cat.CarrierIDName(m.Name(), r.CarrierID)

	because := ""
	switch {
	case slcf != "":
		because = fmt.Sprintf(", and it ships subsidy lock %s (carrier unit)", slcf)
	case name != "":
		because = fmt.Sprintf(" (%s)", name)
	}

	if eligible, known := cat.UnlockEligible(m.Name(), r.CarrierID); known {
		if eligible {
			return fmt.Sprintf("eligible: cid %s is on Motorola's unlock allow-list%s", r.CarrierID, because)
		}
		return fmt.Sprintf("expect refusal: cid %s is absent from Motorola's unlock allow-list%s", r.CarrierID, because)
	}

	switch {
	case slcf != "":
		return fmt.Sprintf("expect refusal: cid %s ships subsidy lock %s (carrier unit) — untested, try anyway", r.CarrierID, slcf)
	case strings.Contains(strings.ToLower(name), "subsidy"):
		return fmt.Sprintf("expect refusal: cid %s is a subsidy channel (%s) — untested, try anyway", r.CarrierID, name)
	case name != "":
		return fmt.Sprintf("no subsidy lock recorded for cid %s (%s); eligibility unknown until tried", r.CarrierID, name)
	default:
		return fmt.Sprintf("cid %s is uncatalogued; nothing here predicts eligibility", r.CarrierID)
	}
}

// FastbootCommands implements FastbootCommander: Motorola's extra fastboot
// subcommands.
func (motorola) FastbootCommands(env FastbootEnv) []*cobra.Command {
	return []*cobra.Command{motoUnlockDataCmd(env)}
}

// motoUnlockDataCmd surfaces `oem get_unlock_data` plus the portal and an
// eligibility outlook — a Motorola-branded command, so it lives here rather than
// in the neutral command tree.
func motoUnlockDataCmd(env FastbootEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "oem-unlock-data",
		Short: "retrieve Motorola OEM unlock token string for bootloader unlocking",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := env.Client()
			if err != nil {
				return err
			}
			serial, err := env.ResolveSerial(client)
			if err != nil {
				return err
			}
			if err := env.RequireBootloader(client, serial, "'oem get_unlock_data'"); err != nil {
				return err
			}
			prof := env.InstallProfile(client, serial)
			udp, ok := prof.(UnlockDataProvider)
			if !ok {
				return fmt.Errorf("this device's fastboot profile (%s) has no OEM unlock-data command", prof.Name())
			}
			data, err := udp.GetUnlockData(client, serial)
			if err != nil {
				return err
			}

			fmt.Println("Motorola OEM Unlock Data:")
			fmt.Println(data)
			fmt.Printf("\nPaste this token string into Motorola's Unlock Your Bootloader portal:\n  %s\n", udp.UnlockPortal())

			// Say up front whether the portal is likely to honour it, so a
			// refusal reads as the expected outcome rather than a failed step.
			if recon, err := client.GetVarAll(serial); err == nil {
				if recon.Unlocked {
					fmt.Println("\nNote: this device already reports an unlocked bootloader.")
				} else if outlook := udp.UnlockOutlook(recon, env.Catalog(), env.Library()); outlook != "" {
					fmt.Printf("\nOutlook: %s\n", outlook)
				}
			}
			return nil
		},
	}
}
