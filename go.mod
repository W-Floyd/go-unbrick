module github.com/W-Floyd/go-unbrick

go 1.26.5

// Nokia/Microsoft-era Qualcomm attestation certs carry negative serials, which
// crypto/x509 otherwise refuses — losing the loader's whole secboot identity.
godebug x509negativeserial=1

require (
	charm.land/bubbles/v2 v2.2.1
	charm.land/bubbletea/v2 v2.1.0
	charm.land/lipgloss/v2 v2.0.6
	github.com/NurramoX/streakboard v0.1.0
	github.com/W-Floyd/erofs v0.8.1-0.20261012162035-00032a399f76
	github.com/W-Floyd/go-ext4 v0.0.0-20260927073552-3926e5ef3caf
	github.com/alecthomas/chroma/v2 v2.27.0
	github.com/anchore/go-lzo v0.1.0
	github.com/charmbracelet/x/ansi v0.11.9
	github.com/diskfs/go-diskfs v1.9.4
	github.com/electricbubble/gadb v0.1.0
	github.com/go-git/go-git/v5 v5.19.3
	github.com/kevinburke/ssh_config v1.2.0
	github.com/klauspost/compress v1.20.0
	github.com/pierrec/lz4/v4 v4.1.30
	github.com/pkg/sftp v1.13.11
	github.com/schollz/progressbar/v3 v3.19.1
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.21.0
	github.com/ulikunitz/xz v0.5.16
	go.yaml.in/yaml/v4 v4.0.0-rc.6
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.58.0
	golang.org/x/term v0.46.0
	golang.org/x/text v0.42.0
	google.golang.org/protobuf v1.36.12
)

require (
	dario.cat/mergo v1.0.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.6 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/harmonica v0.2.0 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20261008173134-6b8d4baf91b4 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/dlclark/regexp2/v2 v2.2.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.1 // indirect
	github.com/mattn/go-runewidth v0.0.30 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/pjbgf/sha1cd v0.7.0 // indirect
	github.com/sahilm/fuzzy v0.1.3 // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xo/terminfo v1.0.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
)

require (
	github.com/dsoprea/go-logging v0.0.0-20200710184922-b02d349568dd // indirect
	github.com/elliotwutingfeng/asciiset v0.0.0-20260129054604-cfde2086bc57 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-errors/errors v1.0.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/sys v0.48.0
)
