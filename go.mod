module go-unbrick

go 1.26.1

// Nokia/Microsoft-era Qualcomm attestation certs carry negative serials, which
// crypto/x509 otherwise refuses — losing the loader's whole secboot identity.
godebug x509negativeserial=1

require (
	github.com/Xe/erofs v0.8.0
	github.com/dsoprea/go-ext4 v0.0.0-20190528173430-c13b09fc0ff8
	github.com/electricbubble/gadb v0.1.0
	github.com/klauspost/compress v1.20.0
	github.com/pierrec/lz4/v4 v4.1.30
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
	github.com/dsoprea/go-logging v0.0.0-20200710184922-b02d349568dd // indirect
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
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/dsoprea/go-ext4 => github.com/W-Floyd/go-ext4 v0.0.0-20260920151443-568f8a2dfbfc

replace github.com/Xe/erofs => ./third_party/xe-erofs
