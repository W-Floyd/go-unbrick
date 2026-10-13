package pmaports

import (
	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const gitlabTag = `# Maintainer: x
pkgname=linux-$_flavor
_flavor="postmarketos-qcom-sdm845"
pkgver=7.1_rc1
pkgdesc="Mainline Kernel fork for SDM845 devices"
url="https://gitlab.com/sdm845-mainline/linux"
_tag="sdm845-7.1-rc1-r0"
source="
	linux-$_tag.tar.gz::https://gitlab.com/sdm845-mainline/linux/-/archive/$_tag/linux-$_tag.tar.gz
	config-postmarketos-qcom-sdm845.aarch64
"
`

const githubURLVar = `pkgname=linux-postmarketos-qcom-msm8916
pkgdesc="Mainline kernel fork for Qualcomm MSM8909/MSM8916/MSM8939 devices"
url="https://github.com/msm8916-mainline/linux"
_tag=v${pkgver//_/-}-msm8916
source="
	$pkgname-$_tag.tar.gz::$url/archive/$_tag.tar.gz
	config-$_flavor.aarch64
"
`

const githubRepoVar = `_repository="linux"
pkgver=7.2
pkgname=linux-postmarketos-mediatek-mt6878
pkgdesc="Mainline Kernel fork for MT6878 devices"
_commit="12f2e9f040d0049f3f5ce5a7e53bf5ef27b46422"
source="
	$pkgname-$_commit.tar.gz::https://github.com/MT6878-mainline/$_repository/archive/$_commit.tar.gz
"
`

const kernelOrg = `pkgname=linux-postmarketos-qcom-sc7180
pkgdesc="Mainline kernel for Qualcomm Snapdragon 7c devices"
url="https://kernel.org"
source="https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.tar.xz config"
`

const urlBranch = `pkgname=linux-postmarketos-allwinner-d1
pkgdesc="Mainline kernel fork for d1/d1-h"
url="https://github.com/smaeul/linux/tree/riscv/d1-wip"
source="$pkgname.tar.gz::https://github.com/smaeul/linux/archive/refs/heads/riscv/d1-wip.tar.gz"
`

func TestRepository(t *testing.T) {
	for _, c := range []struct {
		name, text string
		want       Source
		ok         bool
	}{
		{"gitlab archive with a tag", gitlabTag, Source{URL: "https://gitlab.com/sdm845-mainline/linux", Pinned: "sdm845-7.1-rc1-r0"}, true},
		{"$url in the archive, a tag shell cannot expand here", githubURLVar, Source{URL: "https://github.com/msm8916-mainline/linux"}, true},
		{"$_repository and a pinned commit", githubRepoVar, Source{URL: "https://github.com/MT6878-mainline/linux", Pinned: "12f2e9f040d0049f3f5ce5a7e53bf5ef27b46422"}, true},
		{"kernel.org is mainline, not a fork", kernelOrg, Source{}, false},
		{"a url that names a branch", urlBranch, Source{URL: "https://github.com/smaeul/linux", Ref: "riscv/d1-wip"}, true},
	} {
		p := ParseAPKBUILD("linux-postmarketos-x", "testing", c.text)
		got, ok := p.Repository()
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got %+v %v, want %+v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestSoCs(t *testing.T) {
	for _, c := range []struct {
		name, desc string
		want       string
	}{
		{"linux-postmarketos-qcom-msm8916", "Mainline kernel fork for Qualcomm MSM8909/MSM8916/MSM8939 devices", "qcom,msm8909 qcom,msm8916 qcom,msm8939"},
		{"linux-postmarketos-qcom-sc7280", "Mainline Kernel fork for SC7280/SM7325/QCM6490 devices", "qcom,qcm6490 qcom,sc7280 qcom,sm7325"},
		{"linux-postmarketos-mediatek-mt6768", "Mainline Kernel fork for MT6768-based devices", "mediatek,mt6768"},
		{"linux-postmarketos-exynos850", "Mainline kernel fork for Exynos850", "samsung,exynos850"},
		{"linux-postmarketos-rockchip-rk3188", "Rockchip RK3188 kernel package", "rockchip,rk3188"},
		{"linux-postmarketos-lts", "LTS Kernel", ""},
		{"linux-postmarketos-omap", "Mainline kernel fork for OMAP devices", ""},
	} {
		got := strings.Join(Package{Name: c.name, Desc: c.desc}.SoCs(naming(t)), " ")
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestReposGroupsBySourceAndKeepsBranches(t *testing.T) {
	root := t.TempDir()
	write := func(category, pkg, text string) {
		dir := filepath.Join(root, "device", category, pkg)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "APKBUILD"), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("testing", "linux-postmarketos-qcom-sdm845", gitlabTag)
	write("testing", "linux-postmarketos-qcom-sc7180", kernelOrg)
	// One repository, two packages: a default-branch SoC and one on a branch.
	write("testing", "linux-postmarketos-qcom-msm8916", githubURLVar)
	write("archived", "linux-postmarketos-qcom-msm8939", strings.NewReplacer(
		"MSM8909/MSM8916/MSM8939", "MSM8939",
		`url="https://github.com/msm8916-mainline/linux"`, `url="https://github.com/msm8916-mainline/linux/tree/msm8939/next"`).Replace(githubURLVar))

	repos, skipped, err := Repos(root, "2026-10-13", naming(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 1 || skipped[0] != "linux-postmarketos-qcom-sc7180" {
		t.Errorf("skipped %v (a kernel.org package is mainline)", skipped)
	}
	byURL := map[string]int{}
	for i, rp := range repos {
		byURL[rp.URL] = i
	}
	m, ok := byURL["https://github.com/msm8916-mainline/linux"]
	if !ok || len(repos) != 2 {
		t.Fatalf("repos %+v", repos)
	}
	branches := repos[m].Branches
	if len(branches) != 2 {
		t.Fatalf("branches %+v: the default branch and msm8939/next are separate", branches)
	}
	var def, br = branches[0], branches[1]
	if def.Ref != "" {
		def, br = br, def
	}
	if strings.Join(def.SoCs, " ") != "qcom,msm8909 qcom,msm8916 qcom,msm8939" || br.Ref != "msm8939/next" || strings.Join(br.SoCs, " ") != "qcom,msm8939" {
		t.Errorf("default %+v, branch %+v", def, br)
	}
	if !strings.Contains(br.Notes, "archived") || def.Checked != "2026-10-13" {
		t.Errorf("notes/checked: %+v", br)
	}
	if _, _, err := Repos(t.TempDir(), "x", naming(t)); err == nil {
		t.Error("a directory with no pmaports packages is an error")
	}
}

// naming is the catalog's shipped vendor naming rules, so the data file is what
// is tested.
func naming(t *testing.T) map[string]catalog.SoCNaming {
	t.Helper()
	c, err := catalog.Load(filepath.Join("..", "..", "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	n := c.SoCNamings()
	if len(n) == 0 {
		t.Fatal("the catalog has no soc_naming")
	}
	return n
}

func TestPartRegexp(t *testing.T) {
	re := catalog.SoCNaming{Parts: []string{"msm[0-9]{4}", "sdm[0-9]{3}", "exynos ?[0-9]{3}"}}.PartRegexp()
	var got []string
	for _, s := range []string{"MSM8916 and msm8909 devices", "SDM845/SDM670", "Exynos850, Exynos 850", "msm89x7 qm215 sdm12345 xmsm8916"} {
		got = append(got, strings.Join(re.FindAllString(s, -1), "|"))
	}
	want := []string{"MSM8916|msm8909", "SDM845|SDM670", "Exynos850|Exynos 850", ""}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("case %d: got %q, want %q (a part is a whole word of its shape: msm89x7, sdm12345 and xmsm8916 are not)", i, got[i], want[i])
		}
	}
	if (catalog.SoCNaming{}).PartRegexp() != nil {
		t.Error("no patterns, no matcher")
	}
}
