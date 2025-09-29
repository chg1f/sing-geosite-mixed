package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"github.com/google/go-github/v45/github"
)

var (
	gh  *github.Client
	cli = http.DefaultClient

	outputDir, _ = filepath.Abs("rule-set")
	generates    []string
)

func init() {
	transport := &github.BasicAuthTransport{
		Username: os.Getenv("ACCESS_TOKEN"),
	}
	gh = github.NewClient(transport.Client())
}

func getLatestRelease(from string) (*github.RepositoryRelease, error) {
	names := strings.SplitN(from, "/", 2)
	latestRelease, _, err := gh.Repositories.GetLatestRelease(context.Background(), names[0], names[1])
	if err != nil {
		return nil, err
	}
	return latestRelease, err
}

func fetch(uri *string) ([]byte, error) {
	log.Info("download ", *uri)
	response, err := http.Get(*uri)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func download(release *github.RepositoryRelease, assetName string) ([]byte, error) {
	asset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == assetName
	})
	if asset == nil {
		return nil, E.New(assetName+" not found in upstream release ", release.Name)
	}
	data, err := fetch(asset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	checksumAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == assetName+".sha256sum"
	})
	if checksumAsset != nil {
		remoteChecksum, err := fetch(checksumAsset.BrowserDownloadURL)
		if err != nil {
			return nil, err
		}
		checksum := sha256.Sum256(data)
		if hex.EncodeToString(checksum[:]) != string(remoteChecksum[:64]) {
			return nil, E.New("checksum mismatch")
		}
	}
	return data, nil
}

func generateSource(plainRuleSet option.PlainRuleSet, name string) error {
	bs, err := json.MarshalIndent(option.PlainRuleSetCompat{
		Version: 1,
		Options: plainRuleSet,
	}, "", "  ")
	if err != nil {
		return err
	}
	generates = append(generates, name+".json")
	return os.WriteFile(filepath.Join(outputDir, name+".json"), bs, 0o644)
}

func generateBinary(plainRuleSet option.PlainRuleSet, name string) error {
	output, err := os.Create(filepath.Join(outputDir, name+".srs"))
	if err != nil {
		return err
	}
	defer output.Close()
	err = srs.Write(output, plainRuleSet)
	if err != nil {
		return err
	}
	generates = append(generates, name+".srs")
	return nil
}

func setActionOutput(name string, content string) {
	os.Stdout.WriteString("::set-output name=" + name + "::" + content + "\n")
}

type ClashOption struct {
	Repo     string
	Asset    string
	SrsFile  string
	JsonFile string
}

func main() {
	os.RemoveAll(outputDir)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		log.Fatal(err)
	}

	eg, ctx := errgroup.WithContext(context.Background())

	opts := []ClashOption{
		{Repo: "Loyalsoldier/clash-rules", Asset: "apple.txt", SrsFile: "apple.srs", JsonFile: "apple.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "cncidr.txt", SrsFile: "cncidr.srs", JsonFile: "cncidr.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "gfw.txt", SrsFile: "gfw.srs", JsonFile: "gfw.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "greatfire.txt", SrsFile: "greatfire.srs", JsonFile: "greatfire.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "lancidr.txt", SrsFile: "lancidr.srs", JsonFile: "lancidr.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "proxy.txt", SrsFile: "proxy.srs", JsonFile: "proxy.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "telegramcidr.txt", SrsFile: "telegramcidr.srs", JsonFile: "telegramcidr.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "applications.txt", SrsFile: "applications.srs", JsonFile: "applications.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "direct.txt", SrsFile: "direct.srs", JsonFile: "direct.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "google.txt", SrsFile: "google.srs", JsonFile: "google.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "icloud.txt", SrsFile: "icloud.srs", JsonFile: "icloud.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "private.txt", SrsFile: "private.srs", JsonFile: "private.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "reject.txt", SrsFile: "reject.srs", JsonFile: "reject.json"},
		{Repo: "Loyalsoldier/clash-rules", Asset: "tld-not-cn.txt", SrsFile: "tld-not-cn.srs", JsonFile: "tld-not-cn.json"},
		// {Repo: "Loyalsoldier/v2ray-rules-dat", Asset: "geosite.db", SrsFile: "geosite.srs", JsonFile: "geosite.json"},
		// {Repo: "Loyalsoldier/v2ray-rules-dat", Asset: "geosite-cn", SrsFile: "geosite-cn.srs", JsonFile: "geosite-cn.json"},
	}

	for _, opt := range opts {
		repo, asset, srsFile, jsonFile := opt.Repo, opt.Asset, opt.SrsFile, opt.JsonFile
		eg.Go(func() error {
			bs, err := downloadRelease(ctx, repo, asset)
			if err != nil {
				return err
			}
			ruleSet, err := parseClashRuleProviders(bs)
			if err != nil {
				return err
			}
			if err := createSrsFile(ruleSet, srsFile); err != nil {
				return err
			}
			if err := createJsonFile(ruleSet, jsonFile); err != nil {
				return err
			}
			return nil
		})
	}

	eg.Go(func() error {
		sourceRelease, err := getLatestRelease("Loyalsoldier/clash-rules")
		if err != nil {
			return err
		}
		log.Warn("clash-rules from " + *sourceRelease.TagName)
		return generateClashRules(sourceRelease,
			"apple.txt",
			"cncidr.txt",
			"gfw.txt",
			"greatfire.txt",
			"lancidr.txt",
			"proxy.txt",
			"telegramcidr.txt",
			"applications.txt",
			"direct.txt",
			"google.txt",
			"icloud.txt",
			"private.txt",
			"reject.txt",
			"tld-not-cn.txt",
		)
	})
	eg.Go(func() error {
		sourceRelease, err := getLatestRelease("Loyalsoldier/v2ray-rules-dat")
		if err != nil {
			return err
		}
		log.Warn("v2ray-rules-dat from " + *sourceRelease.TagName)
		return generateV2rayRulesDat(sourceRelease,
			"geosite.db",
			"geosite-cn.db",
		)
	})
	if err := eg.Wait(); err != nil {
		log.Fatal(err)
	}
	sort.Strings(generates)
	os.WriteFile(filepath.Join(outputDir, ".rule_set.txt"), []byte(strings.Join(generates, "\n")), 0o644)
	setActionOutput("tag", time.Now().Format("20060102150405"))
}

func downloadRelease(ctx context.Context, repo, name string) ([]byte, error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repo %s", repo)
	}

	latest, _, err := gh.Repositories.GetLatestRelease(ctx, parts[0], parts[1])
	if err != nil {
		return nil, err
	}

	for i := range latest.Assets {
		if name == *latest.Assets[i].Name {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, *latest.Assets[i].BrowserDownloadURL, http.NoBody)
			if err != nil {
				return nil, err
			}
			resp, err := cli.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			return io.ReadAll(resp.Body)
		}
	}
	return nil, fmt.Errorf("asset %s not found in %s", name, repo)
}

func parseClashRuleProviders(bs []byte) (*option.PlainRuleSet, error) {
	var ruleProviders struct {
		Payload []string `yaml:"payload"`
	}
	if err := yaml.Unmarshal(bs, &ruleProviders); err != nil {
		return nil, err
	}
	var headlessRule option.DefaultHeadlessRule
	for _, line := range ruleProviders.Payload {
		switch {
		case strings.HasPrefix(line, "DOMAIN,"):
			headlessRule.Domain = append(headlessRule.Domain, line[7:])
		case strings.HasPrefix(line, "DOMAIN-SUFFIX,"):
			headlessRule.DomainSuffix = append(headlessRule.DomainSuffix, strings.TrimPrefix(line[14:], "."))
		case strings.HasPrefix(line, "DOMAIN-KEYWORD,"):
			headlessRule.DomainKeyword = append(headlessRule.DomainKeyword, line[15:])
		case strings.HasPrefix(line, "IP-CIDR,"):
			headlessRule.IPCIDR = append(headlessRule.IPCIDR, line[8:])
		case strings.HasPrefix(line, "IP-CIDR6,"):
			headlessRule.IPCIDR = append(headlessRule.IPCIDR, line[9:])
		case strings.HasPrefix(line, "SRC-IP-CIDR,"):
			headlessRule.SourceIPCIDR = append(headlessRule.SourceIPCIDR, line[11:])
		case strings.HasPrefix(line, "SRC-PORT,"):
			port, err := strconv.ParseUint(line[9:], 10, 16)
			if err != nil {
				continue
			}
			headlessRule.SourcePort = append(headlessRule.SourcePort, uint16(port))
		case strings.HasPrefix(line, "PROCESS-NAME,"):
			headlessRule.ProcessName = append(headlessRule.ProcessName, line[13:])
		case strings.HasPrefix(line, "PROCESS-PATH,"):
			headlessRule.ProcessPath = append(headlessRule.ProcessPath, line[13:])
		default:
			if strings.HasPrefix(line, "+.") {
				headlessRule.DomainSuffix = append(headlessRule.DomainSuffix, strings.TrimPrefix(line[1:], "."))
			} else if prefix, err := netip.ParsePrefix(line); err == nil {
				headlessRule.IPCIDR = append(headlessRule.IPCIDR, prefix.String())
			} else if addr, err := netip.ParseAddr(line); err == nil {
				headlessRule.IPCIDR = append(headlessRule.IPCIDR, addr.String())
			} else {
				headlessRule.Domain = append(headlessRule.Domain, line)
			}

		}
	}
	ruleSet := option.PlainRuleSet{
		Rules: []option.HeadlessRule{
			{
				Type:           constant.RuleTypeDefault,
				DefaultOptions: headlessRule,
			},
		},
	}
	return &ruleSet, nil
}

func createSrsFile(ruleSet *option.PlainRuleSet, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return srs.Write(f, *ruleSet)
}

func createJsonFile(ruleSet *option.PlainRuleSet, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(option.PlainRuleSetCompat{
		Version: 1,
		Options: *ruleSet,
	})
}
