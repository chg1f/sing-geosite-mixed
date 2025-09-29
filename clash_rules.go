package main

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/go-github/v45/github"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

/*
> REF: https://clash.wiki/premium/rule-providers.html

#domain
payload:
  - '.blogger.com'
  - '*.*.microsoft.com'
  - 'books.itunes.apple.com'

#ipcidr
payload:
  - '192.168.1.0/24'
  - '10.0.0.0.1/32'

#classical
payload:
  - DOMAIN-SUFFIX,google.com
  - DOMAIN-KEYWORD,google
  - DOMAIN,ad.com
  - SRC-IP-CIDR,192.168.1.201/32
  - IP-CIDR,127.0.0.0/8
  - GEOIP,CN
  - DST-PORT,80
  - SRC-PORT,7777

> REF: https://clash.wiki/configuration/rules.html

- DOMAIN 域名
- DOMAIN-SUFFIX 域名后缀
- DOMAIN-KEYWORD 域名关键字
- GEOIP IP地理位置 (国家代码)
- IP-CIDR IPv4地址段
- IP-CIDR6 IPv6地址段
- SRC-IP-CIDR 源IP段地址
- SRC-PORT 源端口
- DST-PORT 目标端口
- PROCESS-NAME 源进程名
- PROCESS-PATH 源进程路径
- IPSET IP集
- RULE-SET 规则集
- SCRIPT 脚本
- MATCH 全匹配
*/
func generateClashRules(release *github.RepositoryRelease, names ...string) error {
	var eg errgroup.Group
	for index := range names {
		name := names[index]
		eg.Go(func() error {
			rawData, err := download(release, name)
			if err != nil {
				return err
			}
			var ruleProviders struct {
				Payload []string `yaml:"payload"`
			}
			if err := yaml.Unmarshal(rawData, &ruleProviders); err != nil {
				ruleProviders.Payload = strings.Split(string(rawData), "\n")
			}
			var headlessRule option.DefaultHeadlessRule
			for _, line := range ruleProviders.Payload {
				if strings.HasPrefix(line, "DOMAIN,") {
					headlessRule.Domain = append(headlessRule.Domain, line[7:])
				} else if strings.HasPrefix(line, "DOMAIN-SUFFIX,") {
					headlessRule.DomainSuffix = append(headlessRule.DomainSuffix, line[15:])
				} else if strings.HasPrefix(line, "DOMAIN-KEYWORD,") {
					headlessRule.DomainKeyword = append(headlessRule.DomainKeyword, line[15:])
				} else if strings.HasPrefix(line, "IP-CIDR,") {
					headlessRule.IPCIDR = append(headlessRule.IPCIDR, line[8:])
				} else if strings.HasPrefix(line, "IP-CIDR6,") {
					headlessRule.IPCIDR = append(headlessRule.IPCIDR, line[9:])
				} else if strings.HasPrefix(line, "SRC-IP-CIDR,") {
					headlessRule.SourceIPCIDR = append(headlessRule.SourceIPCIDR, line[11:])
				} else if strings.HasPrefix(line, "SRC-PORT,") {
					port, err := strconv.ParseUint(line[9:], 10, 16)
					if err != nil {
						log.Error("invalid port: " + line)
						continue
					}
					headlessRule.SourcePort = append(headlessRule.SourcePort, uint16(port))
				} else if strings.HasPrefix(line, "DST-PORT,") {
					port, err := strconv.ParseUint(line[9:], 10, 16)
					if err != nil {
						log.Error("invalid port: " + line)
						continue
					}
					headlessRule.Port = append(headlessRule.SourcePort, uint16(port))
				} else if strings.HasPrefix(line, "PROCESS-NAME,") {
					headlessRule.ProcessName = append(headlessRule.ProcessName, line[13:])
				} else if strings.HasPrefix(line, "PROCESS-PATH,") {
					headlessRule.ProcessPath = append(headlessRule.ProcessPath, line[13:])
				} else if strings.HasPrefix(line, "GEOIP,") ||
					strings.HasPrefix(line, "IPSET,") ||
					strings.HasPrefix(line, "RULE-SET,") ||
					strings.HasPrefix(line, "SCRIPT,") {
					log.Error("unsupported: " + line)
					continue
				} else {
					if strings.HasPrefix(line, "+.") {
						headlessRule.DomainSuffix = append(headlessRule.DomainSuffix, line[1:])
					} else if prefix, err := netip.ParsePrefix(line); err == nil {
						headlessRule.IPCIDR = append(headlessRule.IPCIDR, prefix.String())
					} else if addr, err := netip.ParseAddr(line); err == nil {
						headlessRule.IPCIDR = append(headlessRule.IPCIDR, addr.String())
					} else {
						headlessRule.Domain = append(headlessRule.Domain, line)
					}
				}
			}
			var plainRuleSet option.PlainRuleSet
			plainRuleSet.Rules = []option.HeadlessRule{
				{
					Type:           C.RuleTypeDefault,
					DefaultOptions: headlessRule,
				},
			}
			eg.Go(func() error {
				return generateSource(plainRuleSet, strings.TrimSuffix(name, ".txt"))
			})
			eg.Go(func() error {
				return generateBinary(plainRuleSet, strings.TrimSuffix(name, ".txt"))
			})
			return nil
		})
	}
	return eg.Wait()
}
