# sing-box-mixed

## Intro

- Fork from [@SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite) and replace to [@Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)
- Add [@Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)

## QuickStart

> ALL GENERATES: https://raw.githubusercontent.com/chg1f/sing-geosite-mixed/rule-set/.rule_set.txt

```json
{
  "dns": {
    "fakeip": {
      "enabled": true,
      "inet4_range": "198.18.0.0/15",
      "inet6_range": "fc00::/18"
    },
    "final": "adguard-doh",
    "independent_cache": true,
    "rules": [
      {
        "clash_mode": "Direct",
        "server": "direct-dns"
      }
    ],
    "servers": [
      {
        "address": "fakeip",
        "tag": "fakeip-dns"
      },
      {
        "address": "local",
        "detour": "direct-out",
        "tag": "direct-dns"
      },
      {
        "address": "8.8.4.4",
        "detour": "direct-out",
        "tag": "google-dns"
      },
      {
        "address": "quic://dns.adguard.com",
        "address_resolver": "google-dns",
        "detour": "proxy-out",
        "tag": "adguard-doh"
      },
      {
        "address": "https://1.1.1.1/dns-query",
        "address_resolver": "google-dns",
        "detour": "proxy-out",
        "tag": "cloudflare-doh"
      }
    ],
  },
  "experimental": {},
  "inbounds": [
    {
      "address": [
        "198.51.100.1/30",
        "fc01::ff01/126"
      ],
      "auto_route": true,
      "platform": {
        "http_proxy": {
          "enabled": true,
          "server": "127.0.0.1",
          "server_port": 7890
        }
      },
      "strict_route": true,
      "tag": "tun-in",
      "type": "tun"
    },
    {
      "listen": "127.0.0.1",
      "listen_port": 7890,
      "tag": "mixed-in",
      "type": "mixed"
    }
  ],
  "log": {
    "level": "trace",
    "output": "",
    "timestamp": true
  },
  "outbounds": [
    {
      "default": "proxy-out",
      "interrupt_exist_connections": true,
      "outbounds": [
        "proxy-out",
        "direct-out"
      ],
      "tag": "final-out",
      "type": "selector"
    },
    {
      "tag": "direct-out",
      "type": "direct"
    },
    {
      "default": "urltest-out",
      "interrupt_exist_connections": true,
      "outbounds": [
        "urltest-out",
        "direct-out",
        // ... other outbounds
      ],
      "tag": "proxy-out",
      "type": "selector"
    },
    {
      "idle_timeout": "30m",
      "interrupt_exist_connections": true,
      "interval": "30m",
      "outbounds": [
        "direct-out",
        // ... other outbounds
      ],
      "tag": "urltest-out",
      "type": "urltest",
      "url": "https://client3.google.com/generate_204"
    }
    // ... other outbounds
  ],
  "route": {
    "final": "final-out",
    "rule_set": [
      {
        "download_detour": "proxy-out",
        "format": "binary",
        "tag": "reject",
        "type": "remote",
        "update_interval": "1d",
        "url": "https://raw.githubusercontent.com/chg1f/sing-geosite-mixed/rule-set/reject.srs"
      },
      {
        "download_detour": "proxy-out",
        "format": "binary",
        "tag": "direct",
        "type": "remote",
        "update_interval": "1d",
        "url": "https://raw.githubusercontent.com/chg1f/sing-geosite-mixed/rule-set/direct.srs"
      },
      {
        "download_detour": "proxy-out",
        "format": "binary",
        "tag": "cncidr",
        "type": "remote",
        "update_interval": "1d",
        "url": "https://raw.githubusercontent.com/chg1f/sing-geosite-mixed/rule-set/cncidr.srs"
      },
      {
        "download_detour": "proxy-out",
        "format": "binary",
        "tag": "proxy",
        "type": "remote",
        "update_interval": "1d",
        "url": "https://raw.githubusercontent.com/chg1f/sing-geosite-mixed/rule-set/proxy.srs"
      },
      {
        "download_detour": "proxy-out",
        "format": "binary",
        "tag": "telegramcidr",
        "type": "remote",
        "update_interval": "1d",
        "url": "https://raw.githubusercontent.com/chg1f/sing-geosite-mixed/rule-set/telegramcidr.srs"
      }
    ],
    "rules": [
      {
        "action": "sniff"
      },
      {
        "action": "hijack-dns",
        "protocol": "dns"
      },
      {
        "ip_is_private": true,
        "outbound": "direct-out"
      },
      {
        "clash_mode": "Direct",
        "outbound": "direct-out"
      },
      {
        "clash_mode": "Global",
        "outbound": "proxy-out"
      },
      {
        "action": "reject",
        "method": "default",
        "rule_set": [
          "reject"
        ]
      },
      {
        "outbound": "direct-out",
        "rule_set": [
          "direct",
          "cncidr"
        ]
      },
      {
        "outbound": "proxy-out",
        "rule_set": [
          "proxy",
          "telegramcidr"
        ]
      }
    ]
  }
}
```
