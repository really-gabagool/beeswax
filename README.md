<div align="center">

# 🐝 beeswax

**Real credentials that real bots threw at real honeypots.**

Usernames and passwords captured from internet-facing SSH/Telnet honeypots, cleaned up and published as plain wordlists.

![source](https://img.shields.io/badge/source-Cowrie%20honeypots-222?style=flat-square)
![license](https://img.shields.io/badge/license-CC%20BY%204.0-222?style=flat-square)

</div>

---

## What is this?

Every exposed SSH or Telnet port gets hammered around the clock by botnets guessing logins. I run [Cowrie](https://github.com/cowrie/cowrie) and various other honeypots that let them try, and this repo holds what they tried.

These aren't leaked passwords and they aren't made up. They're the dictionaries attackers are using **right now**, as observed on the wire. That makes them useful for:

- **Defenders** auditing their own systems and password-block policies against what bots actually try first
- **Researchers** tracking how attacker wordlists shift over time
- **Honeypot operators** comparing against their own sensors
- **Tool authors** who need a realistic, current corpus

> Beeswax is what the hive builds the honeycomb from. If you analyze honeypot logs, see also **[HONEYCOMB](https://github.com/really-gabagool)**.

## Contents

| File | Entries | Description |
|---|---:|---|
| [`captured_passwords.txt`](captured_passwords.txt) | 35,584 | Every unique password attempted |
| [`captured_usernames.txt`](captured_usernames.txt) | 995 | Every unique username attempted |

- One entry per line, **UTF-8**, **LF** line endings, no duplicates
- Ordered by how often each entry was tried, so the top of each file is what bots reach for first
- Non-English entries (Cyrillic, Arabic, Korean, Chinese) are kept as real UTF-8 text, not escaped bytes
- Suspected canaries removed

## Collection

| | |
|---|---|
| **Sensors** | Cowrie (SSH + Telnet), multiple cloud VPS nodes across North America and Asia |
| **Collection window** | `10/30/26` → `11/12/26` |
| **Update cadence** | Roughly monthly, tagged by date (`11/26`, `12/26`, …) |

### Cleaning

Raw honeypot logs are messy. Before publishing, every list goes through:

- **Protocol noise removed.** Scanners hit Telnet with all kinds of non-login traffic that Cowrie dutifully logs as "passwords": TLS ClientHellos, HTTP `GET` requests, SIP `OPTIONS` probes, MongoDB handshakes, even a bot's `command -v curl wget busybox` recon one-liner. None of that belongs in a wordlist.
- **Byte escapes decoded.** Cowrie logs non-ASCII input as `\xd0\xb9…`. Valid UTF-8 is decoded back to readable text (e.g. `12345678йцукен`); undecodable binary junk is dropped.
- **Control characters stripped.** Trailing `\x00`, tabs, BOMs, and CRLF endings.
- **Sensor identifiers scrubbed.** Anything that could point back to the honeypots themselves.
- **Deduplicated.**

## By the numbers

**Passwords**

| | |
|---|---:|
| Median length | 8 chars |
| 8 characters or fewer | 79.2% |
| Digits only | 28.0% |
| Lowercase letters only | 41.3% |
| Contain a year (19xx / 20xx) | 18.1% |
| Contain any special character | 8.3% |

The headline: nearly four out of five attempts are eight characters or shorter, and over a quarter are nothing but digits. A modern length-and-complexity policy blocks the overwhelming majority of this traffic outright.

**Top 15 passwords:** `password` `admin` `12345` `123456` `123` `111111` `root` `1234` `123123` `12345678` `123456789` `123321` `support` `1234567` `qwerty`

**Top 15 usernames:** `username` `admin` `root` `support` `test` `user` `ftpuser` `ubuntu` `dev` `ubnt` `data` `frappe` `demo` `pi` `kafka`

## What the usernames reveal

The username list is small but tells a story about what attackers expect to find exposed:

- **AI-agent boxes.** `claude`, `openclaw`, `clawdbot`, `cursor`, `codex`, `deepseek`, `kimi`, `aiuser`, `aibox` — machines set up to run AI coding agents and self-hosted LLMs.
- **Crypto infrastructure.** `solana`, `jito`, `firedancer`, `shredstream`, `blockscout`, `eth-validator`, `eigenlayer`, `validator`, `miner`, plus GPU-rental hosts `vastai` and `clore`.
- **Self-hosted app defaults.** `odoo` through `odoo18`, `frappe` / `erpnext`, `n8n`, `airflow`, `gitlab-runner`, `github-runner`, `zabbix`, `grafana`, `elastic`, `dolphinscheduler`.
- **Game servers.** `minecraft`, `teamspeak` / `ts3`, `steam`, `factorio`, `palworld`, `arma3server`, `fivem`.
- **IoT / embedded defaults.** `ubnt`, `pi`, `orangepi`, `radxa`, `odroid`, `jetson`, `AdminGPON`, `telecomadmin`, `xc3511`, `vstarcam2015`, `moxa`.

## Using it defensively

The most useful thing here is the frequency ordering. A short prefix of each list (say the first few hundred lines) accounts for most of the attack volume, so it's a practical set to:

- feed into a password-blocklist or filter so your users can't pick anything on it
- check your own accounts against, to confirm none match
- prioritize monitoring and lockout rules around the usernames bots probe most

## ⚠️ Responsible use

These lists are published for **defense and research**. If you use them for security testing, only do so against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal in most jurisdictions.

## License

Released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Use it however you like, just credit **beeswax by [@really-gabagool](https://github.com/really-gabagool)**.

## 🤝 Related

- [Cowrie](https://github.com/cowrie/cowrie) — the SSH/Telnet honeypot behind the data
- [SecLists](https://github.com/danielmiessler/SecLists) — the classic collection of security wordlists
- More of my honeypot and ICS tooling: [github.com/really-gabagool](https://github.com/really-gabagool)
