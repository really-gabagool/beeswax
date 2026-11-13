<div align="center">

# 🐝 beeswax

**Login guesses observed by internet-facing honeypots.**

A curated collection of usernames and passwords submitted to Cowrie SSH and Telnet honeypots, published for defense and research.

![source](https://img.shields.io/badge/source-Cowrie%20honeypots-222?style=flat-square)
![license](https://img.shields.io/badge/license-CC%20BY%204.0-222?style=flat-square)

</div>

## What is this?

I operate Cowrie honeypots and collect the login guesses they receive. Beeswax makes those observations available as portable wordlists for authorized security testing, password-blocklist evaluation, and comparison with other honeypot datasets.

These are observed inputs, not evidence of valid accounts or successful compromises. The collection is not a breach dump, although submitted guesses may overlap with passwords found elsewhere.

## Download

| File | Description |
|---|---|
| [captured_passwords.txt](captured_passwords.txt) | Unique observed password values |
| [captured_usernames.txt](captured_usernames.txt) | Unique observed username values |
| [stats.md](stats.md) | Generated counts, composition, length statistics, and SHA-256 hashes |

Both wordlists use UTF-8, LF line endings, and one case-sensitive entry per line. There are no duplicate or empty entries. Meaningful spaces are retained, including leading or trailing spaces.

**Ordering:** the current snapshot retains its inherited order. Historical attempt counts are not included, so its frequency ranking and the traffic coverage of any prefix cannot be independently verified. The build tool orders new candidates by retained attempt count, with Unicode lexical ordering to break ties.

## Collection and limitations

| Item | Current snapshot |
|---|---|
| Collector | Cowrie SSH/Telnet honeypots |
| Operator-reported deployment | Multiple cloud VPS nodes across North America and Asia |
| Operator-reported collection dates | 2026-10-31 through 2026-11-12 |
| Historical timestamp precision and timezone | Not supplied with the published lists |
| Historical frequencies, source counts, and sensor counts | Not available in this snapshot |
| Planned cadence | Roughly monthly; use date tags such as `2026-11-12` |

The raw collection provenance is operator-reported. File validation confirms the published bytes and statistics; it does not independently verify their origin. These observations represent this deployment and collection window, not the whole internet. A single high-volume source can dominate attempt counts. Sensor acceptance of a guess does not demonstrate a real-world compromise.

## What the usernames suggest

The list includes technology-themed guesses, including:

- **AI tools:** `claude`, `openclaw`, `clawdbot`, `cursor`, `codex`, `deepseek`, `kimi`, `aiuser`, `aibox`.
- **Cryptocurrency infrastructure:** `solana`, `jito`, `firedancer`, `shredstream`, `blockscout`, `eth-validator`, `validator`, `miner`.
- **Self-hosted applications:** `frappe`, `n8n`, `airflow`, `gitlab-runner`, `zabbix`, `grafana`.
- **Embedded devices:** `ubnt`, `pi`, `orangepi`, `jetson`, `telecomadmin`.

These names are consistent with dictionaries containing technology-related account guesses. They do not establish a targeted campaign, the technology present on a victim, exploitation, or attacker identity. Separately published username and password lists also do not preserve attempted pairs.

## Using the data

- Compare it with guesses received by your own sensors.
- Evaluate password-blocklist coverage and test accounts in authorized environments.
- Use recurring account names as context for monitoring; a username alone is not an indicator of compromise.

See [generated statistics](stats.md) for the dictionary's composition. Unique-entry percentages must not be reported as percentages of login attempts. These lists cannot quantify authentication success or how much traffic a password policy would prevent.

## Reproduce and maintain

Python 3.10 or newer; standard library only. No network requests or external dependencies.

```sh
python tools/beeswax.py validate
python tools/beeswax.py stats
python -m unittest discover -s tests -v
```

To process your own **Cowrie JSONL** exports into a separate local candidate directory:

```sh
python tools/beeswax.py build raw/cowrie.json raw/cowrie.json.2026-11-11 --out scratch/candidates --exclude-file raw/private-exclusions.txt
python tools/beeswax.py stats --root scratch/candidates
```

Create the private exclusions file first, with one literal, case-sensitive substring per line: sensor IPs, hostnames, personal identifiers, and suspected canary values you want excluded. Blank lines are ignored; there is no comment syntax. An empty file is accepted but adds no operator-specific filtering.

The output includes wordlists, per-value metadata CSVs, and aggregate rejection counters. **Review candidates before publication.** Automated filtering does not guarantee removal of every identifier, canary, or protocol artifact. CSV values are untrusted attacker input; import value columns as text with spreadsheet formula execution disabled.

See [METHODOLOGY.md](METHODOLOGY.md) for event selection, deduplication, normalization, privacy limitations, and metadata definitions. New processing rules do not retroactively establish how the original snapshot was cleaned.

## Contributing and responsible use

See [CONTRIBUTING.md](CONTRIBUTING.md). Use these lists only against systems you own or have explicit permission to test. Do not contribute breach dumps, invented entries, or private identifiers.

## License

Released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Credit **beeswax by [@really-gabagool](https://github.com/really-gabagool)**. See [LICENSE.md](LICENSE.md).

## Related

- [Cowrie](https://github.com/cowrie/cowrie) — the collection software
- [SecLists](https://github.com/danielmiessler/SecLists) — a broader security wordlist collection
- [My GitHub projects](https://github.com/really-gabagool) — honeypot and analysis tooling
