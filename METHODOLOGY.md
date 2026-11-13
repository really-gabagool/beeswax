# Collection and processing methodology

## Existing snapshot

The existing wordlists are preserved byte-for-byte. Their operator previously described removing protocol noise, decoding byte escapes, removing control characters, scrubbing sensor identifiers, and excluding suspected canaries. No original processing script or raw-event audit accompanies this snapshot. The new tool does not claim to reproduce those historical decisions.

There are no historical frequency CSVs: manufacturing counts from deduplicated wordlists would be misleading. Rebuild from the original logs to recover those measurements. Do not combine independently aggregated CSVs by simply adding distinct-source counts.

## New Cowrie builds

1. Read UTF-8 JSONL files in supplied order. Skip blank lines, count malformed JSON, and select only `cowrie.login.failed` and `cowrie.login.success` events. Success is honeypot acceptance, not proof of a valid credential elsewhere.
2. Deduplicate exact parsed JSON objects across all supplied files, ignoring object-key order. This handles overlapping copied logs. Events with changed or additional fields remain distinct. Identical records are collapsed even if emitted twice legitimately; source-side unique IDs would be preferable if available.
3. Require a timestamp with an explicit timezone, a valid `src_ip`, and a nonempty `sensor` string. Reject events missing these fields and report aggregate counts. Convert timestamps to UTC. A protocol field of `ssh` or `telnet` is counted explicitly; other or absent values remain `unknown`. No transport is inferred from ports or filenames.
4. Treat username and password independently. Decode contiguous literal `\xNN` runs as strict UTF-8. This is an assumption about escaped Cowrie input: a literal credential containing that notation is ambiguous and needs review. Invalid UTF-8 escape runs are excluded.
5. Exclude empty/non-string values, Unicode control/format/surrogate/private-use/unassigned characters (Unicode category C), and Unicode line/paragraph separators. Reject these values rather than silently changing credentials. Do not trim, casefold, or Unicode-normalize values.
6. Exclude common HTTP/SSH greeting and command-probe prefixes, standalone IP literals, and values containing any operator-supplied exclusion substring. These are conservative candidate filters, not a complete protocol classifier or sensitive-data detector. An actual password may match a filter. Record aggregate reasons; review the filtering assumptions for your deployment.
7. Deduplicate retained values, count their occurrences in eligible distinct events, and sort descending by count, then Unicode lexical order. Emit UTF-8/LF wordlists and CSVs.

Use a new or empty candidate output directory for each build; the tool refuses to overwrite existing candidates.

The tool operates offline. It holds event hashes and per-value source/sensor sets in memory, so memory grows with dataset size. Inputs are plain JSONL, not ZIP or gzip archives. Process manageable batches from a complete, non-overlapping collection when possible; do not infer historical totals from only a subset.

## Metadata schema

Each `password_metadata.csv` or `username_metadata.csv` row contains:

| Field | Meaning |
|---|---|
| `value` | Retained credential value, unchanged except documented byte-escape decoding |
| `attempt_count` | Eligible deduplicated events containing that retained value |
| `first_seen_utc`, `last_seen_utc` | Earliest/latest retained observation, ISO 8601 UTC |
| `distinct_sources` | Unique normalized source IP addresses for that value |
| `distinct_sensors` | Unique sensor strings for that value |
| `ssh_attempts`, `telnet_attempts`, `unknown_protocol_attempts` | Counts by explicit protocol classification |

Source IPs are not people or campaigns. Sensor aliases can inflate distinct-sensor counts. Metadata describes the input batch only. A password may be retained even if its associated username is excluded, and vice versa.

`build_audit.json` contains aggregate event/rejection counters only, with no input paths, rejected values, raw source IPs, or sensor names. CSVs omit raw source/sensor identities, but credential values themselves may still contain identifying text. CSV quoting does not neutralize spreadsheet formulas: treat value cells as untrusted text.

## Publication checklist

- Review candidate values for embedded addresses, hostnames, emails, canaries, binary/protocol leftovers, and ambiguous escapes. Automated filters are incomplete.
- Review aggregate exclusions and unknown-protocol counts. Document any intentional filtering or sensor-name mapping.
- Preserve significant whitespace; the existing snapshot has one edge-whitespace entry. Do not identify it as accidental without checking its source.
- Record exact collection boundaries/timezone, protocols, broad sensor geography, and methodology changes without exposing sensor addresses.
- Replace both wordlists together only after review. Optionally publish reviewed metadata CSVs; retain raw logs and exclusion lists privately.
- Regenerate `stats.md`, run validation/tests, and create a date-tagged release with the generated hashes.
- Report unique dictionary composition separately from attempt-weighted statistics. Only claim top-N traffic coverage after calculating it from complete counts.
