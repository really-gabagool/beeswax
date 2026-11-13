# Contributing to beeswax

Thanks for your interest. This repo is a curated dataset, not a code project, so contributions work a little differently.

## What's welcome

- **Corrections.** If an entry looks like leftover protocol noise, an un-decoded byte string, or something that could identify a specific sensor, open an issue and point to the line. That kind of cleanup is exactly what keeps the lists usable.
- **Data from your own honeypots.** If you run Cowrie (or similar) and want to merge in captures, open an issue first so we can agree on format and make sure your sensor identifiers are scrubbed before anything lands.
- **Analysis.** Interesting patterns, new attacker tooling signatures in the usernames, write-ups that cite the data.

## What won't be merged

- **Real leaked credentials** from breaches or dumps. This repo is strictly honeypot-observed attacker input. Mixing in breach data changes what the dataset means and creates problems it doesn't currently have.
- **Anything that identifies a real person or a specific victim host.**
- **Made-up or generated entries** padded in to inflate the count.

## Format rules

If you do submit data, every file must stay:

- one entry per line
- UTF-8, LF line endings
- deduplicated
- free of sensor IPs, hostnames, and other identifiers
- non-ASCII input decoded to real text, not `\xNN` escapes

## Reporting a problem privately

If you find something sensitive that shouldn't be public (an identifier that slipped through the scrub), **don't open a public issue.** Reach out through the contact on my GitHub profile instead.

## Reproducible updates

Read [METHODOLOGY.md](METHODOLOGY.md) before submitting a new collection. Include collection dates/timezone, broad sensor geography, event-selection rules, and aggregate exclusions. Keep logs, exclusion files, and sensor identifiers private.

Run these checks before opening a pull request:

```sh
python tools/beeswax.py validate
python tools/beeswax.py stats
python -m unittest discover -s tests -v
python tools/beeswax.py stats --check
```

Preserve significant whitespace and case. Do not silently turn a guessed credential into a different string. Review byte-escape decoding and filter exclusions against source logs. Publish per-value metadata only after a privacy review; frequency order must be supported by counts for the same collection window. Never derive historical attempt counts from unique-entry lists.

The current snapshot predates the new processing tool. Changes to its values require evidence from source logs; documentation/statistics corrections alone should not alter its bytes.
