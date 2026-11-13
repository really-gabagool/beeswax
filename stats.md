# 📊 beeswax — full breakdown

Stats for the current release. Counts are over **unique** entries, not raw attempts.

- **Passwords:** 35,585 unique
- **Usernames:** 996 unique

## Password length

| Length | Count | Share |
|---|---:|---:|
| 1–4 chars | 2,419 | 6.8% |
| 5–6 chars | 10,127 | 28.5% |
| 7–8 chars | 15,650 | 44.0% |
| 9–10 chars | 5,119 | 14.4% |
| 11–12 chars | 1,504 | 4.2% |
| 13+ chars | 766 | 2.2% |

**79.2%** are 8 characters or shorter. Shortest is 1 character; longest is 128.

## Password composition

| Property | Share |
|---|---:|
| Digits only | 28.0% |
| Letters only | 43.4% |
| Lowercase letters only | 41.3% |
| Letters + digits (no symbols) | 20.3% |
| Contains a special character | 8.3% |
| Contains a year (19xx / 20xx) | 18.1% |

Only about 1 in 12 attempted passwords contains any special character, and fewer than 5% are longer than 10 characters. The attacker corpus is overwhelmingly short and simple, because that's what still works.

## Notes

- Lists are deduplicated, so a password tried a million times counts once here. These numbers describe the **shape of the dictionary**, not traffic volume.
- Non-English passwords (Cyrillic, Arabic, Korean, Chinese) are a small slice of the unique set but are preserved as real UTF-8 text.
- Regenerate these figures yourself from the published files; nothing here depends on private logs.
