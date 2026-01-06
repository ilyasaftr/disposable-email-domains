# Disposable Email Domains

Aggregates disposable-email domain data from multiple upstream sources and publishes clean, deduplicated allow and deny lists. A scheduled GitHub Action keeps the lists current and commits changes automatically.

## Stats
<!-- STATS:START -->
- Deny: 193749
- Allow: 1100
- Total: 194849
- Last updated: 2026-01-06 12:02 UTC
<!-- STATS:END -->

## What "lists/" Contains

| Path                 | Format | Description                                      |
|----------------------|--------|--------------------------------------------------|
| `lists/deny.txt`     | text   | Blocklist of disposable domains (one per line).  |
| `lists/deny.json`    | JSON   | JSON array of disposable domains.                |
| `lists/allow.txt`    | text   | Allowlist of common/high‑trust providers.        |
| `lists/allow.json`   | JSON   | JSON array of common/high‑trust providers.       |

Notes
- Deny is filtered against Allow and against `sources/secure.txt` (by eTLD+1). If a domain appears in allow/secure, it is removed from deny.
- Lists are normalized (lowercase, no leading `*.`/`.`), sorted, and deduplicated.
- File paths and formats are stable so they can be consumed directly.

## Sources
This repository aggregates public lists declared under `sources/`:
- `sources/deny-text.txt` and `sources/deny-json.txt`
- `sources/allow-text.txt` and `sources/allow-json.txt`
- `sources/secure.txt` — trusted domains always allowed and excluded from deny

### Download URLs
Use `raw.githubusercontent.com` or the `jsDelivr` CDN. Replace `main` with a tag or commit to pin a version.

- Deny (text):
  - raw.githubusercontent.com: [https://raw.githubusercontent.com/ilyasaftr/disposable-email-domains/main/lists/deny.txt](https://raw.githubusercontent.com/ilyasaftr/disposable-email-domains/main/lists/deny.txt)
  - jsDelivr CDN: [https://cdn.jsdelivr.net/gh/ilyasaftr/disposable-email-domains@main/lists/deny.txt](https://cdn.jsdelivr.net/gh/ilyasaftr/disposable-email-domains@main/lists/deny.txt)
- Deny (JSON):
  - raw.githubusercontent.com: [https://raw.githubusercontent.com/ilyasaftr/disposable-email-domains/main/lists/deny.json](https://raw.githubusercontent.com/ilyasaftr/disposable-email-domains/main/lists/deny.json)
  - jsDelivr CDN: [https://cdn.jsdelivr.net/gh/ilyasaftr/disposable-email-domains@main/lists/deny.json](https://cdn.jsdelivr.net/gh/ilyasaftr/disposable-email-domains@main/lists/deny.json)
- Allow (text):
  - raw.githubusercontent.com: [https://raw.githubusercontent.com/ilyasaftr/disposable-email-domains/main/lists/allow.txt](https://raw.githubusercontent.com/ilyasaftr/disposable-email-domains/main/lists/allow.txt)
  - jsDelivr CDN: [https://cdn.jsdelivr.net/gh/ilyasaftr/disposable-email-domains@main/lists/allow.txt](https://cdn.jsdelivr.net/gh/ilyasaftr/disposable-email-domains@main/lists/allow.txt)
- Allow (JSON):
  - raw.githubusercontent.com: [https://raw.githubusercontent.com/ilyasaftr/disposable-email-domains/main/lists/allow.json](https://raw.githubusercontent.com/ilyasaftr/disposable-email-domains/main/lists/allow.json)
  - jsDelivr CDN: [https://cdn.jsdelivr.net/gh/ilyasaftr/disposable-email-domains@main/lists/allow.json](https://cdn.jsdelivr.net/gh/ilyasaftr/disposable-email-domains@main/lists/allow.json)

## Local Generation
- Requires Go 1.22+: `go run .`
- By default writes outputs to `lists/`. Flags allow overriding input/output paths if needed.

## Automation
A scheduled workflow (`.github/workflows/update-lists.yml`) runs periodically to regenerate and commit updates. Only changed files are committed.

## Important Notes
- Upstream sources may change or temporarily fail, the generator retries and continues with partial data, then normalizes and deduplicates.
- You should still apply your own validation/logging when integrating these lists into production systems.
