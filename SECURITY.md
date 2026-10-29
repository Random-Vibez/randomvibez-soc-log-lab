# Security policy

SOC Log Lab is a static browser-only synthetic-data generator. It does not accept uploads, make network requests, persist inputs, or contact a service. Do not enter real credentials, personal data, or live indicators; do not treat generated events as IOCs or use them as production detection validation without independent review.

## Reporting a concern

Please report security issues privately to the RandomVibez project owner through the contact route on <https://randomvibez.ai/>. Do not publish secrets or personal information in a public issue. There is no server-side account, storage, or processing component in this application.

## Scope and known limitations

- The answer-key download intentionally contains the private trainer seed and finding IDs so the scenario can be regenerated. It is unencrypted: keep it private and separate from analyst JSONL/raw exports. The trainer seed is not included in analyst JSONL or raw syslog. Do not put secrets or personal information in a manually entered seed.
- The default seed, per-generation record IDs, and numeric process IDs use Web Crypto secure randomness. Generation fails closed if `crypto.getRandomValues` is unavailable; there is no weaker randomness fallback.
- The app’s no-network design is enforced in code and by a restrictive page Content Security Policy. The parent site’s existing consent banner can set its documented first-party preference cookie if accepted.
- Vendor-shaped examples are educational approximations only. They are not official vendor exports or ingest-ready schemas.
