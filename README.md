# Spoof Spotter

Spoof Spotter is a Python-based domain, URL, and email-domain analysis tool designed to identify indicators commonly associated with spoofing, phishing, and malicious domain activity.

The project combines local domain analysis, historical IOC correlation, privacy-aware live threat intelligence, and explainable heuristic risk scoring.

> **Important:** Spoof Spotter is an educational cybersecurity project. Risk scores represent weighted security indicators and are **not** probabilities that a domain is malicious.

---

## Getting Started

### 1. Clone the Repository

Clone or download the Spoof Spotter repository and open a terminal in the project directory.

### 2. Install Dependencies

```cmd
py -m pip install -r requirements.txt
```

### 3. Obtain and Configure API Credentials (Optional)

Spoof Spotter can store supported API credentials in the operating system credential vault through Python `keyring`. Credentials are optional. If a service is unavailable, not configured, blocked by the selected privacy policy, or otherwise cannot be reached, Spoof Spotter continues with the intelligence sources that remain available.

#### ThreatFox Auth-Key

ThreatFox requires a personal abuse.ch Auth-Key for API access.

1. Open the [abuse.ch Authentication Portal](https://auth.abuse.ch/).
2. Sign in or create an abuse.ch account.
3. Create or copy your personal Auth-Key.
4. Do not paste the key into source code, screenshots, issues, or commits.
5. Store it with Spoof Spotter using the credential setup utility described below.

Official documentation: [ThreatFox Community API](https://threatfox.abuse.ch/api/)

#### Google Safe Browsing API Key

Spoof Spotter uses Google Safe Browsing v5 for privacy-conscious hash-prefix lookups.

1. Sign in to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new Google Cloud project or select an existing project.
3. Open **APIs & Services > Library** and enable the **Safe Browsing API** for that project.
4. Open **APIs & Services > Credentials**.
5. Select **Create credentials > API key**.
6. Apply an API restriction so the key is limited to the Safe Browsing API when practical.
7. Copy the API key and store it with Spoof Spotter using the credential setup utility.
8. Do not commit or publish the key.

Google recommends restricting API keys and keeping them out of source code. Safe Browsing is intended for non-commercial use; Google directs commercial malicious-URL detection use cases to Web Risk.

Official documentation:

- [Google Cloud API key management](https://cloud.google.com/docs/authentication/api-keys)
- [Google Safe Browsing APIs](https://developers.google.com/apis-explorer/#p/safebrowsing/v5/)

#### PhishTank Application Key

Spoof Spotter includes PhishTank integration for phishing-specific full-URL intelligence.

Normally, obtaining a PhishTank application key requires:

1. Complete the free PhishTank registration.
2. Confirm the registration email.
3. Sign in to PhishTank.
4. Open the PhishTank API page.
5. Copy the application key displayed for the account.
6. Store it with Spoof Spotter using the credential setup utility.

At the time of this project snapshot, **new PhishTank user registration is temporarily disabled**. Existing members can still sign in. Because a new personal application key could not be obtained during development, Spoof Spotter's PhishTank client is implemented and covered by mocked automated tests, but live application-key validation remains pending.

Official documentation:

- [PhishTank API Information](https://phishtank.org/api_info.php)
- [PhishTank FAQ](https://phishtank.org/faq.php)
- [PhishTank Registration](https://phishtank.org/register.php)

#### Store Keys in the OS Credential Vault

After obtaining a supported key, run:

```cmd
py tools\configure_api_keys.py
```

Use the menu to store or update the credential for the appropriate service:

```text
ThreatFox
Google Safe Browsing
PhishTank
```

The setup utility uses the operating system credential vault through Python `keyring`. The key is not intentionally written into the Spoof Spotter repository.

You can run the setup utility again to view credential **status** or remove a stored credential. Status output identifies whether a credential is coming from the OS keyring, an environment variable, or is missing without printing the secret itself.

#### Environment-Variable Alternative

Environment variables remain supported for development, CI, and automation and take priority over the OS keyring when present.

```text
THREATFOX_AUTH_KEY
GOOGLE_SAFE_BROWSING_API_KEY
PHISHTANK_API_KEY
```

Example temporary Windows CMD variables:

```cmd
set THREATFOX_AUTH_KEY=YOUR_AUTH_KEY
set GOOGLE_SAFE_BROWSING_API_KEY=YOUR_API_KEY
set PHISHTANK_API_KEY=YOUR_API_KEY
```

Remove temporary values from the current CMD session when finished:

```cmd
set THREATFOX_AUTH_KEY=
set GOOGLE_SAFE_BROWSING_API_KEY=
set PHISHTANK_API_KEY=
```

> **Credential safety:** Never hardcode real API keys in source code. Never commit API keys, `.env` files, credential exports, screenshots containing secrets, or other secret material to GitHub. Review `git diff` and `git diff --cached` before every public commit.

### 4. Run Spoof Spotter

```cmd
py spoof_spotter.py
```

Choose an analysis mode, then enter an email address, domain, or website when prompted.

### 5. Run the Automated Test Suite

```cmd
py -m unittest discover -s tests -v
```

The automated suite uses mocked responses for live-service behavior where appropriate. Unit tests should not require real API keys or intentionally contact live threat-intelligence services.

---

## Analysis Modes

Spoof Spotter separates local analysis from external intelligence requests.

### Standard Mode

Standard Mode can use:

- Local domain analysis
- Historical IOC intelligence
- ThreatFox live IOC lookups
- Google Safe Browsing hash-prefix lookups
- PhishTank full-URL lookups when available

### Privacy Mode

Privacy Mode minimizes disclosure to external services.

Privacy Mode:

- Keeps local analysis enabled
- Keeps historical/local intelligence enabled
- Keeps Google Safe Browsing hash-prefix lookups enabled
- Blocks cleartext ThreatFox lookups
- Blocks raw-URL PhishTank lookups

Privacy Mode is designed to reduce external disclosure. It should not be interpreted as anonymous browsing or complete network anonymity.

---

## Current Features

### Input Analysis

- Accepts domain names, websites, and email addresses
- Normalizes domain input
- Extracts base domains and subdomains
- Supports multi-level public suffixes
- Distinguishes full URLs from bare domains for URL-specific intelligence

### Domain Analysis

- Approved-domain checking using a separate explicit approved-domain list
- Similarity and typo-squatting detection against a legitimate reference corpus
- 10,000-domain Tranco reference dataset
- Separate approved-domain trust and reference-domain similarity roles
- Exact reference-domain matches are not treated as typo-squatting matches
- ASCII digit detection
- Domain and subdomain character analysis
- Unicode character detection
- Homoglyph detection
- Mixed-script detection
- Punycode detection and decoding

### Reference-Domain Intelligence

Spoof Spotter uses a local 10,000-domain subset of the Tranco research-oriented domain ranking as a reference corpus for similarity and typo-squatting analysis.

Reference domains are used only as comparison candidates. Inclusion in the Tranco reference corpus does **not** mean that a domain is approved, trusted, safe, or free from compromise.

The reference corpus is maintained separately from `approved_domains.txt` so that popularity or similarity data cannot automatically establish trust.

Spoof Spotter records the Tranco list source and version information in `data/reference_sources.txt` for provenance and reproducibility.

### Historical Threat Intelligence

Spoof Spotter supports historical IOC correlation using the FBI LabHost domain dataset.

Historical IOC matches are treated as strong indicators, but they do not by themselves establish that a domain is currently malicious.

### Live Threat Intelligence

#### ThreatFox

Spoof Spotter integrates with the ThreatFox Community API by abuse.ch.

ThreatFox lookups can provide:

- Exact IOC matches
- IOC type
- Threat type
- Threat description
- Associated malware information
- Confidence level
- First-seen and last-seen timestamps
- Compromised-host status

ThreatFox intelligence is preserved as contextual evidence rather than being reduced to a simple malicious/clean result.

ThreatFox cleartext lookups are allowed in Standard Mode and blocked in Privacy Mode.

#### Google Safe Browsing

Spoof Spotter integrates with Google Safe Browsing v5 using locally generated URL hash expressions and 4-byte SHA-256 hash prefixes.

The submitted URL is canonicalized and hashed locally. Only generated hash prefixes are sent to Google. Returned full hashes are verified locally before a match is reported.

The integration includes:

- URL canonicalization
- Safe Browsing hash-expression generation
- 4-byte hash-prefix requests
- Binary protobuf response decoding
- Full-hash verification
- Positive and negative cache handling
- `cacheDuration` support
- Controlled live-test tooling

Google Safe Browsing remains available in both Standard and Privacy modes because the lookup path sends locally generated hash prefixes rather than the submitted URL directly.

#### PhishTank

Spoof Spotter includes a PhishTank client for phishing-specific URL intelligence.

PhishTank is treated as a **full-URL intelligence source**, not as a general domain-reputation service and not as an email-address reputation service.

The current implementation includes:

- HTTPS-only lookup handling
- OS-keyring credential support
- Environment-variable fallback
- Standard/Privacy policy routing
- Full-URL input routing
- Response normalization
- Rate-limit handling
- Report integration
- Mocked automated tests
- A controlled live-test utility

Raw PhishTank URL lookups are allowed only in Standard Mode. Privacy Mode blocks the lookup because the submitted URL would need to be sent to the external service.

Live application-key validation is currently pending. During this development snapshot, new PhishTank user registration was unavailable, so no new personal application key could be obtained. The PhishTank integration should therefore be considered implemented and locally tested, but **not yet live-key validated**.

---

## Explainable Risk Scoring

Spoof Spotter generates a heuristic risk score from 0 to 100.

Current risk levels:

- **LOW:** 0-24
- **MODERATE:** 25-49
- **HIGH:** 50-74
- **CRITICAL:** 75-100

The score can incorporate weighted indicators such as:

- Unapproved domains
- Similarity to legitimate reference domains
- Suspicious character patterns
- Unicode and homoglyph indicators
- Historical IOC matches
- Live ThreatFox IOC matches
- ThreatFox confidence information

PhishTank currently contributes report evidence only. It does not yet change the risk score because live-key validation has not been completed.

Google Safe Browsing is also reported as external intelligence without being treated as a probability of malicious activity.

The score is intended to explain why an input was flagged. It is **not** a probability of malicious activity.

---

## Threat Intelligence Sources

Current and integrated intelligence sources include:

- **FBI / IC3 LabHost historical domain data**
- **ThreatFox by abuse.ch**
- **Google Safe Browsing v5**
- **PhishTank** - implemented, live-key validation pending

Threat-intelligence matches should be interpreted with their source, confidence, freshness, status, and surrounding context.

A matched domain or URL may represent malicious infrastructure, or it may be an otherwise legitimate host that has been compromised.

---

## Screenshots

### Clean Domain Analysis

A known legitimate domain provides a baseline example of Spoof Spotter's approved-domain checking and local analysis.

![Clean Microsoft domain analysis](docs/screenshots/microsoft-clean.png)

### Tranco Reference-Domain Similarity Detection

Spoof Spotter compares an unapproved domain against a 10,000-domain Tranco reference corpus. In this example, the altered domain is matched to `microsoft.com` with a 92.3% similarity score.

![Tranco reference-domain similarity detection](docs/screenshots/tranco-similarity.png)

### Live ThreatFox IOC Detection

A redacted live-IOC example demonstrates Spoof Spotter's ThreatFox integration while avoiding publication of potentially active malicious infrastructure.

![ThreatFox IOC detection](docs/screenshots/threatfox-positive-redacted.png)

> The live IOC example is shown for defensive analysis only. Potentially active IOC values and identifying timestamps have been redacted.

## Project Structure

```text
spoof_spotter/
├── spoof_spotter.py
├── core/
│   ├── parser.py
│   ├── domain_checker.py
│   ├── reference_domains.py
│   ├── similarity.py
│   ├── tranco_importer.py
│   ├── character_checker.py
│   ├── risk.py
│   ├── report.py
│   ├── threat_intel.py
│   ├── threatfox.py
│   ├── privacy.py
│   ├── credentials.py
│   ├── google_safe_browsing.py
│   ├── google_safe_browsing_client.py
│   ├── google_safe_browsing_cache.py
│   ├── google_safe_browsing_protobuf.py
│   └── phishtank.py
├── data/
│   ├── approved_domains.txt
│   ├── reference_domains.txt
│   ├── reference_sources.txt
│   └── historical_iocs/
│       ├── LabHost_Domains.csv
│       └── sources.txt
├── docs/
│   └── screenshots/
│       ├── microsoft-clean.png
│       ├── tranco-similarity.png
│       ├── threatfox-positive-redacted.png
│       └── phishtank-positive-redacted.png  # future after live validation
├── tests/
│   ├── test_parser.py
│   ├── test_domain_checker.py
│   ├── test_reference_domains.py
│   ├── test_similarity.py
│   ├── test_tranco_importer.py
│   ├── test_character_checker.py
│   ├── test_risk.py
│   ├── test_report.py
│   ├── test_threat_intel.py
│   ├── test_threatfox.py
│   ├── test_privacy.py
│   ├── test_credentials.py
│   ├── test_google_safe_browsing.py
│   ├── test_google_safe_browsing_cache.py
│   ├── test_google_safe_browsing_client.py
│   ├── test_google_safe_browsing_protobuf.py
│   └── test_phishtank.py
├── tools/
│   ├── benchmark_similarity.py
│   ├── update_reference_domains.py
│   ├── configure_api_keys.py
│   ├── manual_google_safe_browsing_live.py
│   └── manual_phishtank_live.py
├── requirements.txt
├── README.md
└── LICENSE
```

> `phishtank-positive-redacted.png` is reserved for a future live-validated screenshot and may not exist yet.

---

## Similarity Performance

Spoof Spotter currently compares input domains against a local 10,000-domain reference corpus.

During development, the similarity workflow originally performed two complete reference-corpus comparisons for each analysis. The workflow was refactored to calculate the closest-domain similarity once and reuse the resulting score for threshold evaluation.

Local benchmark results:

- Reference domains: 10,000
- Before optimization: approximately 0.380 seconds
- After optimization: approximately 0.191 seconds
- Benchmark reduction: approximately 50%

Benchmark results are system-dependent and are included as development measurements rather than guaranteed performance.

---

## Security and Credential Handling

Spoof Spotter does not require API credentials to be stored in the repository.

API credentials can be stored through the operating system credential vault using Python `keyring`:

```cmd
py tools\configure_api_keys.py
```

Environment variables remain supported as an override for development and automation.

Security requirements:

- Never hardcode real API credentials in source code.
- Never commit API keys, `.env` files, secret files, or credential exports.
- Each user should obtain and use their own service credentials.
- Credentials should never be printed in reports or diagnostic output.
- Live-intelligence integrations should fail gracefully when credentials or network access are unavailable.
- Privacy Mode should block services that require disclosure of cleartext indicators where appropriate.
- Potentially active malicious URLs should not be opened solely for testing.
- Live-IOC screenshots should redact active infrastructure or identifying values when appropriate.

Before committing changes, review both the working tree and staged diff for accidentally exposed secrets.

---

## Release Roadmap

Spoof Spotter is approaching feature completion. PhishTank is intended to be the final live threat-intelligence integration for the initial release.

Remaining planned work:

- Complete live PhishTank validation when a personal application key becomes available.
- Add locally stored/downloaded phishing intelligence for privacy-aware and offline analysis.
- Track local-dataset source, version, download time, age, and staleness.
- Warn when local intelligence is stale and avoid interpreting dataset absence as proof of safety.
- Decide whether locally downloaded feeds should contribute to risk scoring after validation.
- Refine final risk weights and explanatory wording after the remaining intelligence path is validated.
- Expand regression and integration testing around local/downloaded intelligence.
- Finalize CLI/report formatting and documentation.
- Update screenshots and third-party data attribution.
- Perform a final security, credential, and repository review.
- Tag a stable initial release.

Additional live APIs are intentionally out of scope for the initial release unless a clear security or coverage gap is discovered.

---

## Project Status

Spoof Spotter is approaching feature completion.

The current implementation includes local spoofing analysis, separate approved and reference-domain architectures, a 10,000-domain Tranco similarity corpus, historical FBI/IC3 IOC correlation, live ThreatFox intelligence, Google Safe Browsing v5 privacy-conscious hash-prefix lookups, Standard and Privacy analysis modes, OS-keyring credential storage, PhishTank integration pending live credential validation, explainable heuristic risk scoring, performance benchmarking, and automated testing.

Remaining development is focused primarily on local/downloaded intelligence, validation, documentation, testing, and release polish rather than additional live API integrations.

---

## License

Spoof Spotter source code is licensed under the MIT License.

Third-party datasets and threat-intelligence data, including Tranco, FBI/IC3, abuse.ch, Google Safe Browsing, and PhishTank data, remain subject to the terms, notices, licenses, and usage conditions of their respective sources.
