# scryve

**One domain. Complete security picture.**

Scryve is an open-source CLI security scanner that takes a single domain and delivers a full security assessment — subdomain discovery, port scanning, vulnerability detection, email security validation, and compliance mapping.

## Quick Start

```bash
# Install
go install github.com/kpkaranam/scryve-cli@latest

# Or download from releases
curl -sSfL https://github.com/kpkaranam/scryve-cli/releases/latest/download/scryve_linux_amd64.tar.gz | tar xz

# Run your first scan
scryve scan --target yourdomain.com
```

## What It Does

| Module | Description |
|--------|-------------|
| **Recon** | Subdomain enumeration, DNS resolution, HTTP probing |
| **Port Scanning** | Service discovery across your attack surface |
| **Vulnerability Detection** | 9,000+ Nuclei templates for CVEs, misconfigs, exposed panels |
| **Email Security** | SPF, DKIM, and DMARC validation |
| **Compliance Mapping** | Findings mapped to PCI DSS 4.0, SOC 2, ISO 27001 |

## Output Formats

```bash
# JSON (default)
scryve scan --target example.com --format json

# HTML report
scryve scan --target example.com --format html

# Markdown
scryve scan --target example.com --format markdown
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    scryve scan --target ${{ env.DOMAIN }} --format json --output report.json
```

## Requirements

Scryve orchestrates these open-source tools (auto-installed via `scryve setup`):

- [subfinder](https://github.com/projectdiscovery/subfinder) — Subdomain discovery
- [httpx](https://github.com/projectdiscovery/httpx) — HTTP probing
- [naabu](https://github.com/projectdiscovery/naabu) — Port scanning
- [nuclei](https://github.com/projectdiscovery/nuclei) — Vulnerability scanning

```bash
# Install all dependencies
scryve setup
```

## Build from Source

```bash
git clone https://github.com/kpkaranam/scryve-cli.git
cd scryve-cli
make build
```

## Development

```bash
make test      # Run tests with coverage
make lint      # Run linter
make check     # Full CI gate (fmt + vet + lint + test)
```

## Compliance Frameworks

Scryve maps scan findings to these frameworks (CLI pass/fail output):

- **PCI DSS 4.0** — Payment card security
- **SOC 2** — Service organization controls
- **ISO 27001** — Information security management
- **GDPR** — Data protection (EU)

## License

MIT — see [LICENSE](LICENSE)
