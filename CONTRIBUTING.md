# Contributing to Scryve

Thank you for your interest in contributing to Scryve. This document explains how to get your changes merged efficiently.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [How to Contribute](#how-to-contribute)
3. [Development Setup](#development-setup)
4. [Branching and Commits](#branching-and-commits)
5. [Testing Requirements](#testing-requirements)
6. [Pull Request Process](#pull-request-process)
7. [Types of Contributions](#types-of-contributions)
8. [Compliance Framework Contributions](#compliance-framework-contributions)
9. [Reporting Bugs](#reporting-bugs)

---

## Code of Conduct

Scryve follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) Code of Conduct. Be respectful, constructive, and welcoming to contributors of all backgrounds.

---

## How to Contribute

The process follows a standard fork-based GitHub workflow:

1. **Fork** the repository at `https://github.com/kpkaranam/Scryve`
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/Scryve.git
   cd Scryve
   ```
3. **Add the upstream remote** so you can stay in sync:
   ```bash
   git remote add upstream https://github.com/kpkaranam/Scryve.git
   ```
4. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
5. **Make your changes** following the guidelines below
6. **Push** your branch to your fork:
   ```bash
   git push origin feat/your-feature-name
   ```
7. **Open a pull request** against the `main` branch of the upstream repository

---

## Development Setup

### Requirements

- Go 1.22 or later
- The four external tools installed and in your PATH: Subfinder, httpx, Naabu, Nuclei (see [README.md](README.md#prerequisites))
- `golangci-lint` for linting (optional but recommended):
  ```bash
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
  ```

### Running Scryve locally

```bash
# Build
go build ./cmd/scryve

# Run against a domain you own or have permission to test
./scryve scan yourdomain.com

# Run all tests
go test ./...

# Run tests with coverage
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run linter
golangci-lint run
```

---

## Branching and Commits

### Branch naming

Use one of these prefixes followed by a short kebab-case description:

| Prefix | Use for |
|--------|---------|
| `feat/` | New features or adapters |
| `fix/` | Bug fixes |
| `docs/` | Documentation only changes |
| `test/` | Adding or fixing tests |
| `refactor/` | Code restructuring without behavior change |
| `chore/` | Dependency updates, CI changes, tooling |

Examples:
- `feat/trivy-adapter`
- `fix/nuclei-template-filter`
- `docs/pci-dss-mapping`

### Commit messages

Scryve uses [Conventional Commits](https://www.conventionalcommits.org/). Every commit must follow this format:

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`

**Scope:** the part of the codebase affected, e.g., `adapter`, `reporter`, `normalizer`, `cli`, `compliance`

**Examples:**

```
feat(adapter): add Trivy container scan adapter
fix(normalizer): deduplicate findings with same template ID and asset
docs(compliance): add PCI DSS v4.0 Requirement 11.3 mapping
test(adapter): add unit tests for httpx JSON parser
refactor(reporter): extract HTML template to separate file
chore(deps): update nuclei-sdk to v3.2.0
```

The short description must:
- Use the imperative mood ("add" not "added", "fix" not "fixed")
- Not end with a period
- Be 72 characters or fewer

---

## Testing Requirements

Scryve follows test-driven development (TDD). The rule is: **write the test before the implementation**.

### What must be tested

- Every new adapter must have unit tests covering:
  - Successful parse of representative tool output (use fixture files, not real tool invocations)
  - Parse error handling (malformed input returns a descriptive error, not a panic)
  - Output normalization (verify the `Finding` and `Asset` structs are populated correctly)

- Every compliance mapping must have a test verifying that a known finding template ID maps to the expected control IDs

- Bug fixes must include a regression test that fails before the fix and passes after

### Running the test suite

All tests must pass before opening a pull request:

```bash
go test ./...
```

The CI pipeline runs tests on every pull request. A failing test blocks merge.

### Test fixtures

Tool output fixtures live in `testdata/` subdirectories next to the adapter code they test. Use real tool output (sanitized of any real hostnames or IPs) as fixtures — do not hand-craft JSON that does not match actual tool output.

---

## Pull Request Process

### Before opening a PR

- [ ] All tests pass (`go test ./...`)
- [ ] Linter passes (`golangci-lint run`) — or document why a lint warning is acceptable
- [ ] New code has tests (see Testing Requirements above)
- [ ] Commit messages follow the Conventional Commits format
- [ ] The branch is rebased on the latest `main` (not merged — rebase only)

### PR description template

When opening a pull request, fill in these sections:

```
## What this PR does

[One paragraph summary of the change and why it is needed.]

## How to test

[Step-by-step instructions for a reviewer to manually verify the change.]

## New dependencies

[List any new Go module dependencies added, with a brief rationale for each.
If none, write "None".]

## Checklist

- [ ] Tests added
- [ ] All tests pass
- [ ] Linter clean
- [ ] Documentation updated (if applicable)
```

### Review process

- At least one maintainer approval is required before merge
- Maintainers may request changes — address all comments before re-requesting review
- Rebasing to resolve conflicts is the contributor's responsibility
- Squash commits are preferred for single-purpose changes; multi-commit PRs are acceptable when each commit is meaningful and the history tells a clear story

---

## Types of Contributions

### New tool adapters

An adapter wraps a single external security tool. To add an adapter:

1. Create a directory under `internal/adapters/<toolname>/`
2. Implement the `Adapter` interface (defined in `internal/adapters/adapter.go`)
3. Add a fixture file under `internal/adapters/<toolname>/testdata/`
4. Write unit tests in `internal/adapters/<toolname>/<toolname>_test.go`
5. Register the adapter in the pipeline configuration

The adapter must not invoke the real tool during tests. Use the fixture file.

### Compliance framework mappings

Compliance mappings are YAML files that map Nuclei template tags and IDs to framework control IDs. They live in `compliance/`. See the existing `compliance/pci-dss-4.0.yaml` for the format. Contributions here do not require Go code changes.

### HTML report templates

The report template lives in `internal/reporter/templates/report.html`. Improvements to layout, readability, and print formatting are welcome. Include screenshots in the PR description showing before and after.

### Bug fixes

Open an issue first (unless the fix is trivially small) so the approach can be discussed before you invest time in implementation.

---

## Compliance Framework Contributions

Compliance mappings are especially valuable and relatively easy to contribute. The format is:

```yaml
# compliance/<framework-id>.yaml
framework:
  id: pci-dss-4.0
  name: "PCI DSS v4.0"
  version: "4.0"

controls:
  - id: "6.3.2"
    title: "An inventory of bespoke and custom software is maintained"
    nuclei_tags:
      - cve
      - exposed-panel
    nuclei_template_ids:
      - CVE-2023-12345
    severity_threshold: medium   # findings at this severity or above trigger a FAIL

  - id: "11.3.1"
    title: "Internal vulnerability scans are performed periodically"
    nuclei_tags:
      - misconfig
      - default-login
    severity_threshold: low
```

A control maps to FAIL if any Nuclei finding with a matching tag or template ID meets or exceeds the severity threshold during a scan. A control maps to PASS if matching templates ran and found nothing. A control maps to NOT TESTED if no matching templates were applicable to the detected technologies.

---

## Reporting Bugs

Open an issue at `https://github.com/kpkaranam/Scryve/issues` and include:

1. **Scryve version** — output of `scryve --version`
2. **Command run** — the exact `scryve scan ...` command (redact the domain if needed)
3. **Expected behavior** — what you expected to happen
4. **Actual behavior** — what actually happened, including any error output
5. **Environment** — OS, Go version, versions of Subfinder/httpx/Naabu/Nuclei

For security vulnerabilities in Scryve itself (not findings discovered by Scryve), please do not open a public issue. Email the maintainers directly.

---

## License

By contributing to Scryve, you agree that your contributions will be licensed under the MIT License. Community template and compliance mapping contributions stay open forever — Scryve will never relicense them.
