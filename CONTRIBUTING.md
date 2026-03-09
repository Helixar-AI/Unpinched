# Contributing to pinchtab-detector

Thank you for your interest in contributing to `pinchtab-detector`.

## Getting started

1. Fork the repository and clone it locally.
2. Ensure you have Go 1.22+ installed.
3. Run `go mod tidy` to fetch dependencies.
4. Build: `go build ./...`
5. Vet: `go vet ./...`

## What we welcome

- New detection signatures for PinchTab artifacts
- Platform-specific improvements (Windows, Linux `/proc` parsing)
- Performance improvements to the port scanner
- Bug fixes with clear reproduction steps
- Improved test coverage

## Out of scope

Please do not submit PRs that:

- Add detection for tools other than PinchTab and its direct CDP/HTTP bridge pattern
- Add network scanning beyond `localhost`
- Add persistent daemon or background service behaviour
- Add Helixar API calls or any telemetry

## Submitting a PR

- Keep commits focused and atomic
- Ensure `go build ./...` and `go vet ./...` pass clean
- Describe the detection logic clearly in the PR description — this is security tooling and reviewers need to understand what and why

## Reporting vulnerabilities

Security issues in this tool itself should be reported privately to **security@helixar.ai**.
