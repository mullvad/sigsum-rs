# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-02-09

### Added

- The `Policy` type gained a full implementation of the quorum logic and the
  ability to parse Sigsum policies.
- There's a new `PolicyBuilder` type that can be used to programatically build
  valid `Policy` values.
- The crates now ships with the `sigsum-generic-2025-1` policy as well as three
  test policies (same policies that are built into the reference Sigsum
  tooling).

### Removed

- The `Policy::new_k_of_n()` constructor has been removed in favor of
  `PolicyBuilder`.
