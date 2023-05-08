# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add support for dynamic clients

### Changed

- Improve logging

## [v1.0.1] - 2022-11-24

### Added

- Initialize `webOrigins` to `+`

### Fixed

- Fix the case of `token_endpoint_auth_method`'s value

## [v1.0.0] - 2022-09-01

### Added

- Initialize files

### Fixed

- Enable consent page only if the authZ code or device code flow is enabled

### Removed

- Ignore `client.offline.session.max.lifespan` parameter
