# Changelog

## [2.0.0] - 2026-07-20
### Added
- AI-powered interactive shell mode via Ollama.
- MITRE ATT&CK technique mapping and logging.
- Threat intelligence integration (AbuseIPDB, AlienVault OTX, VirusTotal).
- Multi-channel alerting (webhook, Slack, Discord, email).
- GeoIP lookup with MaxMind GeoLite2.
- SFTP server emulation.
- Dashboard for monitoring attack data.
- Metrics endpoint for Prometheus scraping.
- Configurable fingerprint rotation for SSH banners.

### Changed
- Migrated from single-threaded to connection-per-thread architecture.
- Improved fake filesystem with realistic `/etc`, `/var/log`, and `/home` structure.
- Enhanced session logging with structured JSON output.
- Rate limiting now supports sliding window with automatic ban/unban.

### Fixed
- Duplicate severity key (`low`) replaced with correct `medium` level.
- VirusTotal API key now uses separate config field instead of reusing AbuseIPDB key.
