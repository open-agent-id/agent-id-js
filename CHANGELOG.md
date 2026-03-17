# Changelog

## 0.2.0 (2026-02-24)

### Breaking Changes
- DID format changed from `did:agent:{platform}:{id}` to `did:oaid:{chain}:{address}`
- Removed `AgentIdentity` class, replaced with `Agent`

### Added
- Two signing domains: `oaid-http/v1` (HTTP requests) and `oaid-msg/v1` (P2P messages)
- `signMessage()` for P2P message signing
- `Signer` class for oaid-signer daemon integration
- `RegistryClient` with wallet auth support
- `canonicalUrl()` and `canonicalJson()` utilities

### Changed
- All signing payloads now include domain prefix

## 0.1.1 (2026-02-18)

### Changed

- **Client-side key generation**: `AgentIdentity.register()` now generates the Ed25519 keypair locally and sends only the public key to the registry. The private key never leaves the client.

### Added

- `userToken` option on `register()` for wallet-based Bearer authentication (alternative to `apiKey`).
- `ownerId` option on `register()` for specifying the owner wallet address when using platform-key auth.

## 0.1.0 (2026-02-17)

- Initial release: register, sign, verify, and look up AI agent identities.
