# Marauder Notebook downloads

This repository is the public distribution boundary for Marauder Notebook. It contains no application source code and has no write deploy key. Signed candidates arrive as inert Git data in a separate Actions-disabled intake repository; only this repository's protected publisher can turn one into a release.

Each published release includes:

- the notarized universal macOS app archive;
- its SHA-256 checksum;
- the Sparkle update feed;
- immutable release provenance; and
- the committed update-trust manifest.

The publishing workflow verifies the archive checksum, the Sparkle Ed25519 signature on the archive, a detached Ed25519 signature binding the complete release manifest and source commit, the Ed25519 signature on the update feed, the exact bundle identity and security entitlements, Developer ID signing, hardened runtime, both architectures in every nested Mach-O, Apple notarization, Gatekeeper acceptance, and monotonically increasing app and build versions before a draft can be published. Partial drafts are recovered only after every existing byte and identity field matches. GitHub immutable releases protect the final tag and assets after publication. Each scheduled run rechecks the immutable history and attestation for every published release, then downloads and fully revalidates the latest release and each of its asset attestations.

Download the current app from [Releases](https://github.com/Balllvin/marauder-notebook-releases/releases/latest). Marauder Notebook reads the same signed `appcast.xml` to check for updates.
