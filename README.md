# Marauder Notebook downloads

This repository is the public distribution boundary for Marauder Notebook. It contains no application source code and has no write deploy key. Release candidates arrive as inert Git data in a separate Actions-disabled intake repository; only the reviewed publisher on this repository's protected `main` can turn one into a release.

## Download and open

Download the current app from [Releases](https://github.com/Balllvin/marauder-notebook-releases/releases/latest), move **Marauder Notebook** to Applications, and open it. Publication is blocked unless the archive is Developer ID signed, accepted by Apple notarization, stapled with that ticket, and accepted by Gatekeeper. Users must never need to bypass macOS security or clear quarantine to open an ordinary public release. Marauder sign-in is the only product account flow. Later updates are installed by the app from the signed update feed.

## Release integrity

Every published release includes:

- the Developer ID signed, Apple-notarized, stapled, and Gatekeeper-accepted universal macOS app archive;
- its SHA-256 checksum;
- the Sparkle update feed;
- immutable release provenance; and
- the committed update-trust manifest.

The publishing policy requires one configured Apple Team ID. Before publication it verifies that:

- the main app and every nested Mach-O are signed by the same Developer ID Application certificate for the configured Apple Team ID;
- every executable retains Hardened Runtime and every nested executable has exactly the producer-approved entitlement set;
- Apple's stapler validates the notarization ticket and `spctl` accepts the expanded app before publication;
- the app, every nested executable, and every framework are universal `arm64` and `x86_64` code;
- the exact bundle identity, version, build, update key, feed URL, deep link, sandbox, file, network, and microphone entitlements match the protected contract;
- the archive checksum, Sparkle Ed25519 archive signature, signed appcast, and signed provenance all validate against the committed public key;
- the intake contains exactly the five approved immutable files, points to an exact Marauder source commit, and links to the source commit in the latest signed immutable release; and
- the version and build number are newer than every published release.

Unsigned, ad-hoc, independently signed, wrong-team, mixed-certificate, tampered, unsealed, thin, relabeled, malformed, mutable, unnotarized, unstapled, Gatekeeper-rejected, or incompletely signed candidates fail closed. Independent signatures may remain useful for private audit artifacts, but they never qualify a public download. The Ed25519 signing key remains mandatory: the publisher never releases an unsigned archive or update feed.

GitHub immutable releases protect final tags and assets after publication. Every publisher run rechecks the full release history and attestations, downloads the latest release, revalidates all five signed assets, expands the archive, and repeats the complete bundle/signature verification.

Every candidate after the first carries the previous published source commit inside its signed provenance. The publisher downloads the latest immutable manifest, verifies both signatures, and requires an exact link before publication. The private producer separately proves that the candidate source descends from that commit. This prevents a higher version number from republishing older source and rejects candidates emitted by historical workflows that lack the signed continuity field.

## Publisher branch protection

GitHub-hosted checks are not part of the publisher trust path. Before a publisher change is merged, run the tracked verifier locally against the exact clean candidate checkout:

```bash
scripts/verify_publisher_boundary.sh \
  --root /path/to/candidate-checkout
```

The verifier performs the compile, shell, OpenSSL, actionlint, and complete test-suite checks without GitHub credentials or repository mutations. The optional `.github/workflows/publisher-ci.yml` is a manual mirror for environments that have hosted runners; it is informational and is not required for merging or publication. The tracked bootstrap prints the complete intended branch policy without changing GitHub by default:

```bash
scripts/configure_branch_protection.sh
```

After the local result and policy have been reviewed, a repository administrator can apply it explicitly with `GH_TOKEN` set:

```bash
scripts/configure_branch_protection.sh --apply
```

The policy deliberately has no required hosted status checks. It still enforces protected main, linear history, conversation resolution, and rejects force pushes and branch deletion. The script fails unless it is operating on this exact repository and verifies that hosted status checks remain absent. It is not run by CI and never changes repository settings implicitly.

The supported publisher is local and deliberate. From a clean checkout whose `HEAD` exactly matches canonical protected `main`, first run the non-mutating verification mode:

```bash
scripts/publish_local.sh --verify
```

When a locked intake is ready, publish it explicitly:

```bash
scripts/publish_local.sh --publish
```

The command requires macOS, authenticated `gh` access scoped to this release repository, the required protected-main policy, and GitHub immutable releases. It never reads source-signing keys or the intake deploy key. It selects and extracts intake data in a temporary repository, verifies the archive before expansion, verifies the complete app identity, checks signed source continuity and monotonic version/build history, byte-compares every uploaded asset, and verifies the final release and asset attestations. Verification is the default; only `--publish` may create a draft or release.

GitHub Actions remains an optional manually dispatched mirror that calls this exact script. It is not required for local publication and does not own a second release implementation.

An intake is eligible only when its versioned branch points to the same commit as `publication-lock/notebook`; unlocked publication branches fail closed. The producer creates or moves the branch and lock atomically and cannot move a locked candidate until its signed manifest is published byte-for-byte. The publisher reads both refs in one snapshot before work and again immediately before publication.
