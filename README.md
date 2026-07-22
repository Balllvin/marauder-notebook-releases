# Marauder Notebook downloads

This repository is the public distribution boundary for Marauder Notebook. It contains no application source code and has no write deploy key. Release candidates arrive as inert Git data in a separate Actions-disabled intake repository; only the reviewed publisher on this repository's protected `main` can turn one into a release.

## Download and open

Download the current app from [Releases](https://github.com/Balllvin/marauder-notebook-releases/releases/latest), move **Marauder Notebook** to Applications, and open it. Neither downloading nor using the app requires an Apple account, an Apple Developer membership, Xcode, or terminal commands.

The independent build is signed under Marauder's pinned non-Apple private certificate authority, so updates keep one stable, certificate-bound app identity without requiring Apple membership. Because Apple has not notarized this independent build, macOS cannot associate the first launch with an Apple-registered developer. If macOS blocks it:

1. In Finder, Control-click **Marauder Notebook** and choose **Open**, then confirm **Open**; or
2. Open **System Settings → Privacy & Security**, find the blocked-app message, choose **Open Anyway**, and confirm.

This is a one-time choice for that app. Marauder sign-in is the only product account flow. Later updates are installed by the app from the signed update feed.

## Release integrity

Every published release includes:

- the independently signed universal macOS app archive;
- its SHA-256 checksum;
- the Sparkle update feed;
- immutable release provenance; and
- the committed update-trust manifest.

The default publishing policy requires no Apple credentials. Before publication it verifies that:

- the main app and every nested Mach-O are signed by one release certificate under the pinned Marauder private-CA root with no Apple team identifier;
- every Mach-O carries its exact identifier-and-root-bound designated requirement;
- every executable retains Hardened Runtime; the main app has only the narrow library-validation exception required to load Sparkle without an Apple-issued identity;
- independent signatures do not depend on Apple timestamp services, and every nested executable has exactly the producer-approved entitlement set;
- the app, every nested executable, and every framework are universal `arm64` and `x86_64` code;
- the exact bundle identity, version, build, update key, feed URL, deep link, sandbox, file, network, and microphone entitlements match the protected contract;
- the archive checksum, Sparkle Ed25519 archive signature, signed appcast, and signed provenance all validate against the committed public key;
- the intake contains exactly the five approved immutable files, points to an exact Marauder source commit, and links to the source commit in the latest signed immutable release; and
- the version and build number are newer than every published release.

Unsigned, plain ad-hoc, mixed-certificate, Developer ID, wrong-team, wrong-requirement, tampered, unsealed, thin, relabeled, malformed, mutable, or incompletely signed candidates fail closed. The Ed25519 signing key remains mandatory: the publisher never releases an unsigned archive or update feed.

The verifier retains a dormant Developer ID mode for a future, deliberately reviewed policy change. It requires one exact team identifier, Hardened Runtime throughout, a valid notarization ticket, and Gatekeeper acceptance. That path is not enabled or claimed by the current independent policy.

The independent root and release private keys never enter this repository. The offline root is a long-lived release identity and must be backed up securely; an authorized local producer receives only a rotating leaf key. Release certificates may rotate under that root without changing the root-pinned application identity. Replacing the root is an explicit distribution-identity migration.

Independent certificates have no Apple Team Identifier, so Sparkle cannot apply its optional Apple-team policy to XPC client connections and explicitly treats that policy as non-security-critical. The account-free path does not claim that Apple-team check. Update authenticity instead fails closed on the Ed25519-signed feed and archive, and every shipped updater executable is sealed under the pinned Marauder root identity. Enabling the Apple-team policy would require an Apple-issued signing identity.

GitHub immutable releases protect final tags and assets after publication. Every publisher run rechecks the full release history and attestations, downloads the latest release, revalidates all five signed assets, expands the archive, and repeats the complete bundle/signature verification.

Every candidate after the first carries the previous published source commit inside its signed provenance. The publisher downloads the latest immutable manifest, verifies both signatures, and requires an exact link before publication. The private producer separately proves that the candidate source descends from that commit. This prevents a higher version number from republishing older source and rejects candidates emitted by historical workflows that lack the signed continuity field.

## Publisher branch protection

The `main` branch requires the `Verify publisher boundary` commit status. From a separate clean protected-`main` checkout, run its trusted verifier against the exact clean candidate checkout and record the successful result explicitly:

```bash
scripts/verify_publisher_boundary.sh \
  --root /path/to/candidate-checkout \
  --record-status
```

Status recording refuses to run from the candidate checkout. It first proves that the verifier's own checkout is clean, uses the canonical repository, and exactly matches both local and remote protected `main`; only then does it validate and report the candidate commit. Without `--record-status`, the command performs the same compile, shell, OpenSSL, actionlint, and complete test-suite verification without changing GitHub. The optional `.github/workflows/publisher-ci.yml` only reverifies protected `main` after a push or manual dispatch; it has no status-write permission and never executes candidate code. The protected-main local verifier is the sole owner of the required candidate status, so hosted runners are not part of the merge or publication path. The tracked bootstrap prints the complete intended protection policy without changing GitHub by default:

```bash
scripts/configure_branch_protection.sh
```

After a local result has been recorded and the policy has been reviewed, a repository administrator can apply it explicitly with `GH_TOKEN` set:

```bash
scripts/configure_branch_protection.sh --apply
```

The script fails unless it is operating on this exact repository and verifies that the required check was retained. It is not run by CI and never changes repository settings implicitly.

The supported publisher is local and deliberate. From a clean checkout whose `HEAD` exactly matches canonical protected `main`, first run the non-mutating verification mode:

```bash
scripts/publish_local.sh --verify
```

When a locked intake is ready, publish it explicitly:

```bash
scripts/publish_local.sh --publish
```

The command requires macOS, authenticated `gh` access scoped to this release repository, the required protected-main policy, and GitHub immutable releases. It never reads source-signing keys or the intake deploy key. It selects and extracts intake data in a temporary repository, verifies the archive before expansion, verifies the complete app identity, checks signed source continuity and monotonic version/build history, byte-compares every uploaded asset, and verifies the final release and asset attestations. Verification is the default; only `--publish` may create a draft or release.

GitHub Actions remains an optional unattended trigger that calls this exact script. It is not required for local publication and does not own a second release implementation.

An intake is eligible only when its versioned branch points to the same commit as `publication-lock/notebook`; unlocked publication branches fail closed. The producer creates or moves the branch and lock atomically and cannot move a locked candidate until its signed manifest is published byte-for-byte. The publisher reads both refs in one snapshot before work and again immediately before publication.
