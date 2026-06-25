# Security policy

## Reporting a vulnerability

Email **security@octetproof.com** with details and, if possible, a reproduction.
Please do not open public issues for security reports.

## Trust model

`octet-attest-verify` is a **verification** library: it consumes attestation
evidence and produces a verdict. It holds no signing key and creates no proofs.

- The **App Attest** layer (default build) is offline and anchored to Apple's
  published App Attest root certificate, embedded in the crate. It makes no
  network calls and reads no credentials. A change to that embedded root is a
  security-relevant change and is called out in the changelog.
- The **Play Integrity** layer (`--features playintegrity`) decodes tokens using
  credentials the caller supplies for their own Google Play Console project. The
  library never embeds or transmits those credentials; the caller is responsible
  for storing them securely (never in source control).

## Scope

In scope: incorrect verdicts (accepting forged/expired/replayed evidence,
rejecting valid evidence), certificate-chain validation flaws, parsing panics on
adversarial input.

Out of scope: the security of the device-side attestation itself (that's
Apple's / Google's), and the secrecy of credentials the caller provides.
