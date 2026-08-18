# MRTDScope

**A cross-platform eMRTD inspection instrument.** It reads an electronic passport over a PC/SC contactless reader or Android NFC, executes the ICAO Doc 9303 security protocols, and reports every security check as an individually named assertion with its outcome, reason, and evidence.

> **Status: early development.** The inspection vocabulary and project scaffold are in place; the protocol implementations land milestone by milestone. Run `mrtdscope` to see exactly what this build can and cannot do — it reports its own capability posture honestly, and every unimplemented path says so.

## Why another passport reader

There are two kinds of eMRTD tooling and neither is satisfying.

Commercial inspection products are closed and licensed. They return a verdict you cannot audit. Open implementations — JMRTD and the samples built on it — read the chip competently but stop at extraction; the published examples display a photo and a name, and their verification story is a boolean at best.

Neither kind demonstrates its own **rejection behavior**. No open reader ships evidence that it detects a tampered data group, a substituted Document Signer, an expired trust anchor, or a corrupted MAC.

A verification tool that has never been shown to reject anything is an assertion, not an instrument.

MRTDScope is built the other way around. Its differentiating deliverable is a synthetic eMRTD and a fault-injection corpus that prove, in CI on every commit, that the inspection chain detects each forgery class **and names the right failing check** — with no hardware and no real document data anywhere near the repository.

## Design rules

Three rules shape the codebase.

**No check reports success without performing it.** This is enforced by the type system, not by convention. `InspectionCheck` has no public constructor, and the only route to a passing result requires evidence:

```csharp
// Compiles, and throws: a check that observed nothing has verified nothing.
InspectionCheck.Passed(CheckIds.PassiveAuthSodSignature, "SOD signature verified.");

// The only way to pass.
InspectionCheck.Passed(
    CheckIds.PassiveAuthSodSignature,
    "SOD signature verified under the embedded Document Signer.",
    Evidence.Of("algorithm", "SHA256withRSA"),
    Evidence.Of("signer-serial", "0x2A17"));
```

**"Cannot verify" is not "verification failed."** Five statuses, deliberately: `Passed`, `Failed`, `Inconclusive`, `NotApplicable`, `Unavailable`. A missing trust anchor is `Inconclusive` — that is a statement about the inspector, not the document. Collapsing these into a boolean is how a tool stops being auditable and starts training its operator to ignore it.

**Passive Authentication means the data-group hashes too.** Verifying the SOD signature and chaining the Document Signer to a CSCA is not enough. Without hashing every data group read from the chip against the LDS Security Object, a substituted portrait passes silently. All three sub-checks are reported independently.

## What it verifies

| Check | Status |
| --- | --- |
| Basic Access Control | M1 |
| Passive Authentication — SOD signature | M2 |
| Passive Authentication — Document Signer chain | M2 |
| Passive Authentication — data-group hashes | M2 |
| Fault-injection corpus | M3 |
| PACE (Generic Mapping, ECDH, AES) | M4 |
| Active Authentication (ISO/IEC 9796-2 DS1) | M5 |
| Chip Authentication | M5 |
| Terminal Authentication / EAC | **Never** — see below |

## What it does not do

These are boundaries, stated as plainly as the capabilities.

- **It never writes to a chip.** No personalization, no applet loading, no key injection, no locking. MRTDScope is read-only against real documents, permanently.
- **It is not forgery tooling.** Fault injection operates exclusively on synthetic documents MRTDScope generates itself, to prove detection.
- **It ships no trust anchors.** No CSCA certificates, no master list. Trust material is operator-supplied, and its absence is reported as `Inconclusive`.
- **No Extended Access Control.** Reading DG3 fingerprints requires a country-issued Inspection System certificate chain that this project cannot legitimately hold. The path reports `Unavailable` with a reason code. It is not stubbed as successful.
- **No iOS.** eMRTD reading on iOS needs a macOS build host and an Apple-granted NFC entitlement. A licensing and hardware wall, not an unfinished feature.
- **No biometric matching.** Portraits are extracted and displayed; there is no face comparison and no identity verification.
- **Not a certified conformance suite**, and no claim of accreditation.

## Building

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```bash
dotnet build MRTDScope.slnx
```

```bash
dotnet test MRTDScope.slnx --filter "Category!=Hardware"
```

The full suite runs with no reader, no chip, and no network. Hardware-dependent tests are trait-gated and skipped by default; they require a PC/SC reader and a document you are entitled to read.

```bash
dotnet run --project src/MRTDScope.Cli
```

## Layout

| Path | Purpose |
| --- | --- |
| `src/MRTDScope.Core` | Protocols, LDS parsing, verification, report model. No UI, no transport specifics. |
| `src/MRTDScope.Cli` | Headless inspection emitting the JSON report. |
| `tests/MRTDScope.Core.Tests` | The full suite, including the fault corpus from M3. |

The Android head arrives at M6 and the desktop application at M7, each created at its own milestone rather than sitting unused.

## Privacy

No real MRZ, chip dump, portrait, certificate, or key from any genuine document enters this repository, its history, its documentation, or any published artifact. Test PKI material is generated at run time and never committed. APDU traces redact secure-messaging key material.

## Licence

[MIT](LICENSE). MRTDScope vendors no third-party source and bundles no certificate or key material.
