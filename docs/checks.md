# Check reference

A completed inspection reports **ten** checks, in the order the protocols run. Each carries a status, an optional reason code, a human-readable detail, and the evidence behind it.

This page says what each one **proves** — and, more importantly, what it **does not**. A check that is understood as proving more than it does is worse than no check at all.

An eleventh, `secure-messaging.integrity`, appears only when a MAC fails. It is not reported on a healthy session because there is nothing to say: every command was protected and every response verified, which the access-control check already establishes.

## Statuses

Five, deliberately. Collapsing them into a boolean is how a tool stops being auditable and starts training its operator to ignore it.

| Status | Meaning |
| --- | --- |
| `Passed` | The check was performed and the document satisfied it. Never reported without evidence — the type system enforces this. |
| `Failed` | The check was performed and the document did not satisfy it. This is a statement about the document. |
| `Inconclusive` | The check could not reach a verdict. **This is a statement about the inspector, not the document** — most often a missing trust anchor. |
| `NotApplicable` | The document does not offer this protocol, or lacks the data group it needs. A passport without DG15 does not support Active Authentication; that is a fact about the document, not a defect. |
| `Unavailable` | MRTDScope cannot perform this check at all. Only Terminal Authentication, permanently. |

`Inconclusive` and `NotApplicable` are not failures, and the report never converts them into one.

## Access control

### `access-control.bac`

Basic Access Control: a challenge-response over 3DES using keys derived from the MRZ, establishing an encrypted and MAC-protected session.

**Proves** the terminal knew the document number, date of birth and date of expiry — that is, had physical access to the data page.

**Does not prove** anything about the chip's authenticity. BAC keys derive from printed data, so anyone who has photographed the data page can derive them. Reports `NotApplicable` with `protocol-not-offered` when PACE established the session instead.

### `access-control.pace`

Password Authenticated Connection Establishment with Generic Mapping over elliptic curves, producing AES session keys.

**Proves** the same knowledge as BAC, over a channel with forward secrecy and no offline-guessing weakness.

**Does not prove** chip authenticity either. Preferred over BAC whenever the chip advertises a variant this build can execute.

### `secure-messaging.integrity`

Every command and response after access control carries a MAC, checked on arrival.

**This check only ever reports a failure.** A healthy session produces no entry for it: there is no separate act of verification to report, because the MAC on every single exchange was already checked as a condition of that exchange completing at all. A `Passed` row here would be an eleventh way of saying what `access-control.*` already said.

**Fails** with `secure-messaging-integrity` mid-session if a MAC does not verify.

**The inspection stops there.** A broken channel means nothing further can be read, so the report ends after this check rather than continuing — a corrupted-MAC report carries four checks, not ten with six inconclusive ones appended. Consumers matching on check ids should treat absence as "not reached", not as "passed": read the summary counts, which always describe exactly what was performed.

```
access-control.pace          NotApplicable  protocol-not-offered
access-control.bac           Passed
secure-messaging.integrity   Failed         secure-messaging-integrity
terminal-auth.certificate-chain  Unavailable  credentials-not-held
```

## LDS structure

### `lds.com-sod-consistency`

EF.COM advertises which data groups are present. The Document Security Object lists which are protected. This compares them.

**Proves** nothing was read that the issuer never signed.

**Catches** a data group added to a chip and announced in EF.COM but absent from the security object — content the hash check is structurally blind to, because it can only compare what the security object actually lists. Fails with `unsigned-content`.

### `lds.card-access-authenticity`

EF.CardAccess tells a terminal which access protocols the chip supports. It is **unsigned** and readable before any authentication. DG14 carries the same information and *is* covered by the security object. This compares them.

**Catches** a protocol downgrade: an attacker who can present a modified EF.CardAccess strips the strong PACE variant, leaving a weaker one the terminal then negotiates in good faith.

**What makes it necessary** is that nothing else sees it. The weaker session is cryptographically sound, mutual authentication succeeds, and every Passive Authentication check passes — because the document's *signed* content is genuinely untouched.

**It cannot prevent the downgrade.** By the time DG14 is readable the session has already been negotiated. The check is retrospective by nature; it reports that a downgrade occurred. Fails with `protocol-downgrade`.

## Passive Authentication

Three independent checks. All three matter, and reporting them separately is the point.

### `passive-auth.sod-signature`

The CMS signature over the LDS Security Object, verified under the Document Signer certificate embedded in the document.

**Proves** the security object is intact and was signed by the key in that certificate.

**Does not prove** that certificate is trustworthy — that is the next check. Verified against the signer's public key directly, so an expired certificate does not make a valid signature report as invalid. Signature validity and certificate validity are different questions and are answered separately.

### `passive-auth.document-signer-chain`

The Document Signer chained to an operator-supplied CSCA trust anchor, with validity periods checked.

**Proves** the issuing authority's certificate chain is intact and current.

**Reports `Inconclusive`** with `no-trust-anchor` when no anchors are configured — MRTDScope ships none (see [Trust anchors](#trust-anchors)). That is not a failure and must not be read as one.

**No revocation checking.** CRL and OCSP are not implemented, so a Document Signer revoked after issue still chains successfully. This is a real gap, stated rather than hidden.

### `passive-auth.data-group-hashes`

Every data group read from the chip is hashed and compared against the value in the signed security object, and reported **per group**.

**Proves** the content read matches what the issuer signed.

**This is the check that detects a substituted portrait.** Verifying the SOD signature and the certificate chain without this one leaves a chip whose DG2 has been replaced passing every check. Fails with `hash-mismatch`, naming each group that differs.

**Does not prove the chip is genuine.** A byte-for-byte clone onto a blank chip passes all three Passive Authentication checks completely. Closing that gap is what the next two checks are for.

## Chip authenticity

### `active-auth.challenge-response`

The terminal generates a nonce; the chip signs it with a private key whose public half is in DG15, using ISO/IEC 9796-2 Digital Signature Scheme 1 with message recovery.

**Proves** the chip holds a private key it cannot export — so it is the original silicon, not a copy of its data.

**Why message recovery matters**: the scheme folds the terminal's challenge into the recovered message, binding the response to *this* session. A signature captured from an earlier session verifies under DG15 perfectly but does not bind to the current nonce, and is rejected.

**Does not prove** the key is the issuer's — DG15 is covered by the security object, so that assurance comes from the hash check. If DG15 were tampered with, the hashes fail first.

**Reports `NotApplicable`** with `data-group-absent` when the document has no DG15. Many do not.

### `chip-auth.key-agreement`

Ephemeral-static Diffie-Hellman against the static public key in DG14, after which secure messaging restarts on the newly agreed session keys.

**Proves** the same thing as Active Authentication — possession of a non-exportable private key — and additionally re-establishes the channel on keys that no longer derive from the MRZ.

**Reports `NotApplicable`** with `protocol-not-offered` when DG14 carries only PACE information and no Chip Authentication parameters.

## Extended Access Control

### `terminal-auth.certificate-chain`

Always `Unavailable`, with reason `credentials-not-held`.

Reading DG3 fingerprints and DG4 iris data requires an Inspection System certificate chain issued by a country's Document Verifier. MRTDScope cannot legitimately hold one. The path is reported rather than omitted, and it is **not stubbed as successful**.

This is a permanent boundary, not an unfinished feature.

## Trust anchors

MRTDScope ships no CSCA certificates and no master list. Trust material is operator-supplied, typically extracted from the ICAO Public Key Directory.

Without anchors, `passive-auth.document-signer-chain` is `Inconclusive` and everything else still runs. Check what actually loaded before an inspection:

```bash
dotnet run --project src/MRTDScope.Cli -- trust ./trust
```

Files that are not X.509 certificates are skipped, so a directory of CRLs or archives yields nothing — which is worth discovering before a read rather than during one.

## What no check reports

There is no overall verdict, on any surface. The report ends with counts per status and stops there.

"Is this passport genuine?" is not a question a chip can answer on its own, and flattening eleven checks into one accept/reject line discards exactly the information an operator needs to act. A test asserts that no surface ever prints one.
