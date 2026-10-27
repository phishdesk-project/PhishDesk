# C02 synthetic MIME parsing

`phishdesk.parsing.parse_eml(data, case_id=UUID(...))` and
`parse_eml_file(Path(...), case_id=...)` return the existing `EvidenceV1` model.
Source is always `synthetic`; this is not mailbox intake. No schema, mock API,
authentication decision, verdict or remediation behavior changes.

The MIME tree is traversed iteratively. Only bounded header blocks are handed to
the standard library's compat32 header parser, avoiding whole-message recursive
parsing and the address headerregistry grammar. Multipart delimiters are matched
as complete lines; incomplete final parts are omitted with a missing state.

| Resource | Default hard ceiling |
| --- | --- |
| Input message / file read | 2 MiB / at most 2 MiB + 1 byte |
| Header block / physical line / count per part | 32 KiB / 4096 bytes / 100 |
| MIME nodes / nesting depth | 100 including root / 8 below root |
| Encoded leaf payload | 512 KiB before transfer decoding |
| Aggregate decoded payload | 2 MiB (nested message bytes count again) |
| Body projection | 100,000 UTF-8 bytes across plain and HTML parts |
| Attachments / URL strings | 20 / 200 |
| URL / filename / subject and sender | 4096 / 255 / 1000 characters |
| Wall time | 5 seconds, including worker startup |

`ParseLimits` permits lower positive ceilings only. Base64 is strict; malformed
quoted-printable and unknown transfer encodings are omitted. Supported charsets
are UTF-8, ASCII, ISO-8859-1 and Windows-1252 aliases listed in the worker.
Unknown charset falls back to UTF-8 with a missing state; invalid bytes use
replacement characters. No decompression, archive or image parsing takes place.

Public parsing uses a fresh subprocess with a timeout. On expiration Python kills
and waits for the worker; no partial result is accepted. The worker also checks a
monotonic deadline between operations. Byte/count/depth bounds constrain memory
and work, including pending siblings. There is no OS memory quota or security
sandbox claim. File callers must supply a regular local file; the worker deadline
covers parsing, not a blocked filesystem read or already allocated caller input.
Concurrent-call admission control belongs to future intake, not this offline API.

Subject, From and Reply-To are decoded untrusted display strings, not verified
addresses. Duplicate identity or MIME control headers reject that part. Forged
Authentication-Results never produce trusted authentication signals. Plain and
HTML alternatives are concatenated in MIME order. HTML is projected to inert text
with script/style text suppressed; href/src/action HTTP(S) strings and visible
plain-text URLs are deduplicated. This is neither browser sanitization nor
canonicalization, URL validation or a complete HTML/URL extractor. Consumers must
escape all returned fields. Nothing resolves DNS or visits URLs.

Attachments, including inline images, get display-only basename, exact decoded
byte length and SHA-256 only when the entire payload fits and decodes. Rejected
payloads are omitted with explicit missing states; a partial hash/size is never
presented as complete. No attachment is written, opened or executed. Attached
multipart containers are explicitly unsupported; inline message/rfc822 is
traversed within the same limits. Media type remains internal because v1 has no
attachment type field. No incompatible field is added for HTML, QR or headers.

Every result records `authentication.not_checked`, `sandbox.not_run`, `qr.not_run`.
QR extraction is deferred: safely bounding image dimensions, native decoder
resources and dependencies is outside this change. Thus the QR portion of Issue
#8's original acceptance remains unfulfilled unless both owners accept this cut.
Inline-image fixtures prove metadata extraction only.

Static `missing_evidence` codes record limits (`parser.message_bytes`, `parts`,
`depth`, `body_bytes`, `part_bytes`, `decoded_bytes`, `attachments`, `links`),
header/boundary/charset/transfer defects and absent fields. `parser.timeout`,
`parser.worker_failed`, `parser.malformed` return no attacker text on whole-worker
failure. Truncation/omission never means safe. Findings remain empty. No content,
filename, URL, exception or traceback is logged. The fixture demo emits only
numeric counts and static codes; Evidence itself intentionally contains content.

Run `python -m phishdesk.parsing.demo tests/fixtures/mime` and the normal README
checks. Tests validate all 20 fixtures through the public worker and contract,
with generated malformed/nested/oversized/count/timeout regressions. C01 is closed;
S02 (#7) remains open. This implementation consumes its existing draft interface
unchanged under the user's explicit continuation request. Rishitha's review of
that handoff, this PR and the QR cut remains required before merge/Issue #8 closure.
