# Data sources register

The machine-readable register is `data/sources.json`. Scripts and tests read it;
this page explains it. Change both together, in one reviewed PR.

## Status values

| Status | Meaning |
| --- | --- |
| `approved` | Licence checked and allows our use; raw data may be redistributed (we still don't commit public raw files that contain real addresses) |
| `approved-local` | No explicit licence, but both owners agreed it may be used locally for research. Raw data is never committed or redistributed; only labels are |
| `pending` | Not decided yet. Download scripts refuse to fetch it |
| `do-not-use` | Rejected. Records from it fail validation |

A source moves to `approved` or `approved-local` only when **both owners** agree,
recorded in `decided_by` and in the decision log below.

## Sources

| ID | Contains | Licence | Redistributable | Status |
| --- | --- | --- | --- | --- |
| `synthetic` | Phishing and legitimate, invented | Apache-2.0 (project) | Yes | approved |
| `nazario` | Phishing | CC-BY-4.0 (publisher README) | Yes, with attribution | approved |
| `spamassassin` | Legitimate (easy_ham, hard_ham) | No explicit licence | No | approved-local |
| `enron` | Legitimate business mail | No explicit licence | No | approved-local |

### Nazario phishing corpus
- **Where:** https://monkey.org/~jose/phishing/ (one mbox file per year; we use `phishing-2025`)
- **Licence:** CC-BY-4.0, stated in the publisher's README.txt. Attribution required.
- **Known issues:** one person's inbox, so representative rather than exhaustive; hand-classified and may contain errors; recent years are not anonymized.
- **Our handling:** raw files stay in `data/raw/public/nazario/` (gitignored). Only labels are committed.
- **Attribution:** Jose Nazario, Nazario Phishing Corpus, https://monkey.org/~jose/phishing/ (CC-BY-4.0).

### Apache SpamAssassin public mail corpus
- **Where:** https://spamassassin.apache.org/old/publiccorpus/ (`20030228_easy_ham`, `20030228_hard_ham`)
- **Licence:** none stated. The readme says the messages were posted to public fora or donated by individuals; some addresses are obfuscated.
- **Known issues:** 2002–2003 mail; spam folders are spam, not phishing, so we don't use them.
- **Handling:** `approved-local` (local research use, labels only committed).

### Enron email dataset
- **Where:** https://www.cs.cmu.edu/~enron/ (`enron_mail_20150507.tar.gz`)
- **Licence:** none stated. Released publicly by FERC; CMU distributes it as a research resource and asks users to be sensitive to the privacy of the people involved. Some messages were removed at employees' request.
- **Known issues:** real people's mail; 1999–2002; no attachments.
- **Handling:** `approved-local` (local research use, labels only committed). Never quote email content in issues, PRs or reports.


## Decision log

| Date | Source | Decision | Decided by | Reason |
| --- | --- | --- | --- | --- |
| 2026-10-31 | nazario | approved | Person 1, Person 2 | CC-BY-4.0 stated by the publisher; attribution recorded |
| 2026-10-31 | spamassassin | approved-local | Person 1, Person 2 | Widely used research corpus; no licence stated, so local use only, labels committed, raw emails never redistributed |
| 2026-10-31 | enron | approved-local | Person 1, Person 2 | Public FERC release distributed by CMU for research; local use only, labels committed, no email content quoted anywhere |

## File hashes

Every downloadable file has a SHA-256 in `data/sources.json`. The first maintainer
to download a file runs `python scripts/download_sources.py <id> --record` and
commits the hash. Everyone else gets an error if their download differs.
