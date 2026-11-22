# Dataset design (v0)

How the PhishDesk dataset is built and why. Label definitions are in
[`docs/decisions/0001-label-taxonomy.md`](../decisions/0001-label-taxonomy.md); current
counts are in [`composition.md`](composition.md).

## Goals

1. Ground truth for measuring the baseline classifier and the LLM analyzer, so no
   result is claimed without measurement.
2. Dev and test sets that reflect real mail, including legitimate-but-urgent mail,
   where false alarms are most likely.
3. Full provenance and licence for every record; no private data in the repository.
4. A rebuild from a fresh clone that reproduces the same dataset or fails loudly.

## Record format

Each record is an `EmailRecord` (`src/phishdesk_analysis/records.py`), validated by
Pydantic, with a JSON Schema export. Key fields:

| Field | Purpose |
| --- | --- |
| `id`, `source`, `source_ref` | Identity and exact provenance |
| `licence`, `redistributable` | What may be published |
| `date`, `language` | Time-separated and language checks in later months |
| `template_family` | Group key that keeps related emails in one split |
| `is_phishing`, `category`, `tactics` | Labels |
| `label_by`, `label_confidence` | Audit trail |
| `raw_path` | Local path of the email file |

Consistency rules (a phishing category requires `is_phishing: true`, a missing category
is an error, sources must be registered) are enforced by the model and tested.

## Sources

Registered in `data/sources.json` with status, licence, attribution and SHA-256 per
file. Download scripts refuse sources that are not approved, refuse files without a
recorded hash, and delete files whose hash does not match. Archive extraction rejects
absolute paths, `..` and links.

- **Nazario 2025:** real phishing. Split from mbox into one `.eml` per message,
  numbered in file order.
- **Enron:** real legitimate mail. Inbox messages are sampled from the archive with a
  fixed seed into an "urgent" bucket (time-pressure words) and an "other" bucket.
- **SpamAssassin ham:** real legitimate mail, sampled with a fixed seed.

## Synthetic generator

`src/phishdesk_analysis/generator.py`, configured by `data/generator/brands.json` and
`families.json`.

- Invented brands and organisation; reserved domains only (`example.com/org/net`,
  `*.example`, `*.test`). Every email carries an `X-PhishDesk-Synthetic` header.
- 18 template families, three per category; one per category is held back for the
  Month 7 fresh test set.
- Deterministic: the same family, generator version and seed give byte-identical output.
- Duplicate texts are skipped while generating, so requested counts survive
  deduplication.
- Attachments are inert text with no scripts or links.
- Tests fail on any non-reserved domain or real brand name in templates or output.

## Labelling pipeline

1. `make_label_sheet.py` writes a local sheet with senders and subjects (gitignored).
2. `label_cli.py` shows each email as safe text (links defanged, control characters
   removed, attachments named but never opened), records labels, and skips exact
   duplicates of emails already labelled.
3. `export_labels.py` validates every row against the email's SHA-256 and the record
   rules, then writes the committed labels file with ids, hashes, labels and a hashed
   sender group only.

## Building and splitting

`build_dataset.py` joins committed labels with the verified local emails and the
synthetic records, then:

1. **Deduplicates:** exact duplicates (same normalised subject and text) are dropped;
   near-duplicates (word-shingle similarity of at least 0.9) are merged into one group.
2. **Groups:** synthetic records by template family; real emails by hashed sender
   address. Sender address rather than domain, because nearly all Enron senders share
   one domain and phishing often spoofs the recipient's own domain.
3. **Splits:** synthetic records go to train only. Real email groups are assigned,
   largest first, to the split furthest below its 70/15/15 share for that group's
   category. A group never spans two splits. Seed 42.

Dev and test therefore contain only real emails. Synthetic data augments training but
is never used to report a score, because a model can learn template wording and score
unrealistically well on it.

## Composition report

`dataset_stats.py` writes `docs/data/composition.md`: counts by category, split, source
and tactic, licences, label confidence, input file hashes, and warnings for thin
categories or empty splits. Numbers in the docs are taken from it, never typed by hand.

## Freezing the test set

The Month 2 plan hashes and freezes the test split. The SHA-256 of
`data/splits/splits-v0.json` in the composition report identifies it. After freezing,
the test split is never used for tuning; changes to the data produce a new split version.
