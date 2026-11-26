# Baseline classifier: TF-IDF + logistic regression

The reference model every later result is compared against. It reads the v0 dataset,
trains on the train split, and evaluates on dev. The frozen test split is used only
for an agreed final evaluation.

## Commands

From the repo root, with the virtual environment active and the dataset built
(see `data/README.md`):

```
python scripts/run_baseline.py                       # train on train, evaluate on dev
python scripts/run_baseline.py --split test --final  # final evaluation only
```

Without `--final`, the script refuses to touch the test split.

## Configuration

`configs/baseline-v0.json`:

| Setting | Value |
| --- | --- |
| Seed | 42 (logistic regression `random_state`; liblinear solver) |
| Text | subject + decoded text parts, HTML tags removed |
| TF-IDF | word 1–2-grams, `min_df` 2, max 50,000 features, sublinear TF, lowercase |
| Logistic regression | `C` 1.0, class weight balanced, max 1,000 iterations |
| Decision threshold | 0.5 on the phishing probability |
| Target | `is_phishing` |

A new configuration gets a new file and name (`baseline-v1.json`), so earlier results
stay reproducible.

## Keeping development and evaluation data separate

- The model is fitted on **train only**; the TF-IDF vocabulary is learnt from train too.
- **Dev** is for comparing configurations. **Test** is frozen (Month 2) and needs `--final`.
- Before training, the run fails if any id **or group** (template family, sender group,
  near-duplicate cluster) appears in both train and the evaluated split.
- Synthetic records are train-only by construction of `splits-v0.json`, so every
  reported score is on real emails.

## Outputs

`results/baseline/<config name>/<split>/`:

| File | Contents |
| --- | --- |
| `report.md` | Readable summary: metrics with 95% Wilson intervals, confusion matrix, per-category and per-source rates, false positive and false negative ids |
| `metrics.json` | The same numbers, machine-readable |
| `manifest.json` | Seed, full config, split and records SHA-256, split sizes, git commit (and whether the tree had uncommitted changes), Python, platform, package versions, command, time |
| `false_positives.csv` | Legitimate emails flagged as phishing: id, source, category, score |
| `false_negatives.csv` | Phishing emails missed: id, source, category, score |

Outputs contain ids, counts and scores only, never email text, senders or subjects.
Review false positives locally with
`python scripts/label_cli.py <sheet> --by <name> --review --ids <ids>`.

## Results

See [`results/baseline/baseline-v0/dev/report.md`](../../results/baseline/baseline-v0/dev/report.md)
(generated; do not copy numbers here by hand).

## Reading the numbers

- Dev holds about 30 real emails, so intervals are wide; quote counts with rates.
- Categories with only 1–2 dev emails (payment, impersonation, legit_urgent) say
  little on their own; urgency has none.
- `precision` is undefined (`-`) when nothing is predicted as phishing; it is not zero.
- The baseline sees text only: no headers, sender domains, links as structure, or
  attachments. That is deliberate; those signals belong to the evidence checks and the
  LLM analyzer it will be compared with.
- No claim is made beyond the evaluated split and configuration.
- **v0 dev results are inflated by a source shortcut.** All real phishing comes from
  Nazario (2025) and all real legitimate mail from Enron and SpamAssassin (2001–2003).
  `python scripts/inspect_baseline_features.py` shows the model relies largely on source
  identifiers (the Nazario inbox owner's address, "enron", years, a phone code) and on
  synthetic template phrases. Treat v0's dev score as a reproducible reference, not as
  evidence of phishing detection ability. Follow-ups: identifier masking (baseline v1)
  and a dataset without the source/era split (dataset v1).
