# Labelling guidelines (v0)

Practical rules for labelling real emails. The authoritative definitions are in
[`docs/decisions/0001-label-taxonomy.md`](../decisions/0001-label-taxonomy.md); if the two
differ, the decision record wins.

## Fields

| Field | Rule |
| --- | --- |
| `category` | Exactly one of credential, payment, impersonation, urgency, benign, legit_urgent |
| `tactics` | Every tag that applies. **Always add `urgency` and `impersonation` when they apply**; `link_lure`, `attachment_lure`, `qr_code` when obvious |
| `label_confidence` | high (obvious), medium (a rule decided it), low (unsure: goes to review) |
| `reason` | One factual line with no names, addresses, domains or file names |

`is_phishing` follows from the category; the labelling tool sets it automatically.

## Five questions for every email

1. Who claims to send it, and does the real address match? (Display name vs address,
   Reply-To vs From.)
2. What does it want the reader to do? (Log in, pay, open a file, reply, nothing.)
3. Do the links go where the text claims?
4. How does it pressure the reader?
5. Would the real sender ever send this?

## Choosing a phishing category: the priority order

Ask in order and stop at the first yes:

| Order | Key | Question | Category |
| --- | --- | --- | --- |
| 1 | `1` | Does it try to get a login, password or code? | credential |
| 2 | `2` | Does it try to get money or payment details? | payment |
| 3 | `3` | Does it pretend to be a person, brand or service? | impersonation |
| 4 | `4` | Is pressure the main thing driving it? | urgency |

Everything else the email does goes into tactics.

| Example | Category | Tactics |
| --- | --- | --- |
| Fake IT: "verify your mailbox within 24 hours" + link | credential | urgency, impersonation, link_lure |
| Invoice whose attachment opens a login page | credential | impersonation, attachment_lure |
| "Our bank details changed, pay here" | payment | impersonation |
| Lottery or inheritance asking for a fee; crypto extortion | payment | urgency |
| Fake courier: "open the attached form" | impersonation | impersonation, attachment_lure |
| Fake boss: "are you free? reply quickly" | impersonation | urgency, impersonation |
| "FINAL WARNING: open the attachment", no sender identity | urgency | urgency, attachment_lure |

Decide by what the email collects, not by its subject.

## Legitimate mail

- **legit_urgent:** a real deadline within about one day, or a stated consequence, from
  the expected sender, with no unusual request. Tactics usually `urgency`.
- **benign:** everything else legitimate.
- Mentions of passwords or links to other domains do not make legitimate mail
  phishing. Internal notices about a partner system, newsletters and forwarded mail
  often link elsewhere; judge by what the email asks the reader to do.

## Skip (leave unlabelled)

- Spam that is not phishing (ads, unwanted newsletters).
- Personal or sensitive messages (health, family, legal or HR matters about individuals).
- Broken, empty or unreadable messages; languages the labeller cannot read.
- Real phishing found inside a legitimate source, unless confidently identified.
- When unsure whether an email is usable at all. A skipped email costs nothing; a
  wrong label weakens the dataset.

Do not force an email into a category to reach a target. Shortfalls are reported as
limitations and topped up with synthetic training data.

## Source notes

| Sheet | Typical answer | Watch for |
| --- | --- | --- |
| `nazario` | credential | Payment and impersonation hide behind generic subjects; search with `--search` |
| `enron-urgent` | benign or legit_urgent | Most "reminder" or "deadline" mentions are not urgent |
| `enron-other` | benign | Personal messages: skip |
| `spamassassin` | benign | Read only sender, subject and first lines; skip if unclear |

## Tool workflow

```
python scripts/make_label_sheet.py nazario
python scripts/label_cli.py nazario --by <name> [--search word] [--review]
python scripts/export_labels.py nazario
```

Keys: `1`–`6` category, `s` skip, `b` undo, `m` more text, `n` leave as is, `q` quit.
Answers are saved after every email. Links are shown defanged; never open
attachments or visit links from real emails.

## Privacy

- Refer to emails by id only in issues, pull requests, chats and reports.
- Labelling sheets (`data/labels/work/`) contain real senders and subjects and are never
  committed. Delete any spreadsheet copies when finished.

## Agreement check

A second labeller independently labels a seeded random sample of about 15% of the real
emails, without seeing the first labeller's answers:

```
python scripts/make_review_sheet.py --by person1
python scripts/label_cli.py review-person1-nazario --by person1
python scripts/label_agreement.py data/labels/nazario.csv data/labels/work/review-person1-nazario.csv --show
```

The sampled ids are recorded in `data/labels/review-sample.json`. Disagreements are
discussed, rules clarified here if needed, and final labels corrected with
`label_cli.py <sheet> --review --ids <ids>` and re-exported.
