# 0001 – Label taxonomy for the PhishDesk dataset

**Status:** Accepted
**Date:** 2026-10-27
**Proposed by:** Person 2 (AI/ML)
**Reviewer:** Person 1 (Cybersecurity)
**Related issue:** 3

## Context

PhishDesk needs a labeled email dataset for the baseline classifier, the LLM intent analyzer and the benchmark. The plan names six categories: credential, invoice/payment, urgency, impersonation, benign and legitimate-but-urgent. We use these six as single labels, exactly as named in the plan and the dataset issue. Because many phishing emails fit more than one category, a fixed priority order (below) decides which one applies.

## Decision

Every email gets two required label fields and one optional field.

| Field | Allowed values | Rule |
| --- | --- | --- |
| `is_phishing` | `true`, `false` | Ground truth the classifier learns |
| `category` | Phishing: `credential`, `payment`, `impersonation`, `urgency`. Legitimate: `benign`, `legit_urgent` | Exactly one; must match `is_phishing` |
| `tactics` (optional) | `urgency`, `impersonation`, `link_lure`, `attachment_lure`, `qr_code` | Zero or more; fill when obvious, otherwise leave empty |

Two supporting fields record label quality: `label_by` (who labeled) and `label_confidence` (`high`, `medium`, `low`).

**Important:** Safe / Suspicious / Dangerous is the *system's output* (Verdict v1), produced by fusion. It is never a dataset label.

### Priority order for phishing

Check the phishing categories in this order and use the **first** that fits:

1. **credential:** does it want a login, password or MFA code?
2. **payment:** does it want money or payment details?
3. **impersonation:** does it pretend to be a person, brand or service it isn't?
4. **urgency:** otherwise, is pressure the main thing driving it?

Example: a fake IT email asking you to log in within 2 hours fits credential, impersonation and urgency. It is labeled `credential`, because credential is checked first.

### Category definitions

**credential** (phishing)
Tries to get the recipient to enter or confirm a password, MFA code or login, through a link, form or attachment.
- Example: "Your mailbox is full. Verify your account here to keep receiving mail."
- Not this: a real IT notice telling you to change your password through the usual company portal, with no link.

**payment** (phishing)
Tries to get money or payment details: fake invoices, changed bank details, gift cards, wire transfers, advance-fee scams, crypto extortion.
- Example: "Our bank details have changed. Please send this month's payment to the new account below."
- Not this: a genuine invoice from a known supplier with consistent details.

**impersonation** (phishing)
Pretends to be a person, brand or service, with a goal other than login or money: getting a reply, collecting personal information, or getting a file opened.
- Example: "This is DHL. Your parcel is on hold. Open the attached form to reschedule delivery."
- Example: "Hi, it's your manager. Are you at your desk? Reply quickly."
- Not this: a real delivery notice from the expected courier with a tracking number.

**urgency** (phishing)
Phishing with no clear login or money request and no clear impersonation, where pressure is the main lever.
- Example: "FINAL WARNING: open the attached file within 1 hour or your data will be lost."
- Not this: legitimate mail with a deadline (use `legit_urgent`).

**benign** (legitimate)
Ordinary legitimate mail with no unusual time pressure.
- Example: team newsletter, meeting notes, a colleague's question.
- Not this: legitimate mail with a near deadline or stated consequence (use `legit_urgent`).

**legit_urgent** (legitimate)
Real mail from the expected sender with real time pressure (a deadline within about one day, or a stated consequence) but no deceptive or unusual request.
- Example: "Your password expires on Friday. Change it via the usual portal or press Ctrl+Alt+Del."
- Example: "Invoice #4471 from our regular supplier is due today."
- Not this: the same wording from an unrelated domain or with an outside login link (that is phishing).

### Optional tactic tags

| Tactic | Apply when the email… |
| --- | --- |
| `urgency` | Sets a deadline, threatens loss or suspension, or demands immediate action |
| `impersonation` | Pretends to be a known brand, service, colleague, boss or the recipient's own IT/admin |
| `link_lure` | Asks the reader to click a link to act |
| `attachment_lure` | Asks the reader to open an attachment to act |
| `qr_code` | Asks the reader to scan a QR code |

Tags record extra detail that the single category cannot hold (for example `urgency` on a `credential` email). They are not counted in the agreement test.

## Labeling checklist

Answer these five questions for every email, then fill the fields.

1. Who claims to send it, and does the real address match? (Check display name vs address, and Reply-To vs From.)
2. What does it want the reader to do? (Log in, pay, open a file, reply with information, nothing.)
3. Do links go where the text claims?
4. How does it pressure the reader?
5. Would the real sender ever send this?

Questions 1, 3 and 5 decide `is_phishing`. Questions 2, 1 and 4, applied in the priority order, decide `category`.

## Hard-case rules

1. **More than one phishing category fits:** use the priority order (credential, payment, impersonation, urgency).
2. **Delivery method vs goal:** if a link or attachment leads to a login form, the category is `credential`, whatever the subject says (invoice, voicemail, purchase order).
3. **CEO fraud or gift-card request with no link:** `payment`.
4. **Advance-fee, lottery or inheritance email that ends by asking for a fee:** `payment`.
5. **Fake courier or brand with a malware-style attachment** (`.zip`, `.iso`, `.exe`): `impersonation`. If there is no recognizable sender, just pressure: `urgency`.
6. **Non-phishing spam** (ads, newsletters you didn't sign up for): excluded from v1. Do not label it `benign`.
7. **Unreadable or broken email** (empty body, corrupt encoding): excluded; note the ID in the exclusion log.
8. **Language you can't read:** exclude, or set `label_confidence: low` and send to review.
9. **Public dataset label looks wrong** (for example a Nazario email that isn't phishing): set `is_phishing: false`, choose the correct category and explain in the reason column.
10. **Unsure after the checklist:** set `label_confidence: low` and send to the other owner for review. Never guess.

## Consistency rules (enforced by validation)

- `credential`, `payment`, `impersonation`, `urgency` require `is_phishing: true`.
- `benign`, `legit_urgent` require `is_phishing: false`.
- `category` must never be empty; a missing category is an error, never treated as benign.
- `tactics`, when present, must come from the fixed list.

### Results (2026-11-22)

Person 1 independently labelled a seeded random sample of 29 real emails
(`data/labels/review-sample.json`: Nazario 10, Enron 18, SpamAssassin 1).

| Source | Emails | Category agreement | Tactics agreement | Category kappa |
| --- | --- | --- | --- | --- |
| Nazario | 10 | 7 (70%) | 5 (50%) | 0.27 |
| Enron | 18 | 14 (78%) | 15 (83%) | 0.00* |
| SpamAssassin | 1 | 1 | 1 | – |
| **Total** | **29** | **22 (76%)** | **21 (72%)** | |

*Kappa is 0.00 because the second labeller chose one category for all Enron emails;
kappa is unreliable on such unbalanced samples, so counts are reported alongside it.

Disagreements and resolutions:
- Urgency tactic missed on 3 Nazario emails → added an explicit urgency test to the guidelines.
- Credential vs payment/impersonation on 3 Nazario emails → resolved by rule 2 (label by what
  the link or attachment collects).
- legit_urgent vs benign on 4 Enron emails → clarified that legit_urgent needs a deadline
  within about one day or a stated consequence, and always carries the urgency tactic.

All 9 disagreements were resolved by discussion and the labels corrected. The 76% figure is
below the 85–90% target; with only 29 emails each disagreement moves it by about 3 points,
and the rule clarifications above address its causes.

## Consequences

- Labels match the categories named in the plan and the dataset issue directly.
- `impersonation` and `urgency` will have fewer examples, because they come last in the priority order.
- When tactic tags are filled, the Month 2 LLM intent analyzer (credential/payment request, urgency, impersonation) can still be measured on them.
- Verdict v1 reasons can reference the category.
- Changing this taxonomy later requires a new decision record and relabeling affected records.

## Open questions

- [ ] Should tactic tags become required in a later version?
- [ ] Should non-English emails be included in v1, and in which languages?

## Approval

- [x] Person 1 approved on: 2026-11-23