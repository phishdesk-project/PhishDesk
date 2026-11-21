# Labels

`<source>.csv` files here are **committed**. They hold only ids, file hashes,
labels and a hashed sender group: no senders, subjects, reasons or email text.
They are produced by `scripts/export_labels.py` from work sheets.

`work/` holds the labelling sheets with real senders and subjects. It is
gitignored and must never be committed.

Rules for labelling are in `docs/decisions/0001-label-taxonomy.md`.
Always fill the `urgency` and `impersonation` tactics when they apply.
