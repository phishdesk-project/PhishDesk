"""Terminal labelling tool: label emails one by one, saving after each answer.

Usage (from the repo root, venv active):
  python scripts/label_cli.py nazario --by person2
  python scripts/label_cli.py nazario --by person2 --search invoice
  python scripts/label_cli.py nazario --by person2 --review      # revisit labelled rows
  python scripts/label_cli.py nazario --by person2 --review --ids nazario-2025-0042,...

Works on data/labels/work/<sheet>.csv (create it with make_label_sheet.py first).
Keys: 1-6 category, s skip, b back, m more text, q quit.
Emails are shown as text only; links are defanged and nothing is opened.
"""

import argparse
import copy
import sys

from _common import RAW_PUBLIC, WORK_DIR

from phishdesk_analysis.labelling import (
    CATEGORY_KEYS,
    CONFIDENCE_KEYS,
    WorkSheet,
    apply_label,
    apply_skip,
    check_reason,
    content_key,
    describe_email,
    full_body,
    missing_key_tactics,
    parse_tactics,
    sheet_source,
)
from phishdesk_analysis.records import Category

TARGETS = {
    "nazario": {"credential": 44, "payment": 36, "impersonation": 20, "urgency": 20},
    "spamassassin": {"benign": 90},
    "enron-urgent": {"legit_urgent": 30, "benign": 0},
    "enron-other": {"benign": 90},
}
MENU = "  ".join(f"{k}={c.value}" for k, c in CATEGORY_KEYS.items())


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return "q"


def progress(sheet: WorkSheet, targets: dict[str, int]) -> str:
    counts = sheet.counts()
    parts = [f"{c} {counts[c]}/{t}" if t else f"{c} {counts[c]}" for c, t in targets.items()]
    others = {c: n for c, n in counts.items() if c not in targets}
    parts += [f"{c} {n}" for c, n in sorted(others.items())]
    return " | ".join(parts) + f" | skipped {sheet.skipped()}"


def label_one(row: dict[str, str], category: Category, label_by: str) -> bool:
    """Ask tactics, confidence and reason. Returns False if the user cancels."""
    while True:
        keys = ask("Tactics u=urgency i=impersonation l=link a=attachment r=qr (Enter=none): ")
        try:
            tactics = parse_tactics(keys)
        except ValueError as exc:
            print(f"  {exc}")
            continue
        if missing_key_tactics(category, tactics):
            again = ask("  Phishing without urgency or impersonation. Correct? [y/N]: ")
            if again.lower() != "y":
                continue
        break
    while True:
        key = ask("Confidence h/m/l (Enter=high): ").lower()
        if key in CONFIDENCE_KEYS:
            confidence = CONFIDENCE_KEYS[key]
            break
        print("  use h, m or l")
    while True:
        reason = ask("Reason, no names or domains (Enter to leave empty): ")
        problem = check_reason(reason)
        if not problem:
            break
        print(f"  {problem}")
    apply_label(row, category, tactics, confidence, label_by, reason)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sheet", help="work sheet name, e.g. nazario or enron-urgent")
    parser.add_argument("--by", required=True, help="your labeller name, e.g. person2")
    parser.add_argument("--search", help="only emails whose subject contains this text")
    parser.add_argument("--ids", help="only these ids, comma-separated")
    parser.add_argument("--review", action="store_true", help="include already labelled rows")
    parser.add_argument(
        "--keep-duplicates", action="store_true", help="show emails identical to earlier ones"
    )
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    path = WORK_DIR / f"{args.sheet}.csv"
    if not path.exists():
        print(f"ERROR: {path} not found. Run make_label_sheet.py first.")
        return 1
    sheet = WorkSheet(path)
    source = sheet_source(args.sheet)
    emails_dir = RAW_PUBLIC / source / "emails"
    targets = TARGETS.get(args.sheet, {})
    ids = {i.strip() for i in args.ids.split(",") if i.strip()} if args.ids else None
    queue = sheet.queue(args.search, args.review, ids)
    if not queue:
        print("Nothing to label with these settings.")
        return 0

    # Emails already labelled or skipped claim their content first.
    seen: dict[str, str] = {}
    if not args.keep_duplicates:
        for r in sheet.rows:
            done = r.get("category") or (r.get("reason") or "").startswith("skip:")
            if done and not (r.get("reason") or "").startswith("skip: duplicate"):
                seen.setdefault(content_key((emails_dir / r["file"]).read_bytes()), r["id"])
    auto_skipped = 0

    history: list[tuple[int, int, dict[str, str]]] = []  # (queue pos, row index, old row)
    pos = 0
    while pos < len(queue):
        idx = queue[pos]
        row = sheet.rows[idx]
        data = (emails_dir / row["file"]).read_bytes()
        if not args.keep_duplicates and not args.review:
            key = content_key(data)
            if key in seen and seen[key] != row["id"]:
                apply_skip(row, args.by, f"duplicate of {seen[key]}")
                sheet.save()
                auto_skipped += 1
                pos += 1
                continue
        print("\n" + "=" * 70)
        print(f"[{pos + 1}/{len(queue)}] {row['id']}   {progress(sheet, targets)}")
        if row.get("category") or row.get("reason"):
            print(
                f"Current: {row.get('category') or '-'} | {row.get('tactics')} | "
                f"{row.get('label_confidence')} | {row.get('reason')}"
            )
        print("=" * 70)
        print(describe_email(data))
        print()
        key = ask(f"{MENU}\n  s=skip  b=back  m=more  n=next (leave as is)  q=quit: ").lower()

        if key == "q":
            break
        if key == "m":
            print(full_body(data))
            ask("-- press Enter to continue --")
            continue
        if key == "n":
            pos += 1
            continue
        if key == "b":
            if not history:
                print("  nothing to undo")
                continue
            pos, back_idx, old = history.pop()
            sheet.rows[back_idx] = old
            sheet.save()
            continue
        before = copy.deepcopy(row)
        if key == "s":
            why = ask("Skip reason (e.g. spam, newsletter, personal, unreadable): ")
            apply_skip(row, args.by, why)
        elif key in CATEGORY_KEYS:
            label_one(row, CATEGORY_KEYS[key], args.by)
        else:
            print("  unknown key")
            continue
        sheet.save()
        history.append((pos, idx, before))
        if not args.keep_duplicates:
            seen.setdefault(content_key(data), row["id"])
        pos += 1

    if auto_skipped:
        print(f"\nSkipped {auto_skipped} duplicate(s) of emails you already labelled.")
    print(f"\nSaved to {path}\n{progress(sheet, targets)}")
    if args.sheet.startswith("review-"):
        print(
            f"Next: python scripts/label_agreement.py data/labels/{source}.csv "
            f"data/labels/work/{args.sheet}.csv --show"
        )
    else:
        print(f"Next: python scripts/export_labels.py {source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
