"""Pick Enron inbox emails for labelling, straight from the downloaded archive.

Usage: python scripts/find_enron.py --urgent 150 --other 300
Writes data/raw/public/enron/emails/*.eml, index.csv and candidates.json (gitignored).
"""

import argparse

from _common import RAW_PUBLIC

from phishdesk_analysis.corpus import select_enron


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--urgent", type=int, default=150, help="time-pressure candidates")
    parser.add_argument("--other", type=int, default=300, help="ordinary candidates")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    tar_path = RAW_PUBLIC / "enron" / "enron_mail_20150507.tar.gz"
    if not tar_path.exists():
        print("ERROR: run download_sources.py enron first")
        return 1
    print("Scanning the Enron archive (this takes several minutes)...")
    rows = select_enron(tar_path, RAW_PUBLIC / "enron", args.urgent, args.other, args.seed)
    print(f"Selected {len(rows)} emails into data/raw/public/enron/emails/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
