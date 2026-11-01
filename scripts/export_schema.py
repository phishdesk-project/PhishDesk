"""Write the EmailRecord JSON Schema so non-Python readers can see the format.

Run from the repo root:  python scripts/export_schema.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishdesk_analysis.records import EmailRecord  # noqa: E402

out = ROOT / "packages" / "contracts" / "schemas" / "email_record.schema.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(EmailRecord.model_json_schema(), indent=2) + "\n", encoding="utf-8")
print(f"Wrote {out}")
