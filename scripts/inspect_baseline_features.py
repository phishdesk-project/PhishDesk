"""Print the baseline's most influential terms (local diagnostic; output is not saved).

Usage: python scripts/inspect_baseline_features.py
Terms can include names from real emails, so do not paste the output anywhere public.
"""

from _common import RECORDS_JSONL, ROOT, SPLITS_JSON

from phishdesk_analysis.baseline import build_pipeline, load_config, split_ids
from phishdesk_analysis.corpus import parse_email, plain_text
from phishdesk_analysis.records import load_records
from phishdesk_analysis.stats import load_splits

config = load_config(ROOT / "configs" / "baseline-v0.json")
records = {r.id: r for r in load_records(RECORDS_JSONL)}
train = split_ids(load_splits(SPLITS_JSON), "train")
texts = [plain_text(parse_email((ROOT / records[i].raw_path).read_bytes())) for i in train]
model = build_pipeline(config).fit(texts, [records[i].is_phishing for i in train])

names = model.named_steps["tfidf"].get_feature_names_out()
weights = model.named_steps["clf"].coef_[0]
sign = 1 if list(model.classes_).index(True) == 1 else -1
ranked = sorted(zip(weights * sign, names, strict=True))
print("Most 'legitimate' terms:")
print(", ".join(term for _, term in ranked[:30]))
print("\nMost 'phishing' terms:")
print(", ".join(term for _, term in reversed(ranked[-30:])))
