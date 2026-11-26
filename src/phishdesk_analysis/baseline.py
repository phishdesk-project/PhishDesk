"""Reproducible TF-IDF + logistic regression baseline.

Trains on the train split only and evaluates on one other split (dev by default).
The test split is the frozen evaluation set: it is only used when explicitly
requested, and the run records that it did so. Every run writes metrics, a
confusion matrix, false-positive ids and a manifest (seed, config, split and data
hashes, git commit, environment), so any reported number can be traced and rerun.

Outputs hold ids, counts and scores only: no email text, senders or subjects.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import math
import platform
import shutil
import subprocess
import sys
from collections import Counter
from importlib import metadata
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore[import-untyped]
from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]
from sklearn.pipeline import Pipeline  # type: ignore[import-untyped]

from phishdesk_analysis.records import Category, EmailRecord

EvalSplit = Literal["dev", "test"]
PACKAGES = ("scikit-learn", "numpy", "scipy", "pydantic")


class BaselineError(ValueError):
    """Raised when data, splits or configuration make a run invalid."""


class TfidfConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ngram_min: int = Field(1, ge=1)
    ngram_max: int = Field(2, ge=1)
    min_df: int = Field(2, ge=1)
    max_features: int | None = Field(50000, ge=1)
    sublinear_tf: bool = True
    lowercase: bool = True


class LogRegConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    C: float = Field(1.0, gt=0)
    class_weight: Literal["balanced"] | None = "balanced"
    max_iter: int = Field(1000, ge=1)


class BaselineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    seed: int
    threshold: float = Field(0.5, gt=0, lt=1)
    tfidf: TfidfConfig = TfidfConfig()
    logreg: LogRegConfig = LogRegConfig()


def load_config(path: Path) -> BaselineConfig:
    return BaselineConfig.model_validate_json(path.read_text(encoding="utf-8"))


# --- data -----------------------------------------------------------------


def split_ids(splits: dict[str, object], name: str) -> list[str]:
    ids = splits.get(name)
    if not isinstance(ids, list):
        raise BaselineError(f"split '{name}' not found in the split file")
    return [str(i) for i in ids]


def check_separation(
    records: dict[str, EmailRecord], train: list[str], evaluation: list[str], split: str
) -> None:
    """Fail on any id or group shared between train and the evaluation split."""
    shared = set(train) & set(evaluation)
    if shared:
        raise BaselineError(f"{len(shared)} ids are in both train and {split}")
    for rid in train + evaluation:
        if rid not in records:
            raise BaselineError(f"split id '{rid}' has no record in records.jsonl")
    train_groups = {records[i].template_family for i in train}
    leaked = sorted({records[i].template_family for i in evaluation} & train_groups)
    if leaked:
        raise BaselineError(f"groups shared between train and {split}: {leaked[:3]}")


# --- metrics --------------------------------------------------------------


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float] | None:
    """95% Wilson score interval; honest on small samples."""
    if total == 0:
        return None
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4))


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def compute_metrics(
    records: list[EmailRecord], scores: list[float], threshold: float
) -> dict[str, object]:
    """Binary metrics for the phishing class, plus per-category and per-source rates."""
    pred = [s >= threshold for s in scores]
    tp = sum(1 for r, p in zip(records, pred, strict=True) if r.is_phishing and p)
    fp = sum(1 for r, p in zip(records, pred, strict=True) if not r.is_phishing and p)
    fn = sum(1 for r, p in zip(records, pred, strict=True) if r.is_phishing and not p)
    tn = len(records) - tp - fp - fn
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if precision is not None and recall is not None and precision + recall > 0
        else None
    )

    def group_rates(key: str) -> dict[str, dict[str, object]]:
        out: dict[str, dict[str, object]] = {}
        values = sorted(
            {str(getattr(r, key).value if key == "category" else r.source) for r in records}
        )
        for value in values:
            idx = [
                i
                for i, r in enumerate(records)
                if (r.category.value if key == "category" else r.source) == value
            ]
            phish = [i for i in idx if records[i].is_phishing]
            legit = [i for i in idx if not records[i].is_phishing]
            caught = sum(1 for i in phish if pred[i])
            alarms = sum(1 for i in legit if pred[i])
            out[value] = {
                "n": len(idx),
                "phishing_detected": f"{caught}/{len(phish)}" if phish else None,
                "detection_rate": _ratio(caught, len(phish)),
                "false_alarms": f"{alarms}/{len(legit)}" if legit else None,
                "false_alarm_rate": _ratio(alarms, len(legit)),
            }
        return out

    return {
        "n": len(records),
        "positives": tp + fn,
        "negatives": tn + fp,
        "threshold": threshold,
        "precision": precision,
        "precision_95ci": wilson(tp, tp + fp),
        "recall": recall,
        "recall_95ci": wilson(tp, tp + fn),
        "f1": f1,
        "accuracy": _ratio(tp + tn, len(records)),
        "confusion_matrix": {
            "labels": ["legitimate", "phishing"],
            "rows_actual_cols_predicted": [[tn, fp], [fn, tp]],
        },
        "by_category": group_rates("category"),
        "by_source": group_rates("source"),
    }


# --- training and running -------------------------------------------------


def build_pipeline(config: BaselineConfig) -> Pipeline:
    t, lr = config.tfidf, config.logreg
    if t.ngram_max < t.ngram_min:
        raise BaselineError("tfidf.ngram_max must be >= tfidf.ngram_min")
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(t.ngram_min, t.ngram_max),
                    min_df=t.min_df,
                    max_features=t.max_features,
                    sublinear_tf=t.sublinear_tf,
                    lowercase=t.lowercase,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    C=lr.C,
                    class_weight=lr.class_weight,
                    max_iter=lr.max_iter,
                    solver="liblinear",
                    random_state=config.seed,
                ),
            ),
        ]
    )


class RunResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    metrics: dict[str, object]
    false_positives: list[tuple[str, str, str, float]]  # id, source, category, score
    false_negatives: list[tuple[str, str, str, float]]


def run_baseline(
    config: BaselineConfig,
    records: dict[str, EmailRecord],
    texts: dict[str, str],
    splits: dict[str, object],
    split: EvalSplit,
) -> RunResult:
    train = split_ids(splits, "train")
    evaluation = split_ids(splits, split)
    if not evaluation:
        raise BaselineError(f"split '{split}' is empty")
    check_separation(records, train, evaluation, split)
    missing = [i for i in train + evaluation if not texts.get(i, "").strip()]
    if missing:
        raise BaselineError(f"{len(missing)} records have no text, e.g. {missing[:3]}")
    y_train = [records[i].is_phishing for i in train]
    if len(set(y_train)) < 2:
        raise BaselineError("train split needs both phishing and legitimate records")

    model = build_pipeline(config)
    model.fit([texts[i] for i in train], y_train)
    phishing_col = list(model.classes_).index(True)
    probs = model.predict_proba([texts[i] for i in evaluation])[:, phishing_col]
    scores = [round(float(p), 6) for p in probs]
    eval_records = [records[i] for i in evaluation]
    metrics = compute_metrics(eval_records, scores, config.threshold)

    def rows(want_phishing: bool, predicted: bool) -> list[tuple[str, str, str, float]]:
        out = [
            (r.id, r.source, r.category.value, s)
            for r, s in zip(eval_records, scores, strict=True)
            if r.is_phishing == want_phishing and (s >= config.threshold) == predicted
        ]
        return sorted(out, key=lambda row: -row[3] if predicted else row[3])

    return RunResult(
        metrics=metrics,
        false_positives=rows(want_phishing=False, predicted=True),
        false_negatives=rows(want_phishing=True, predicted=False),
    )


# --- manifest and outputs -------------------------------------------------


def environment() -> dict[str, object]:
    versions: dict[str, str] = {}
    for pkg in PACKAGES:
        try:
            versions[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            versions[pkg] = "not installed"
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "packages": versions,
    }


def git_state(repo: Path) -> dict[str, object]:
    if shutil.which("git") is None:
        return {"commit": "unknown", "dirty": None}
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return {"commit": "unknown", "dirty": None}
    return {"commit": commit, "dirty": bool(dirty)}


def write_outputs(
    result: RunResult,
    out_dir: Path,
    manifest: dict[str, object],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    def dump(name: str, data: object) -> None:
        (out_dir / name).write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )

    dump("metrics.json", result.metrics)
    dump("manifest.json", manifest)
    for name, rows in (
        ("false_positives.csv", result.false_positives),
        ("false_negatives.csv", result.false_negatives),
    ):
        with open(out_dir / name, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, lineterminator="\n")
            writer.writerow(["id", "source", "category", "phishing_score"])
            writer.writerows(rows)
    (out_dir / "report.md").write_text(
        render_report(result, manifest), encoding="utf-8", newline="\n"
    )


def _fmt(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.3f}"
    if isinstance(value, list | tuple) and len(value) == 2:
        return f"{_fmt(value[0])}–{_fmt(value[1])}"
    return str(value)


def _git_line(git: object) -> str:
    if not isinstance(git, dict):
        return "unknown"
    note = " (with uncommitted changes)" if git.get("dirty") else ""
    return f"`{git.get('commit')}`{note}"


def _rows(table: object) -> list[tuple[str, dict[str, object]]]:
    if not isinstance(table, dict):
        return []
    return [(str(k), v) for k, v in table.items() if isinstance(v, dict)]


def render_report(result: RunResult, manifest: dict[str, object]) -> str:
    m = result.metrics
    cm = m["confusion_matrix"]
    if not isinstance(cm, dict):
        raise BaselineError("metrics have no confusion matrix")
    (tn, fp), (fn, tp) = cm["rows_actual_cols_predicted"]
    lines = [
        f"# Baseline results: {manifest['config_name']} on {manifest['split']}",
        "",
        f"Generated by `{manifest['command']}` on {manifest['created']}. Do not edit by hand.",
        "",
        f"- Split evaluated: **{manifest['split']}** ({m['n']} emails: "
        f"{m['positives']} phishing, {m['negatives']} legitimate)",
        f"- Seed {manifest['seed']} · threshold {m['threshold']}",
        f"- Split file SHA-256: `{manifest['split_sha256']}`",
        f"- Records SHA-256: `{manifest['records_sha256']}`",
        f"- Git commit: {_git_line(manifest.get('git'))}",
        "",
        "## Phishing class",
        "",
        "| metric | value | 95% interval |",
        "| --- | --- | --- |",
        f"| precision | {_fmt(m['precision'])} | {_fmt(m['precision_95ci'])} |",
        f"| recall | {_fmt(m['recall'])} | {_fmt(m['recall_95ci'])} |",
        f"| F1 | {_fmt(m['f1'])} | |",
        f"| accuracy | {_fmt(m['accuracy'])} | |",
        "",
        "## Confusion matrix",
        "",
        "| actual \\ predicted | legitimate | phishing |",
        "| --- | --- | --- |",
        f"| legitimate | {tn} | {fp} |",
        f"| phishing | {fn} | {tp} |",
        "",
        "## By category",
        "",
        "| category | n | phishing detected | false alarms |",
        "| --- | --- | --- | --- |",
    ]
    for name, row in _rows(m["by_category"]):
        lines.append(
            f"| {name} | {row['n']} | {_fmt(row['phishing_detected'])} | "
            f"{_fmt(row['false_alarms'])} |"
        )
    lines += [
        "",
        "## By source",
        "",
        "| source | n | phishing detected | false alarms |",
        "| --- | --- | --- | --- |",
    ]
    for name, row in _rows(m["by_source"]):
        lines.append(
            f"| {name} | {row['n']} | {_fmt(row['phishing_detected'])} | "
            f"{_fmt(row['false_alarms'])} |"
        )
    lines += [
        "",
        f"## False positives ({len(result.false_positives)})",
        "",
        "Legitimate emails flagged as phishing, highest score first. Ids only; "
        "review them locally with the labelling tool.",
        "",
    ]
    lines += [f"- {i} ({src}, {cat}) score {s:.3f}" for i, src, cat, s in result.false_positives]
    lines += [
        "" if result.false_positives else "- None",
        "",
        f"## False negatives ({len(result.false_negatives)})",
        "",
    ]
    lines += [f"- {i} ({src}, {cat}) score {s:.3f}" for i, src, cat, s in result.false_negatives]
    if not result.false_negatives:
        lines.append("- None")
    lines += [
        "",
        "## Notes",
        "",
        f"- {m['n']} evaluation emails: intervals are wide; report counts with rates.",
        "- Categories with 1–2 emails here say little on their own.",
        "- No claim is made beyond this split and configuration.",
    ]
    return "\n".join(lines) + "\n"


def make_manifest(
    config: BaselineConfig,
    split: EvalSplit,
    split_sha256: str,
    records_sha256: str,
    repo: Path,
    command: str,
    counts: dict[str, int],
) -> dict[str, object]:
    return {
        "config_name": config.name,
        "config": config.model_dump(mode="json"),
        "seed": config.seed,
        "split": split,
        "final_evaluation": split == "test",
        "split_sha256": split_sha256,
        "records_sha256": records_sha256,
        "split_sizes": counts,
        "git": git_state(repo),
        "environment": environment(),
        "command": command,
        "created": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
    }


def train_counts(records: dict[str, EmailRecord], ids: list[str]) -> dict[str, int]:
    c = Counter(records[i].category for i in ids)
    return {cat.value: c[cat] for cat in Category}
