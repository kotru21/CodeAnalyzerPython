from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import httpx

from eval.dataset_github import github_blob_to_raw_url, parse_github_blob_url


def snapshot_id_for_repo_commit(owner: str, repo: str, sha: str) -> str:
    safe_repo = re.sub(r"[/\\:]+", "_", repo)
    return f"{owner}_{safe_repo}_{sha[:12]}"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def materialize_dataset_csv(
    csv_path: Path,
    materialize_root: Path,
    *,
    refresh: bool = False,
) -> Path:
    """
    Read CSV with column ``full_repo_path``, download each unique file from raw GitHub.

    Returns path to ``materialization_manifest.json`` under ``materialize_root``.
    """
    csv_path = csv_path.resolve()
    materialize_root = materialize_root.resolve()
    materialize_root.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str]] = []
    with csv_path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "full_repo_path" not in reader.fieldnames:
            raise ValueError("CSV must have a full_repo_path column")
        for row in reader:
            blob = (row.get("full_repo_path") or "").strip()
            if not blob:
                continue
            rows.append({k: (v or "").strip() for k, v in row.items()})

    # Unique blob URLs -> one materialized file each
    unique_blobs: dict[str, dict[str, str]] = {}
    for row in rows:
        blob = row["full_repo_path"]
        if blob not in unique_blobs:
            unique_blobs[blob] = row

    file_entries: list[dict[str, Any]] = []
    errors: list[str] = []

    with httpx.Client(follow_redirects=True, timeout=60.0) as client:
        for blob_url, _row in unique_blobs.items():
            try:
                owner, repo, sha, path_in_repo = parse_github_blob_url(blob_url)
            except ValueError as e:
                errors.append(f"{blob_url!r}: {e}")
                continue
            raw_url = github_blob_to_raw_url(blob_url)
            sid = snapshot_id_for_repo_commit(owner, repo, sha)
            dest = materialize_root / sid / path_in_repo
            relpath = dest.relative_to(materialize_root).as_posix()

            if dest.is_file() and not refresh:
                data = dest.read_bytes()
            else:
                resp = client.get(raw_url)
                if resp.status_code == 404:
                    errors.append(f"{raw_url} (404)")
                    continue
                resp.raise_for_status()
                data = resp.content
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)

            file_entries.append(
                {
                    "blob_url": blob_url,
                    "raw_url": raw_url,
                    "relpath": relpath,
                    "sha256": _sha256_bytes(data),
                    "bytes": len(data),
                }
            )

    if errors:
        msg = "Materialization failed:\n" + "\n".join(errors)
        raise RuntimeError(msg)

    manifest_path = materialize_root / "materialization_manifest.json"
    manifest_body: dict[str, Any] = {
        "csv_path": str(csv_path),
        "row_count": len(rows),
        "files": sorted(file_entries, key=lambda x: x["relpath"]),
    }
    manifest_path.write_text(
        json.dumps(manifest_body, indent=2, default=str),
        encoding="utf-8",
    )
    return manifest_path
