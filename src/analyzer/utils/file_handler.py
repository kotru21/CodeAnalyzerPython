import io
import tempfile
import zipfile
from pathlib import Path


def extract_zip(zip_bytes: bytes, target_dir: Path | None = None) -> Path:
    """Extract zip bytes into target_dir, rejecting path-traversal (zip-slip) members."""
    if target_dir is None:
        target_dir = Path(tempfile.mkdtemp(prefix="analyzer_"))
    target_dir = target_dir.resolve()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            # Skip directories; validate file members stay under target_dir.
            name = info.filename
            if not name or name.endswith("/"):
                continue
            dest = (target_dir / name).resolve()
            try:
                dest.relative_to(target_dir)
            except ValueError as e:
                msg = f"zip slip blocked: {name!r}"
                raise ValueError(msg) from e
        zf.extractall(target_dir)
    return target_dir


def iter_source_files(directory: Path) -> list[Path]:
    extensions = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    return sorted(p for p in directory.rglob("*") if p.suffix in extensions)
