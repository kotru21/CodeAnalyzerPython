import io
import tempfile
import zipfile
from pathlib import Path


def extract_zip(zip_bytes: bytes, target_dir: Path | None = None) -> Path:
    if target_dir is None:
        target_dir = Path(tempfile.mkdtemp(prefix="analyzer_"))
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.extractall(target_dir)
    return target_dir


def iter_source_files(directory: Path) -> list[Path]:
    extensions = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    return sorted(p for p in directory.rglob("*") if p.suffix in extensions)
