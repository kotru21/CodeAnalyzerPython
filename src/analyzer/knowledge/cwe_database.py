import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


@dataclass
class CWEEntry:
    cwe_id: str
    name: str
    description: str
    mitigations: list[str] = field(default_factory=list)
    consequences: list[str] = field(default_factory=list)
    likelihood: str = ""
    owasp_mapping: str = ""


class CWEDatabase:
    def __init__(self) -> None:
        self._entries: dict[str, CWEEntry] = {}

    def load(self, xml_path: Path) -> None:
        if not xml_path.exists():
            return
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for weakness in root.findall(".//cwe:Weakness", _NS):
            entry = self._parse_weakness(weakness)
            self._entries[entry.cwe_id] = entry

    def get(self, cwe_id: str) -> CWEEntry | None:
        normalized = cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
        return self._entries.get(normalized)

    @property
    def size(self) -> int:
        return len(self._entries)

    def _parse_weakness(self, elem: ET.Element) -> CWEEntry:
        wid = elem.get("ID", "")
        cwe_id = f"CWE-{wid}"
        name = elem.get("Name", "")

        desc_elem = elem.find("cwe:Description", _NS)
        description = (desc_elem.text or "") if desc_elem is not None else ""

        likelihood_elem = elem.find("cwe:Likelihood_Of_Exploit", _NS)
        likelihood = (likelihood_elem.text or "") if likelihood_elem is not None else ""

        mitigations: list[str] = []
        for mit in elem.findall(".//cwe:Potential_Mitigations/cwe:Mitigation", _NS):
            desc = mit.find("cwe:Description", _NS)
            if desc is not None and desc.text:
                mitigations.append(desc.text.strip())

        consequences: list[str] = []
        for cons in elem.findall(".//cwe:Common_Consequences/cwe:Consequence", _NS):
            scope = cons.find("cwe:Scope", _NS)
            impact = cons.find("cwe:Impact", _NS)
            if scope is not None and impact is not None:
                s = scope.text or ""
                i = impact.text or ""
                consequences.append(f"{s}: {i}")

        return CWEEntry(
            cwe_id=cwe_id,
            name=name,
            description=description,
            mitigations=mitigations,
            consequences=consequences,
            likelihood=likelihood,
        )


_db: CWEDatabase | None = None


def get_cwe_database(xml_path: Path | None = None) -> CWEDatabase:
    """Return process-wide CWE DB; reload if first load left it empty and path exists."""
    global _db
    if _db is None:
        _db = CWEDatabase()
        if xml_path is not None:
            _db.load(xml_path)
    elif _db.size == 0 and xml_path is not None and xml_path.exists():
        _db.load(xml_path)
    return _db


def reset_cwe_database() -> None:
    global _db
    _db = None
