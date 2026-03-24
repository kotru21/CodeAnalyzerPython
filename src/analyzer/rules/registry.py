import importlib
import pkgutil
from typing import Sequence

from analyzer.rules.base import BaseRule


_registry: list[BaseRule] = []
_loaded = False


def _discover_rules() -> None:
    global _loaded
    if _loaded:
        return

    import analyzer.rules.javascript as js_pkg

    for importer, modname, ispkg in pkgutil.walk_packages(
        js_pkg.__path__, prefix=js_pkg.__name__ + "."
    ):
        importlib.import_module(modname)

    for subclass in BaseRule.__subclasses__():
        _registry.append(subclass())

    _loaded = True


def get_all_rules() -> Sequence[BaseRule]:
    _discover_rules()
    return list(_registry)


def get_rules_for_language(language: str) -> Sequence[BaseRule]:
    all_rules = get_all_rules()
    js_langs = {"javascript", "jsx", "typescript", "tsx"}
    if language in js_langs:
        return [r for r in all_rules if r.meta().rule_id.startswith("JS-")]
    return []


def get_rule_by_id(rule_id: str) -> BaseRule | None:
    for r in get_all_rules():
        if r.meta().rule_id == rule_id:
            return r
    return None


def reset_registry() -> None:
    """For testing only."""
    global _loaded
    _registry.clear()
    _loaded = False
