# llmapp_shield/rules/loader.py
"""
Rule Loader — Loads detection rules from YAML files.

Rules are stored in YAML files in the rules/ directory.
This loader finds, parses, and validates all rule files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from llmapp_shield.models import Rule


class RuleLoader:
    """Loads and caches detection rules from YAML files."""

    def __init__(self, rules_dir: Optional[Path] = None) -> None:
        self.rules_dir = rules_dir or (Path(__file__).parent / "definitions")
        self._cache: Optional[list[Rule]] = None

    def load_all(self) -> list[Rule]:
        """Load all rules from the rules directory."""
        if self._cache is not None:
            return self._cache

        rules: list[Rule] = []

        if not self.rules_dir.exists():
            return rules

        for yaml_file in sorted(self.rules_dir.glob("*.yml")):
            try:
                rules.extend(self._load_file(yaml_file))
            except Exception:
                # Don't crash on malformed rule files
                pass

        self._cache = rules
        return rules

    def _load_file(self, path: Path) -> list[Rule]:
        """Load rules from a single YAML file."""
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            return []

        rules = []
        for rule_data in data["rules"]:
            try:
                rule = Rule(**rule_data)
                if rule.enabled:
                    rules.append(rule)
            except Exception:
                continue
        return rules

    def get_by_category(self, category: str) -> list[Rule]:
        """Get rules filtered by category."""
        return [r for r in self.load_all() if r.category == category]

    def get_by_id(self, rule_id: str) -> Optional[Rule]:
        """Get a specific rule by ID."""
        for rule in self.load_all():
            if rule.id == rule_id:
                return rule
        return None