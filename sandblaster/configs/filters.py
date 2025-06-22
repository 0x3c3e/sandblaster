import json
from typing import Dict, Any, Optional


class Filters:
    def __init__(self, json_path: Optional[str] = None):
        self._filters: Dict[int, Any] = self._load_filters(json_path)

    def _load_filters(self, path: str) -> Dict[int, Any]:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return {int(k): v for k, v in raw.items()}

    def exists(self, filter_id: int) -> bool:
        return filter_id in self._filters

    def get(self, filter_id: int) -> Optional[Any]:
        return self._filters.get(filter_id)
