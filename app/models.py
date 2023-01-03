from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask


@dataclass
class WhorfConfig:
    ignores_namespaces: list[str]  # a list of namespaces to ignore requests from
    upload_interval_in_min: str = "*/30"  # every 30 minutes

    def init_app(self, app: Flask) -> None:
        """Register whorf config to a Flask application instance"""

        app.extensions["whorf"] = self
