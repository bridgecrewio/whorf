import os
import re
from pathlib import Path

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

CHECKOV_CONFIG_PATH = Path("config/.checkov.yaml")
MANIFEST_ROOT_PATH = Path("/tmp")
WHORF_CONFIG_PATH = Path("config/whorf.yaml")

DEFAULT_CHECKOV_ARGS = ["--framework", "kubernetes", "--repo-id", "k8s_ac/cluster"]
UUID_PATTERN = re.compile(r"\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b")
