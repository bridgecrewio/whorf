from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from checkov.common.bridgecrew.wrapper import reduce_scan_reports
from flask import current_app as webhook
from flask import jsonify

from app.consts import MANIFEST_ROOT_PATH, WHORF_CONFIG_PATH
from app.models import WhorfConfig

if TYPE_CHECKING:
    from checkov.common.output.report import Report
    from flask import Response


def admission_response(*, allowed: bool, uid: str, message: str) -> Response:
    return jsonify(
        {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "allowed": allowed,
                "uid": uid,
                "status": {"code": 200 if allowed else 403, "message": message},
            },
        }
    )


def get_whorf_config() -> WhorfConfig:
    """Parse the whorf config file"""

    if WHORF_CONFIG_PATH.exists():
        whorf_conf = yaml.safe_load(WHORF_CONFIG_PATH.read_text())
    else:
        # use legacy properties
        whorf_conf = parse_config("config/k8s.properties")

    return WhorfConfig(
        ignores_namespaces=whorf_conf.get("ignores-namespaces") or [],
        upload_interval_in_min=f"*/{whorf_conf.get('upload-interval-in-min') or 5}",
    )


def parse_config(configfile: str) -> dict[str, list[str]]:
    cf = {}
    with open(configfile) as myfile:
        for line in myfile:
            name, var = line.partition("=")[::2]
            cf[name.strip()] = list(var.strip().split(","))
    return cf


def to_dict(obj: Any) -> Any:
    if hasattr(obj, "attribute_map"):
        result = {}
        for k, v in obj.attribute_map.items():
            val = getattr(obj, k)
            if val is not None:
                result[v] = to_dict(val)
        return result
    elif isinstance(obj, list):
        return [to_dict(x) for x in obj]
    elif isinstance(obj, datetime):
        return str(obj)
    else:
        return obj


def cleanup_directory(path: Path) -> None:
    """Deletes all content of given directory, but not the directory itself"""

    if not path.exists():
        return

    for entry in os.scandir(path):
        try:
            if entry.is_dir(follow_symlinks=False):
                shutil.rmtree(entry)
            else:
                os.remove(entry)
        except Exception:
            webhook.logger.error(f"Failed to delete {entry}", exc_info=True)


def check_debug_mode(request_info: dict[str, Any], uid: str, scan_reports: list[Report]) -> None:
    # check the debug env.  If 'yes' we don't delete the evidence of the scan.  Just in case it's misbehaving.
    # to activate add an env DEBUG:yes to the deployment manifest
    debug = os.getenv("DEBUG")
    if isinstance(debug, str) and debug.lower() == "yes":
        # write original request and scan report to file system
        request_file_path = MANIFEST_ROOT_PATH / f"{uid}-req.json"
        request_file_path.write_text(json.dumps(request_info))

        reduced_scan_reports = reduce_scan_reports(scan_reports)
        scan_reports_file_path = MANIFEST_ROOT_PATH / f"{uid}-req-reports.json"
        scan_reports_file_path.write_text(json.dumps(reduced_scan_reports))
