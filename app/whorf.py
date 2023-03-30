from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import yaml
from checkov.common.bridgecrew.check_type import CheckType
from flask import Flask, request
from flask_apscheduler import APScheduler

from app.checkov_whorf import CheckovWhorf
from app.consts import DEFAULT_CHECKOV_ARGS, LOG_LEVEL, MANIFEST_ROOT_PATH
from app.utils import check_debug_mode, cleanup_directory, get_whorf_config, to_dict
from app.validate import process_failed_checks, process_passed_checks, validate_k8s_request

if TYPE_CHECKING:
    from flask import Response

webhook = Flask(__name__)
webhook.logger.setLevel(LOG_LEVEL)

scheduler = APScheduler()
scheduler.init_app(webhook)
scheduler.start()

whorf_conf = get_whorf_config()
whorf_conf.init_app(webhook)


@webhook.route("/", methods=["GET"])
def root() -> str:
    return "<h1 style='color:blue'>Ready!</h1>"


@webhook.route("/validate", methods=["POST"])
def validate() -> Response:
    request_info = cast("dict[str, Any]", request.get_json())
    webhook.logger.debug(json.dumps(request_info, indent=4))

    namespace = request_info["request"].get("namespace")
    uid = request_info["request"].get("uid")

    if response := validate_k8s_request(namespace=namespace, uid=uid):
        # either namespace or UID was wrong
        return response

    manifest_file_path = MANIFEST_ROOT_PATH / f"{uid}-req.yaml"
    manifest_file_path.write_text(yaml.dump(to_dict(request_info["request"]["object"])))

    webhook.logger.info(f"Start scanning file {manifest_file_path}")

    ckv_whorf = CheckovWhorf(logger=webhook.logger, argv=DEFAULT_CHECKOV_ARGS)
    ckv_whorf.update_config()
    ckv_whorf.scan_file(file=str(manifest_file_path))

    check_debug_mode(request_info=request_info, uid=uid, scan_reports=ckv_whorf.scan_reports)

    obj_kind_name = (
        f'{request_info["request"]["object"]["kind"]}/{request_info["request"]["object"]["metadata"]["name"]}'
    )

    if any(report.failed_checks for report in ckv_whorf.scan_reports if report.check_type == CheckType.KUBERNETES):
        return process_failed_checks(ckv_whorf=ckv_whorf, uid=uid, obj_kind_name=obj_kind_name)
    else:
        return process_passed_checks(ckv_whorf=ckv_whorf, uid=uid, obj_kind_name=obj_kind_name)


@scheduler.task("cron", id="scan", minute=whorf_conf.upload_interval_in_min)
def scan_periodic() -> None:
    webhook.logger.info(f"Start scanning directory {MANIFEST_ROOT_PATH}")

    ckv_whorf = CheckovWhorf(logger=webhook.logger, argv=DEFAULT_CHECKOV_ARGS, should_upload_results=True)
    ckv_whorf.update_config()
    ckv_whorf.scan_directory(str(MANIFEST_ROOT_PATH))

    cleanup_directory(MANIFEST_ROOT_PATH)
