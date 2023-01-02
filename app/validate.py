from __future__ import annotations

import re
from typing import TYPE_CHECKING, cast

from checkov.common.bridgecrew.check_type import CheckType
from checkov.common.bridgecrew.severities import BcSeverities
from flask import current_app as webhook

from app.consts import UUID_PATTERN
from app.utils import admission_response

if TYPE_CHECKING:
    from checkov.common.output.report import Report
    from flask import Response

    from app.checkov_whorf import CheckovWhorf


def validate_k8s_request(namespace: str, uid: str) -> Response | None:
    # Check/Sanitise UID to make sure it's a k8s request and only a k8s request as it is used for file naming
    if re.match(UUID_PATTERN, uid):
        webhook.logger.info("Valid UID Found, continuing")
    else:
        message = "Invalid UID. Aborting validation"
        webhook.logger.error("K8s UID failed security checks. Request rejected!")
        return admission_response(allowed=False, uid=uid, message=message)

    # check we're not in a system namespace
    if namespace in webhook.extensions["whorf"].ignores_namespaces:
        message = "Namespace in ignore list. Ignoring validation"
        webhook.logger.error("Namespace in ignore list. Ignoring validation!")
        return admission_response(allowed=True, uid=uid, message=message)

    return None


def process_passed_checks(ckv_whorf: CheckovWhorf, uid: str, obj_kind_name: str) -> Response:
    """Invoked when no Kubernetes related issues were found"""

    message = []

    k8s_message = generate_k8s_output(reports=ckv_whorf.scan_reports)
    message.extend(k8s_message)

    sca_message = generate_sca_output(reports=ckv_whorf.scan_reports)
    message.extend(sca_message)

    webhook.logger.info(f"Object {obj_kind_name} passed security checks. Allowing the request.")
    return admission_response(allowed=True, uid=uid, message="\n".join(message))


def process_failed_checks(ckv_whorf: CheckovWhorf, uid: str, obj_kind_name: str) -> Response:
    """Invoked when Kubernetes related issues were found"""

    message = []

    if ckv_whorf.config.hard_fail_on:
        hard_fails = {}
        try:
            for report in ckv_whorf.scan_reports:
                for check in report.failed_checks:
                    if check.check_id in ckv_whorf.config.hard_fail_on:
                        hard_fails[check.check_id] = f"\n  Description: {check.check_name}"
                        if check.guideline:
                            hard_fails[check.check_id] += f"\n  Guidance: {check.guideline}"
                    elif check.bc_check_id in ckv_whorf.config.hard_fail_on:
                        hard_fails[check.check_id] = f"\n  Description: {check.check_name}"
                        if check.guideline:
                            hard_fails[check.check_id] += f"\n  Guidance: {check.guideline}"
        finally:
            webhook.logger.error("hard fail error")

        if hard_fails:
            message.append(f"Checkov found {len(hard_fails)} issues in violation of admission policy.")

            for ckv in hard_fails:
                message.append(f"{ckv}:{hard_fails[ckv]}")

    k8s_message = generate_k8s_output(reports=ckv_whorf.scan_reports)
    message.extend(k8s_message)

    sca_message = generate_sca_output(reports=ckv_whorf.scan_reports)
    message.extend(sca_message)

    webhook.logger.error(f"Object {obj_kind_name} failed security checks. Request rejected!")
    return admission_response(allowed=False, uid=uid, message="\n".join(message))


def generate_k8s_output(reports: list[Report]) -> list[str]:
    """Counts the failed checks to generate a message output"""

    k8s_report = next((report for report in reports if report.check_type == CheckType.KUBERNETES), None)
    if not k8s_report:
        return []

    issue_count = cast(int, k8s_report.get_summary()["failed"])

    message = [f"Checkov found {issue_count} total issues in this manifest."]

    return message


def generate_sca_output(reports: list[Report]) -> list[str]:
    """Extracts the CVEs and License violations to generate a message output"""

    sca_image_report = next((report for report in reports if report.check_type == CheckType.SCA_IMAGE), None)
    if not sca_image_report:
        return []

    license_count = 0
    cve_count = 0
    cve_severities = {
        BcSeverities.CRITICAL: 0,
        BcSeverities.HIGH: 0,
        BcSeverities.MEDIUM: 0,
        BcSeverities.LOW: 0,
    }

    for check in sca_image_report.failed_checks:  # TODO: differentiate between different images
        if check.check_id.startswith("BC_LIC_"):
            license_count += 1
        elif check.check_id.startswith("BC_VUL_"):
            cve_count += 1
            if check.severity:
                if check.severity.name in cve_severities:
                    cve_severities[check.severity.name] += 1
                else:
                    webhook.logger.warning(f"Unexpected severity {check.severity.name} received")
        else:
            webhook.logger.warning(f"Unexpected check ID {check.check_id} received")

    message = [
        f"Checkov found {cve_count} CVEs in container images of which are {cve_severities[BcSeverities.CRITICAL]} critical, {cve_severities[BcSeverities.HIGH]} high, {cve_severities[BcSeverities.MEDIUM]} medium and {cve_severities[BcSeverities.LOW]} low.",
        f"Checkov found {license_count} license violations in container images.",
    ]

    return message
