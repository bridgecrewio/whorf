from __future__ import annotations

import logging

from checkov.common.bridgecrew.check_type import CheckType
from checkov.common.output.report import Report

from app.checkov_whorf import CheckovWhorf
from app.consts import DEFAULT_CHECKOV_ARGS
from app.validate import (
    generate_sca_output,
    process_failed_checks,
    process_passed_checks,
    validate_k8s_request,
)


def test_process_passed_checks(webhook) -> None:
    #  given
    ckv_whorf = CheckovWhorf(logger=logging.getLogger(), argv=DEFAULT_CHECKOV_ARGS)

    report = Report(check_type=CheckType.KUBERNETES)
    ckv_whorf.scan_reports = [report]

    # when
    with webhook.app_context():
        response = process_passed_checks(
            ckv_whorf=ckv_whorf, uid="13b390aa-ea59-48ef-9fb8-069bf0430dce", obj_kind_name="Deployment/nginx"
        )

    # then
    assert response.json == {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "allowed": True,
            "status": {"code": 200, "message": "Checkov found 0 total issues in this manifest."},
            "uid": "13b390aa-ea59-48ef-9fb8-069bf0430dce",
        },
    }


def test_process_failed_checks(webhook, k8s_record, license_record, package_record) -> None:
    #  given
    ckv_whorf = CheckovWhorf(logger=logging.getLogger(), argv=DEFAULT_CHECKOV_ARGS)

    k8s_report = Report(check_type=CheckType.KUBERNETES)
    k8s_report.add_record(k8s_record)
    sca_report = Report(check_type=CheckType.SCA_IMAGE)
    sca_report.add_record(license_record)
    sca_report.add_record(package_record)

    ckv_whorf.scan_reports = [k8s_report, sca_report]

    # when
    with webhook.app_context():
        response = process_failed_checks(
            ckv_whorf=ckv_whorf, uid="13b390aa-ea59-48ef-9fb8-069bf0430dce", obj_kind_name="Deployment/nginx"
        )

    # then
    assert response.json == {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "allowed": False,
            "status": {
                "code": 403,
                "message": "\n".join(
                    [
                        "Checkov found 1 total issues in this manifest.",
                        "Checkov found 1 CVEs in container images of which are 1 critical, 0 high, 0 medium and 0 low.",
                        "Checkov found 1 license violations in container images.",
                    ]
                ),
            },
            "uid": "13b390aa-ea59-48ef-9fb8-069bf0430dce",
        },
    }


def test_generate_sca_output(webhook, license_record, package_record) -> None:
    #  given
    report = Report(check_type=CheckType.SCA_IMAGE)
    report.add_record(license_record)
    report.add_record(package_record)

    # when
    with webhook.app_context():
        message = generate_sca_output(reports=[report])

    # then
    assert message == [
        "Checkov found 1 CVEs in container images of which are 1 critical, 0 high, 0 medium and 0 low.",
        "Checkov found 1 license violations in container images.",
    ]


def test_validate_k8s_request(webhook) -> None:
    # given
    namespace = "my-namespace"
    uid = "13b390aa-ea59-48ef-9fb8-069bf0430dce"

    # when
    with webhook.app_context():
        response = validate_k8s_request(namespace=namespace, uid=uid)

    # then
    assert response is None


def test_validate_k8s_request_with_invalid_uid(webhook) -> None:
    # given
    namespace = "my-namespace"
    uid = "invalid"

    # when
    with webhook.app_context():
        response = validate_k8s_request(namespace=namespace, uid=uid)

    # then
    assert response.json == {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "allowed": False,
            "status": {"code": 403, "message": "Invalid UID. Aborting validation"},
            "uid": "invalid",
        },
    }


def test_validate_k8s_request_with_ignore_namespace(webhook) -> None:
    # given
    namespace = "default"
    uid = "13b390aa-ea59-48ef-9fb8-069bf0430dce"

    # when
    with webhook.app_context():
        response = validate_k8s_request(namespace=namespace, uid=uid)

    # then
    assert response.json == {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "allowed": True,
            "status": {"code": 200, "message": "Namespace in ignore list. Ignoring validation"},
            "uid": "13b390aa-ea59-48ef-9fb8-069bf0430dce",
        },
    }
