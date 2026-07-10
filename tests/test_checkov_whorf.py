from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from checkov.common.output.report import Report
from pytest_mock import MockerFixture

import app.checkov_whorf
from app.checkov_whorf import CheckovWhorf
from app.consts import DEFAULT_CHECKOV_ARGS


@pytest.mark.parametrize(
    (
        "first_manifest_fixture",
        "first_manifest_scan_results",
        "second_manifest_fixture",
        "second_manifest_scan_results",
    ),
    [
        pytest.param(
            "minimal_deployment_manifest",
            [("passed_checks", "Deployment.test.minimal")],
            "hostpid_deployment_manifest",
            [("failed_checks", "Deployment.test.hostpid-enabled")],
            id="pass-then-fail",
        ),
        pytest.param(
            "hostpid_deployment_manifest",
            [("failed_checks", "Deployment.test.hostpid-enabled")],
            "minimal_deployment_manifest",
            [("passed_checks", "Deployment.test.minimal")],
            id="fail-then-pass",
        ),
    ],
)
def test_checkov_whorf_instances_do_not_share_runner_state(
    mocker: MockerFixture,
    request: pytest.FixtureRequest,
    tmp_path: Path,
    first_manifest_fixture: str,
    first_manifest_scan_results: list[tuple[str, str]],
    second_manifest_fixture: str,
    second_manifest_scan_results: list[tuple[str, str]],
) -> None:
    checkov_conf_path = tmp_path / ".checkov.yaml"
    checkov_conf_path.write_text(
        "\n".join(
            [
                "framework: kubernetes",
                "check:",
                "- CKV_K8S_17",
                "skip-download: true",
            ]
        )
    )
    mocker.patch.object(app.checkov_whorf, "CHECKOV_CONFIG_PATH", checkov_conf_path)

    first_manifest_path = tmp_path / "first.yaml"
    first_manifest_path.write_text(str(request.getfixturevalue(first_manifest_fixture)))
    second_manifest_path = tmp_path / "second.yaml"
    second_manifest_path.write_text(str(request.getfixturevalue(second_manifest_fixture)))

    first_scan_reports = _scan_file(first_manifest_path)
    assert _scan_report_results(first_scan_reports, ["CKV_K8S_17"]) == first_manifest_scan_results

    second_scan_reports = _scan_file(second_manifest_path)
    assert _scan_report_results(second_scan_reports, ["CKV_K8S_17"]) == second_manifest_scan_results


def _scan_file(file_path: Path) -> list[Report]:
    ckv_whorf = CheckovWhorf(logger=MagicMock(), argv=DEFAULT_CHECKOV_ARGS)
    ckv_whorf.update_config()
    ckv_whorf.scan_file(file=str(file_path))
    return ckv_whorf.scan_reports


def _scan_report_results(
    reports: list[Report],
    check_ids: list[str],
) -> list[tuple[str, str]]:
    return [
        (result_type, record.resource)
        for report in reports
        for result_type, records in (
            ("passed_checks", report.passed_checks),
            ("failed_checks", report.failed_checks),
        )
        for record in records
        if record.check_id in check_ids
    ]
