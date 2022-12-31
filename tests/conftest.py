from pathlib import Path

import pytest
from checkov.common.bridgecrew.severities import BcSeverities, Severities
from checkov.common.models.enums import CheckResult
from checkov.common.output.record import SCA_LICENSE_CHECK_NAME, SCA_PACKAGE_SCAN_CHECK_NAME, Record
from pytest_mock import MockerFixture

import app.models
import app.utils


@pytest.fixture()
def webhook(mocker: MockerFixture, tmp_path: Path):
    checkov_conf_path = tmp_path / ".checkov.yaml"
    checkov_conf_path.write_text("framework: kubernetes")
    whorf_conf_path = tmp_path / "whorf.yaml"
    whorf_conf_path.write_text("ignores-namespaces:\n - default")

    mocker.patch.object(app.models, "CHECKOV_CONFIG_PATH", checkov_conf_path)
    mocker.patch.object(app.utils, "WHORF_CONFIG_PATH", whorf_conf_path)

    from app.whorf import webhook

    yield webhook


@pytest.fixture()
def license_record():
    return Record(
        check_id="BC_LIC_2",
        bc_check_id="BC_LIC_2",
        check_class="checkov.common.bridgecrew.vulnerability_scanning.image_scanner.ImageScanner",
        check_name=SCA_LICENSE_CHECK_NAME,
        check_result={"result": CheckResult.FAILED},
        code_block=[(0, "gettext: 0.21-4")],
        evaluations=None,
        file_line_range=[0, 0],
        file_path="/13b390aa-ea59-48ef-9fb8-069bf0430dce-req.yaml (nginx lines:1-98 (sha256:1403e55ab3))",
        resource="13b390aa-ea59-48ef-9fb8-069bf0430dce-req.yaml (nginx lines:1-98 (sha256:1403e55ab3)).gettext",
        file_abs_path="/path/to/13b390aa-ea59-48ef-9fb8-069bf0430dce-req.yaml",
        vulnerability_details={
            "package_name": "gettext",
            "package_version": "0.21-4",
            "license": "GPL",
            "status": "FAILED",
            "policy": "BC_LIC_2",
            "package_type": "os",
        },
    )


@pytest.fixture()
def package_record():
    return Record(
        check_id="BC_VUL_1",
        bc_check_id="BC_CVE_2022_3970",
        check_class="checkov.common.bridgecrew.vulnerability_scanning.image_scanner.ImageScanner",
        check_name=SCA_PACKAGE_SCAN_CHECK_NAME,
        check_result={"result": CheckResult.FAILED},
        code_block=[(0, "tiff: 4.2.0-1+deb11u1")],
        evaluations=None,
        file_abs_path="/path/to/13b390aa-ea59-48ef-9fb8-069bf0430dce-req.yaml",
        file_line_range=[0, 0],
        file_path="/13b390aa-ea59-48ef-9fb8-069bf0430dce-req.yaml (nginx lines:1-98 (sha256:1403e55ab3))",
        resource="13b390aa-ea59-48ef-9fb8-069bf0430dce-req.yaml (nginx lines:1-98 (sha256:1403e55ab3)).tiff",
        severity=Severities[BcSeverities.CRITICAL],
        vulnerability_details={
            "id": "CVE-2022-3970",
            "severity": "critical",
            "package_name": "tiff",
            "package_version": "4.2.0-1+deb11u1",
            "package_type": "os",
            "link": "https://security-tracker.debian.org/tracker/CVE-2022-3970",
            "cvss": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "description": "A vulnerability was found in LibTIFF.",
            "risk_factors": [
                "Attack vector: network",
                "Critical severity",
                "Recent vulnerability",
                "Attack complexity: low",
            ],
            "published_date": "2022-11-13T08:15:00Z",
            "licenses": "Unknown",
            "root_package_name": None,
            "root_package_version": None,
            "status": "open",
            "lowest_fixed_version": "N/A",
            "fixed_versions": [],
        },
    )
