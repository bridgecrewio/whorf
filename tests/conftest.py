from pathlib import Path

import pytest
from checkov.common.bridgecrew.severities import BcSeverities, Severities
from checkov.common.models.enums import CheckResult
from checkov.common.output.record import SCA_LICENSE_CHECK_NAME, SCA_PACKAGE_SCAN_CHECK_NAME, Record
from pytest_mock import MockerFixture

import app.checkov_whorf
import app.utils


@pytest.fixture()
def webhook(mocker: MockerFixture, tmp_path: Path):
    checkov_conf_path = tmp_path / ".checkov.yaml"
    checkov_conf_path.write_text("framework: kubernetes")
    whorf_conf_path = tmp_path / "whorf.yaml"
    whorf_conf_path.write_text("ignores-namespaces:\n - default")

    mocker.patch.object(app.checkov_whorf, "CHECKOV_CONFIG_PATH", checkov_conf_path)
    mocker.patch.object(app.utils, "WHORF_CONFIG_PATH", whorf_conf_path)

    from app.whorf import webhook

    yield webhook


@pytest.fixture()
def license_record() -> Record:
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
def k8s_record() -> Record:
    return Record(
        check_id="CKV_K8S_16",
        bc_check_id="BC_K8S_15",
        check_class="checkov.kubernetes.checks.resource.k8s.PrivilegedContainers",
        check_name="Container should not be privileged",
        check_result={"result": CheckResult.FAILED},
        code_block=[
            (1, "apiVersion: apps/v1\n"),
            (2, "kind: Deployment\n"),
            (3, "metadata:\n"),
            (4, "  annotations:\n"),
            (
                5,
                '    kubectl.kubernetes.io/last-applied-configuration: \'{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"annotations":{},"creationTimestamp":null,"labels":{"app":"nginx","ops":"thing"},"name":"nginx","namespace":"nginx"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"nginx"}},"strategy":{},"template":{"metadata":{"creationTimestamp":null,"labels":{"app":"nginx"}},"spec":{"containers":[{"image":"nginx","name":"nginx","resources":{},"securityContext":{"privileged":true}}]}}}}\n',
            ),
            (6, "\n"),
            (7, "      '\n"),
            (8, "  creationTimestamp: '2022-12-21T16:08:29Z'\n"),
            (9, "  generation: 1\n"),
            (10, "  labels:\n"),
            (11, "    app: nginx\n"),
            (12, "    ops: thing\n"),
            (13, "  managedFields:\n"),
            (14, "  - apiVersion: apps/v1\n"),
            (15, "    fieldsType: FieldsV1\n"),
            (16, "    fieldsV1:\n"),
            (17, "      f:metadata:\n"),
            (18, "        f:annotations:\n"),
            (19, "          .: {}\n"),
            (20, "          f:kubectl.kubernetes.io/last-applied-configuration: {}\n"),
            (21, "        f:labels:\n"),
            (22, "          .: {}\n"),
            (23, "          f:app: {}\n"),
            (24, "          f:ops: {}\n"),
            (25, "      f:spec:\n"),
            (26, "        f:progressDeadlineSeconds: {}\n"),
            (27, "        f:replicas: {}\n"),
            (28, "        f:revisionHistoryLimit: {}\n"),
            (29, "        f:selector: {}\n"),
            (30, "        f:strategy:\n"),
            (31, "          f:rollingUpdate:\n"),
            (32, "            .: {}\n"),
            (33, "            f:maxSurge: {}\n"),
            (34, "            f:maxUnavailable: {}\n"),
            (35, "          f:type: {}\n"),
            (36, "        f:template:\n"),
            (37, "          f:metadata:\n"),
            (38, "            f:labels:\n"),
            (39, "              .: {}\n"),
            (40, "              f:app: {}\n"),
            (41, "          f:spec:\n"),
            (42, "            f:containers:\n"),
            (43, '              k:{"name":"nginx"}:\n'),
            (44, "                .: {}\n"),
            (45, "                f:image: {}\n"),
            (46, "                f:imagePullPolicy: {}\n"),
            (47, "                f:name: {}\n"),
            (48, "                f:resources: {}\n"),
            (49, "                f:securityContext:\n"),
            (50, "                  .: {}\n"),
            (51, "                  f:privileged: {}\n"),
            (52, "                f:terminationMessagePath: {}\n"),
            (53, "                f:terminationMessagePolicy: {}\n"),
            (54, "            f:dnsPolicy: {}\n"),
            (55, "            f:restartPolicy: {}\n"),
            (56, "            f:schedulerName: {}\n"),
            (57, "            f:securityContext: {}\n"),
            (58, "            f:terminationGracePeriodSeconds: {}\n"),
            (59, "    manager: kubectl-client-side-apply\n"),
            (60, "    operation: Update\n"),
            (61, "    time: '2022-12-21T16:08:29Z'\n"),
            (62, "  name: nginx\n"),
            (63, "  namespace: nginx\n"),
            (64, "  uid: 68b18e67-195d-4676-a214-a1b9859431dc\n"),
            (65, "spec:\n"),
            (66, "  progressDeadlineSeconds: 600\n"),
            (67, "  replicas: 1\n"),
            (68, "  revisionHistoryLimit: 10\n"),
            (69, "  selector:\n"),
            (70, "    matchLabels:\n"),
            (71, "      app: nginx\n"),
            (72, "  strategy:\n"),
            (73, "    rollingUpdate:\n"),
            (74, "      maxSurge: 25%\n"),
            (75, "      maxUnavailable: 25%\n"),
            (76, "    type: RollingUpdate\n"),
            (77, "  template:\n"),
            (78, "    metadata:\n"),
            (79, "      creationTimestamp: null\n"),
            (80, "      labels:\n"),
            (81, "        app: nginx\n"),
            (82, "    spec:\n"),
            (83, "      containers:\n"),
            (84, "      - image: nginx\n"),
            (85, "        imagePullPolicy: Always\n"),
            (86, "        name: nginx\n"),
            (87, "        resources: {}\n"),
            (88, "        securityContext:\n"),
            (89, "          privileged: true\n"),
            (90, "        terminationMessagePath: /dev/termination-log\n"),
            (91, "        terminationMessagePolicy: File\n"),
            (92, "      dnsPolicy: ClusterFirst\n"),
            (93, "      restartPolicy: Always\n"),
            (94, "      schedulerName: default-scheduler\n"),
            (95, "      securityContext: {}\n"),
            (96, "      terminationGracePeriodSeconds: 30\n"),
            (97, "status: {}\n"),
        ],
        evaluations=None,
        file_abs_path="/path/to/13b390aa-ea59-48ef-9fb8-069bf0430dce-req.yaml",
        file_line_range=[1, 97],
        file_path="/13b390aa-ea59-48ef-9fb8-069bf0430dce-req.yaml",
        resource="Deployment.nginx.nginx",
        severity=None,
    )


@pytest.fixture()
def package_record() -> Record:
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
