from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from pytest_mock import MockerFixture

import app.models
import app.utils

if TYPE_CHECKING:
    from flask.testing import FlaskClient


@pytest.fixture()
def client(mocker: MockerFixture, tmp_path: Path) -> FlaskClient:
    checkov_conf_path = tmp_path / ".checkov.yaml"
    checkov_conf_path.write_text("framework: kubernetes")
    whorf_conf_path = tmp_path / "whorf.yaml"
    whorf_conf_path.write_text("ignores-namespaces:\n - default")

    mocker.patch.object(app.models, "CHECKOV_CONFIG_PATH", checkov_conf_path)
    mocker.patch.object(app.utils, "WHORF_CONFIG_PATH", whorf_conf_path)

    from app.whorf import webhook

    return webhook.test_client()


@pytest.fixture()
def request_info() -> dict[str, Any]:
    return json.loads((Path(__file__).parent / "request.json").read_text())


def test_validate(client: FlaskClient, request_info) -> None:
    # when
    response = client.post("/validate", json=request_info)

    # then
    assert response.json == {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "allowed": False,
            "uid": "13b390aa-ea59-48ef-9fb8-069bf0430dce",
            "status": {"code": 403, "message": "Checkov found 15 total issues in this manifest."},
        },
    }
