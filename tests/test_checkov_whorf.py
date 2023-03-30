import logging
from datetime import datetime, timedelta

from app.checkov_whorf import CheckovWhorf
from app.models import LastReportedRun


def test_should_upload_results_first_run():
    whorf = CheckovWhorf(logging.getLogger(), [])
    assert whorf.should_upload_results() is True


def test_should_not_upload_results():
    whorf = CheckovWhorf(logging.getLogger(), [])
    whorf.last_reported_run = LastReportedRun()
    assert whorf.should_upload_results() is False


def test_should_upload_results_sequential_run():
    whorf = CheckovWhorf(logging.getLogger(), [])
    whorf.last_reported_run = LastReportedRun(datetime.now() - timedelta(hours=1))
    assert whorf.should_upload_results() is True


def test_should_upload_results_sequential_run_long_time():
    whorf = CheckovWhorf(logging.getLogger(), [])
    whorf.last_reported_run = LastReportedRun(datetime.now() - timedelta(hours=2))
    assert whorf.should_upload_results() is True


def test_should_upload_results_sequential_run_short_time():
    whorf = CheckovWhorf(logging.getLogger(), [])
    whorf.last_reported_run = LastReportedRun(datetime.now() - timedelta(minutes=20))
    assert whorf.should_upload_results() is False
