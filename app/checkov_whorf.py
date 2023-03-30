from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Literal, Optional

import yaml
from checkov.main import Checkov

from app.consts import CHECKOV_CONFIG_PATH
from app.models import LastReportedRun

if TYPE_CHECKING:
    from logging import Logger

    from checkov.common.output.baseline import Baseline
    from checkov.common.runners.runner_registry import RunnerRegistry


class CheckovWhorf(Checkov):
    def __init__(self, logger: Logger, argv: list[str]) -> None:
        super().__init__(argv=argv)

        self.logger = logger
        self.last_reported_run: Optional[LastReportedRun] = None

    def upload_results(
        self,
        root_folder: str,
        files: list[str] | None = None,
        excluded_paths: list[str] | None = None,
        included_paths: list[str] | None = None,
        git_configuration_folders: list[str] | None = None,
    ) -> None:
        # don't upload results with every run
        if self.should_upload_results():
            super().upload_results(root_folder, files, excluded_paths, included_paths, git_configuration_folders)
            self.last_reported_run = LastReportedRun()
        return

    def should_upload_results(self) -> bool:
        if not self.last_reported_run:
            return True
        return datetime.datetime.now() - datetime.timedelta(hours=1) < self.last_reported_run.date

    def upload_results_periodically(self, root_folder: str) -> None:
        """Used to upload results on a periodic basis"""

        super().upload_results(root_folder=root_folder)

    def print_results(
        self,
        runner_registry: RunnerRegistry,
        url: str | None = None,
        created_baseline_path: str | None = None,
        baseline: Baseline | None = None,
    ) -> Literal[0, 1]:
        # just don't print anything to stdout
        return 0

    def update_config(self) -> None:
        conf = yaml.safe_load(CHECKOV_CONFIG_PATH.read_text())

        for param, value in conf.items():
            flag_attr = param.replace("-", "_")
            if hasattr(self.config, flag_attr):
                value = [value] if flag_attr == "framework" and not isinstance(value, list) else value
                setattr(self.config, flag_attr, value)
            else:
                self.logger.error(f"Parameter {param} is not supported")

    def scan_file(self, file: str) -> None:
        """Scan the given file"""

        self.config.file = [file]
        self.run()

        self.logger.info(f"Successfully scanned file {file}")

    def scan_directory(self, directory: str) -> None:
        """Scan the given directory"""

        self.config.directory = [directory]
        self.run()
        self.upload_results_periodically(root_folder=directory)

        self.logger.info(f"Successfully scanned directory {directory} and uploaded results")
