from typing import Callable, Any, ParamSpec, TypeVar, overload

from apscheduler.schedulers.base import BaseScheduler  # type:ignore[import]
from flask import Flask

_F = TypeVar("_F", bound=Callable[..., Any])
_T = TypeVar("_T")
_P = ParamSpec("_P")

class APScheduler:
    def __init__(self, scheduler: BaseScheduler | None = ..., app: Flask | None = ...) -> None: ...
    @overload
    def task(self, func: Callable[_P, _T]) -> Callable[_P, _T]: ...
    @overload
    def task(self, trigger: str, *, id: str, minute: str | None = None) -> Callable[[_F], _F]: ...
    def init_app(self, app: Flask) -> None: ...
    def start(self, paused: bool = ...) -> None: ...
