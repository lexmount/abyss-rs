"""Runtime entries shared by TLS selectors and plugin source metadata."""

from typing import Literal, TypedDict, Union


class ScriptEntry(TypedDict):
    kind: Literal["script"]
    path: str


class ModuleEntry(TypedDict):
    kind: Literal["module"]
    runtime: Literal["python"]
    name: str


ProcessEntry = Union[ScriptEntry, ModuleEntry]
