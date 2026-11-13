"""Registered operations: the only things the execution engine will run.

An operation is a tool plus a fixed argument template with typed, validated
parameters. It renders to an argv list — never a shell string — so a parameter
value can never inject another argument or a shell command. Operations are
defined in data/operations.toml; users add more there (including offensive
ones) without touching code.
"""

from __future__ import annotations

import re
import tomllib
from importlib import resources
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from blackarch_ai.security.permissions import Permission

ParamType = Literal["string", "int", "enum", "bool"]

# A rendered argv value must be printable, free of NUL/controls, and not look
# like an option flag unless the option explicitly allows it.
_SAFE_VALUE = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
_IDENT = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


class OperationError(ValueError):
    pass


class ValidationError(OperationError):
    """A supplied parameter or target was rejected."""


class ParamSpec(BaseModel):
    name: str
    type: ParamType = "string"
    flag: str | None = None          # e.g. "-p"; None means positional
    description: str = ""
    required: bool = False
    default: str | int | bool | None = None
    choices: list[str] = Field(default_factory=list)
    min: int | None = None
    max: int | None = None
    pattern: str | None = None       # extra regex the string value must match
    allow_leading_dash: bool = False
    template: str | None = None      # wrap the validated value, e.g. "/{}//" for ettercap

    @model_validator(mode="after")
    def _check(self) -> ParamSpec:
        if not _IDENT.match(self.name):
            raise OperationError(f"bad param name {self.name!r}")
        if self.type == "enum" and not self.choices:
            raise OperationError(f"enum param {self.name!r} needs choices")
        if self.flag is not None and not self.flag.startswith("-"):
            raise OperationError(f"flag for {self.name!r} must start with '-'")
        if self.template is not None and "{}" not in self.template:
            raise OperationError(f"template for {self.name!r} must contain '{{}}'")
        return self

    def render(self, value: object) -> list[str]:
        """Validate `value` and return the argv tokens it contributes."""
        if self.type == "bool":
            on = bool(value) if value is not None else bool(self.default)
            if on and self.flag is None:
                raise OperationError(f"bool param {self.name!r} needs a flag")
            return [self.flag] if on else []

        if value is None:
            value = self.default
        if value is None:
            if self.required:
                raise ValidationError(f"missing required parameter {self.name!r}")
            return []

        token = self._render_scalar(value)
        if self.template:
            token = self.template.format(token)
        return ([self.flag, token] if self.flag else [token])

    def _render_scalar(self, value: object) -> str:
        if self.type == "int":
            try:
                n = int(value)
            except (TypeError, ValueError):
                raise ValidationError(f"{self.name} must be an integer") from None
            if self.min is not None and n < self.min:
                raise ValidationError(f"{self.name} must be >= {self.min}")
            if self.max is not None and n > self.max:
                raise ValidationError(f"{self.name} must be <= {self.max}")
            return str(n)

        token = str(value)
        if self.type == "enum" and token not in self.choices:
            raise ValidationError(
                f"{self.name} must be one of {', '.join(self.choices)}")
        if not _SAFE_VALUE.match(token):
            raise ValidationError(f"{self.name} has illegal characters")
        if token.startswith("-") and not self.allow_leading_dash:
            raise ValidationError(f"{self.name} may not start with '-'")
        if self.pattern and not re.match(self.pattern, token):
            raise ValidationError(f"{self.name} does not match the required format")
        return token


TargetKind = Literal["host", "url", "network", "any"]


class TargetSpec(BaseModel):
    kind: TargetKind = "any"
    flag: str | None = None          # e.g. "-u"; None means positional (appended last)
    required: bool = True
    separator: bool = False          # put "--" before the target to end option parsing
    template: str | None = None      # wrap the validated target, e.g. "/{}//" for ettercap

    @model_validator(mode="after")
    def _check(self) -> TargetSpec:
        if self.template is not None and "{}" not in self.template:
            raise OperationError("target template must contain '{}'")
        return self

    def render(self, target: str | None) -> list[str]:
        if not target:
            if self.required:
                raise ValidationError("this operation needs a --target")
            return []
        token = target.strip()
        if not _SAFE_VALUE.match(token) or token.startswith("-"):
            raise ValidationError(f"illegal target {target!r}")
        if self.template:
            token = self.template.format(token)
        tokens: list[str] = []
        if self.separator:
            tokens.append("--")
        if self.flag:
            tokens.append(self.flag)
        tokens.append(token)
        return tokens


class Operation(BaseModel):
    id: str
    tool: str                        # package name that must be installed
    command: str | None = None       # executable basename; defaults to `tool`
    summary: str = ""
    permission: Permission
    args: list[str] = Field(default_factory=list)   # fixed literal arguments
    params: list[ParamSpec] = Field(default_factory=list)
    target: TargetSpec | None = None
    timeout: float = 300.0
    host: bool = False               # run on the host via `flatpak-spawn --host`
    #   (needed for packet capture: a rootless toolbox can't get CAP_NET_RAW
    #   over the host's physical interface, so capture tools run on the host)
    unpackaged: bool = False         # resolve the executable off PATH, not the
    #   pacman registry (for pip/pipx-installed tools such as mitmproxy)

    @model_validator(mode="after")
    def _check(self) -> Operation:
        if not _IDENT.match(self.id):
            raise OperationError(f"bad operation id {self.id!r}")
        names = [p.name for p in self.params]
        if len(names) != len(set(names)):
            raise OperationError(f"{self.id}: duplicate parameter names")
        for a in self.args:
            if not _SAFE_VALUE.match(a):
                raise OperationError(f"{self.id}: illegal literal arg {a!r}")
        return self

    @property
    def exe_name(self) -> str:
        return self.command or self.tool

    @property
    def needs_target(self) -> bool:
        return self.target is not None and self.target.required

    def render_argv(self, exe_path: str, params: dict[str, object],
                    target: str | None) -> list[str]:
        """Build the full argv. Raises ValidationError on any bad input."""
        known = {p.name for p in self.params}
        unknown = set(params) - known
        if unknown:
            raise ValidationError(f"unknown parameters: {', '.join(sorted(unknown))}")
        prefix = ["flatpak-spawn", "--host"] if self.host else []
        argv = [*prefix, exe_path, *self.args]
        for spec in self.params:
            argv.extend(spec.render(params.get(spec.name)))
        if self.target is not None:
            argv.extend(self.target.render(target))
        elif target:
            raise ValidationError(f"operation {self.id!r} takes no target")
        return argv


class OperationCatalogue:
    def __init__(self, operations: list[Operation]) -> None:
        self._ops: dict[str, Operation] = {}
        for op in operations:
            if op.id in self._ops:
                raise OperationError(f"duplicate operation id {op.id!r}")
            self._ops[op.id] = op

    def __len__(self) -> int:
        return len(self._ops)

    def ids(self) -> list[str]:
        return sorted(self._ops)

    def get(self, op_id: str) -> Operation:
        if op_id not in self._ops:
            raise OperationError(f"no operation {op_id!r}")
        return self._ops[op_id]

    def all(self) -> list[Operation]:
        return [self._ops[i] for i in self.ids()]

    def for_tool(self, tool: str) -> list[Operation]:
        return [op for op in self.all() if op.tool == tool]


def load_operations(path: Path | None = None) -> OperationCatalogue:
    if path is None:
        text = resources.files("blackarch_ai").joinpath("data/operations.toml").read_text()
    else:
        text = path.read_text()
    raw = tomllib.loads(text)
    ops = [Operation.model_validate(o) for o in raw.get("operation", [])]
    return OperationCatalogue(ops)
