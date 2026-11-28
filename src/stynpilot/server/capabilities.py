"""Fixed, versioned operation contracts for MCP clients that cache tool lists."""

from dataclasses import dataclass
from typing import Annotated, Callable

from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError

from .diag_tools import NOT_AUTHORIZED, READ_ONLY
from .router import AccessDenied

API_VERSION = 1


class EmptyInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class LabEvidenceInput(EmptyInput):
    job_id: str = Field(pattern=r"^[a-f0-9]{32}$", min_length=32, max_length=32)
    offset: int = Field(default=0, ge=0, le=16 * 1024 * 1024)
    limit: int = Field(default=8192, ge=1, le=16384)


class LabEnrollmentInput(EmptyInput):
    repository: str = Field(pattern=r"^bam5693/stynpilot$", min_length=17, max_length=17)


class ArchiveCaptureInput(EmptyInput):
    repository: str = Field(pattern=r"^[a-z][a-z0-9-]{0,47}$", min_length=1, max_length=48)
    refs: dict[Annotated[str, Field(max_length=1024)], Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]] = Field(
        min_length=1, max_length=512)
    head: str = Field(pattern=r"^refs/heads/", max_length=1024)


class ArchiveJobInput(EmptyInput):
    job_id: str = Field(pattern=r"^[a-f0-9]{32}$", min_length=32, max_length=32)


@dataclass(frozen=True)
class Operation:
    name: str
    version: int
    permission: str
    scope: str
    model: type[EmptyInput]
    handler: Callable[..., dict]


def manifest(operations):
    return {"api_version": API_VERSION, "operations": [
        {"name": op.name, "version": op.version, "permission": op.permission,
         "required_scope": op.scope, "input_schema": op.model.model_json_schema()}
        for op in operations
    ]}


def invoke(operations, device_id, name, version, arguments):
    op = next((item for item in operations if item.name == name and item.version == version), None)
    if op is None:
        return {"ok": False, "error": "capability_unknown_or_version_unsupported"}
    try:
        params = op.model.model_validate(arguments)
    except ValidationError:
        return {"ok": False, "error": "capability_arguments_invalid"}
    return op.handler(device_id, **params.model_dump())


def register(server, *, operations, run, bearer, router):
    @server.tool(name="stynpilot_capabilities", title="Discover versioned StyNpilot operations", annotations=READ_ONLY,
                 description="List operation versions, input schemas and permissions for the stable StyNpilot interface.")
    def discover(device_id: str) -> dict:
        return run("stynpilot_capabilities", device_id, lambda owner: manifest(operations), write=False)

    @server.tool(name="stynpilot_invoke", title="Call a versioned StyNpilot operation",
                 description="Call one operation from stynpilot_capabilities using its exact input schema. Each operation keeps its own authorization and phone-approval requirements.")
    def dispatch(device_id: str, operation: Annotated[str, Field(max_length=64)], version: StrictInt,
                 arguments: dict) -> dict:
        header = bearer()
        if header is None:
            return NOT_AUTHORIZED
        try:
            router.authorize_read(header, device_id)
        except AccessDenied:
            return NOT_AUTHORIZED
        return invoke(operations, device_id, operation, version, arguments)
