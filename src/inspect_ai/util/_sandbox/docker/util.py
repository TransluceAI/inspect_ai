import os
import re
from dataclasses import dataclass
from logging import getLogger
from pathlib import Path

from shortuuid import uuid

from ..environment import SandboxEnvironmentConfigType
from .config import (
    COMPOSE_DOCKERFILE_YAML,
    auto_compose_file,
    ensure_auto_compose_file,
    is_dockerfile,
    resolve_compose_file,
)

logger = getLogger(__name__)


@dataclass
class ComposeProject:
    name: str
    config: str | None
    sample_id: int | str | None
    epoch: int | None
    env: dict[str, str] | None

    @classmethod
    async def create(
        cls,
        name: str,
        config: SandboxEnvironmentConfigType | None,
        *,
        sample_id: int | str | None = None,
        epoch: int | None = None,
        env: dict[str, str] = {},
    ) -> "ComposeProject":
        # resolve config to full path if we have one
        config_path = None
        if isinstance(config, str):
            config_path = Path(config).resolve()
        elif config is not None:
            raise ValueError(f"Unsupported config type: {type(config)}. Expected str.")

        # if its a Dockerfile, then config is the auto-generated .compose.yaml
        if config_path and is_dockerfile(config_path.name):
            config = auto_compose_file(
                COMPOSE_DOCKERFILE_YAML.format(dockerfile=config_path.name),
                config_path.parent.as_posix(),
            )

        # if its another config file, just take its path
        elif config_path:
            config = config_path.as_posix()

        # no config passed, look for 'auto-config' (compose.yaml, Dockerfile, etc.)
        else:
            config = resolve_compose_file()

        # this could be a cleanup where docker has tracked a .compose.yaml file
        # as part of its ConfigFiles and passed it back to us -- we in the
        # meantime have cleaned it up so we re-create it here as required
        ensure_auto_compose_file(config)

        # return project
        return ComposeProject(name, config, sample_id=sample_id, epoch=epoch, env=env)

    def __init__(
        self,
        name: str,
        config: str | None,
        sample_id: int | str | None,
        epoch: int | None,
        env: dict[str, str],
    ) -> None:
        self.name = name
        self.config = config
        self.sample_id = sample_id
        self.epoch = epoch
        self.env = env

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ComposeProject):
            return NotImplemented
        else:
            return self.name == other.name


def task_project_name(task: str) -> str:
    # ensure that task conforms to docker project name constraints
    task = task.lower()
    task = re.sub(r"[^a-z\d\-_]", "-", task)
    task = re.sub(r"-+", "-", task)
    if len(task) == 0:
        task = "task"

    # _- breaks docker project name constraints so we strip trailing underscores.
    return f"inspect-{task[:12].rstrip('_')}-i{uuid().lower()[:6]}"


inspect_project_pattern = r"^inspect-[a-z\d\-_]*-i[a-z\d]{6,}$"


def is_inspect_project(name: str) -> bool:
    return re.match(inspect_project_pattern, name) is not None


def is_local_docker():
    return os.environ.get("MORPH_API_KEY", "") == ""
