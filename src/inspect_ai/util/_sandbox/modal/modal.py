from __future__ import annotations

import os
from logging import getLogger
from pathlib import Path
from typing import Any, Literal, Union, cast

import modal
from typing_extensions import override

from ..environment import (
    PortMapping,
    SandboxConnection,
    SandboxEnvironment,
    SandboxEnvironmentConfigType,
)
from ..limits import (
    SandboxEnvironmentLimits,
    verify_exec_result_size,
    verify_read_file_size,
)
from ..registry import sandboxenv

logger = getLogger(__name__)

@sandboxenv(name="modal")
class ModalSandboxEnvironment(SandboxEnvironment):
    def __init__(
        self,
        stub: modal.Stub,
        container: modal.Container,
        working_dir: str = "/root",
        limits: SandboxEnvironmentLimits | None = None,
    ):
        self.stub = stub
        self.container = container
        self.working_dir = working_dir
        self.limits = limits or SandboxEnvironmentLimits()

    @classmethod
    def config_files(cls) -> list[str]:
        return ["modal.toml"]  # Configuration file for Modal settings

    @classmethod
    def default_concurrency(cls) -> int | None:
        # Modal handles concurrency well, but we can still set a reasonable default
        count = os.cpu_count() or 1
        return 2 * count

    @classmethod
    async def task_init(
        cls, task_name: str, config: SandboxEnvironmentConfigType | None
    ) -> None:
        # Initialize Modal stub and container
        stub = modal.Stub(f"inspect-ai-{task_name}")
        
        # Define the container with necessary dependencies
        image = modal.Image.debian_slim().pip_install(
            "python-dotenv",
            # Add other required packages here
        )
        
        container = stub.function(
            image=image,
            gpu="any",  # Remove if GPU not needed
            timeout=600  # 10 minute timeout
        )
        
        # Deploy the Modal app
        stub.deploy()

    @classmethod
    async def sample_init(
        cls,
        task_name: str,
        config: SandboxEnvironmentConfigType | None,
        metadata: dict[str, str],
    ) -> dict[str, SandboxEnvironment]:
        # Create a new Modal environment for this sample
        stub = modal.Stub(f"inspect-ai-{task_name}")
        container = stub.function()
        
        env = cls(
            stub=stub,
            container=container,
            working_dir="/root",
        )
        
        return {"default": env}

    @override
    async def cleanup(self, force: bool = False) -> None:
        # Cleanup Modal resources
        try:
            await self.stub.stop()
        except Exception as e:
            logger.warning(f"Failed to cleanup Modal resources: {e}")

    @override
    async def connect(self) -> SandboxConnection:
        # Return connection info for the Modal container
        return SandboxConnection(
            type="modal",
            command=f"modal shell {self.stub.name}",
            vscode_command=None,  # Modal doesn't have direct VSCode integration yet
        )

    @override
    async def exec(
        self,
        command: str | list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> ExecResult:
        # Execute command in Modal container
        try:
            if isinstance(command, list):
                command = " ".join(command)
            
            result = await self.container.run(
                command,
                cwd=cwd or self.working_dir,
                env=env,
                timeout=timeout,
            )
            
            return ExecResult(
                success=True,
                stdout=result.stdout if hasattr(result, 'stdout') else "",
                stderr=result.stderr if hasattr(result, 'stderr') else "",
                returncode=0,
            )
        except Exception as e:
            return ExecResult(
                success=False,
                stdout="",
                stderr=str(e),
                returncode=1,
            )

    @override
    async def read_file(self, path: str | Path) -> bytes:
        # Read file from Modal container
        try:
            path_str = str(path)
            content = await self.container.read_file.remote(path_str)
            verify_read_file_size(len(content), self.limits)
            return content
        except Exception as e:
            raise FileNotFoundError(f"Failed to read file {path}: {e}")

    @override
    async def write_file(
        self, path: str | Path, content: bytes | str, mode: int | None = None
    ) -> None:
        # Write file to Modal container
        try:
            path_str = str(path)
            if isinstance(content, str):
                content = content.encode()
            await self.container.write_file.remote(path_str, content, mode)
        except Exception as e:
            raise IOError(f"Failed to write file {path}: {e}")
