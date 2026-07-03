from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from .auth_server import AuthenticatedChannelServer, AuthMode


@dataclass
class CondaRunner:
    env: dict[str, str]
    timeout: int = 60

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        conda = shutil.which("conda")
        if conda is None:
            raise RuntimeError("conda executable not found")

        return subprocess.run(
            [conda, *args],
            capture_output=True,
            check=False,
            env=self.env,
            text=True,
            timeout=self.timeout,
        )


@pytest.fixture
def conda_runner(tmp_path: Path) -> CondaRunner:
    home = tmp_path / "home"
    xdg_data = tmp_path / "xdg-data"
    appdata = tmp_path / "appdata"
    localappdata = tmp_path / "localappdata"
    pkgs_dirs = tmp_path / "pkgs"
    envs_dirs = tmp_path / "envs"
    for path in (home, xdg_data, appdata, localappdata, pkgs_dirs, envs_dirs):
        path.mkdir()

    env = os.environ.copy()
    env.update(
        {
            "APPDATA": str(appdata),
            "CONDARC": str(tmp_path / "condarc"),
            "CONDA_ENVS_DIRS": str(envs_dirs),
            "CONDA_PKGS_DIRS": str(pkgs_dirs),
            "HOME": str(home),
            "LOCALAPPDATA": str(localappdata),
            "PYTHON_KEYRING_BACKEND": "keyrings.alt.file.PlaintextKeyring",
            "XDG_DATA_HOME": str(xdg_data),
        }
    )
    return CondaRunner(env=env)


@pytest.fixture
def channel_server(
    tmp_path: Path,
) -> Iterator[Callable[..., AuthenticatedChannelServer]]:
    servers: list[AuthenticatedChannelServer] = []

    def start(
        *,
        mode: AuthMode = "none",
        username: str = "user",
        password: str = "password",
        token: str = "token",
        token_header: str = "Authorization",
        token_template: str = "Bearer {token}",
    ) -> AuthenticatedChannelServer:
        server = AuthenticatedChannelServer.start(
            tmp_path / f"channel-{len(servers)}",
            mode=mode,
            username=username,
            password=password,
            token=token,
            token_header=token_header,
            token_template=token_template,
        )
        servers.append(server)
        return server

    yield start

    for server in reversed(servers):
        server.stop()
