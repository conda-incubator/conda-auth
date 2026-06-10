from __future__ import annotations

import base64
import json
import queue
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Literal
from urllib.parse import unquote, urlsplit

from conda.base.context import context

AuthMode = Literal["none", "basic", "token"]

TEST_PACKAGE_NAME = "conda-auth-test-package"
TEST_PACKAGE_FILENAME = f"{TEST_PACKAGE_NAME}-1.0.0-0.tar.bz2"


@dataclass(frozen=True)
class RequestRecord:
    method: str
    path: str
    headers: dict[str, str]
    status_code: int

    @property
    def authorization(self) -> str | None:
        return self.headers.get("Authorization")


@dataclass
class AuthenticatedChannelServer:
    root: Path
    mode: AuthMode = "none"
    username: str = "user"
    password: str = "password"
    token: str = "token"
    token_header: str = "Authorization"
    token_template: str = "Bearer {token}"
    host: str = "127.0.0.1"
    records: list[RequestRecord] = field(default_factory=list)

    _server: ThreadingHTTPServer | None = field(default=None, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    @classmethod
    def start(
        cls,
        root: Path,
        *,
        mode: AuthMode = "none",
        username: str = "user",
        password: str = "password",
        token: str = "token",
        token_header: str = "Authorization",
        token_template: str = "Bearer {token}",
    ) -> AuthenticatedChannelServer:
        server = cls(
            root=root,
            mode=mode,
            username=username,
            password=password,
            token=token,
            token_header=token_header,
            token_template=token_template,
        )
        server.write_channel()
        server.start_server()
        return server

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("Server is not running")
        return self._server.server_port

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def expected_basic_header(self) -> str:
        secret = f"{self.username}:{self.password}".encode()
        return f"Basic {base64.b64encode(secret).decode('ascii')}"

    @property
    def expected_token_value(self) -> str:
        return self.token_template.format(token=self.token)

    def get_url(self, path: str = "") -> str:
        path = path.lstrip("/")
        return f"{self.url}/{path}" if path else self.url

    def write_channel(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        subdirs = ("noarch", context.subdir)
        for subdir in subdirs:
            directory = self.root / subdir
            directory.mkdir(exist_ok=True)
            repodata = {
                "info": {"subdir": subdir},
                "packages": {},
                "packages.conda": {},
                "repodata_version": 1,
            }
            if subdir == "noarch":
                repodata["packages"][TEST_PACKAGE_FILENAME] = {
                    "name": TEST_PACKAGE_NAME,
                    "version": "1.0.0",
                    "build": "0",
                    "build_number": 0,
                    "subdir": "noarch",
                    "depends": [],
                    "md5": "0" * 32,
                    "sha256": "0" * 64,
                    "size": 0,
                    "timestamp": 0,
                }
            (directory / "repodata.json").write_text(json.dumps(repodata))
            (directory / "repodata_shards.msgpack.zst").write_bytes(
                b"\x28\xb5\x2f\xfdtest shard index"
            )

        (self.root / "channeldata.json").write_text(
            json.dumps(
                {
                    "channeldata_version": 1,
                    "packages": {},
                    "subdirs": list(subdirs),
                }
            )
        )

    def start_server(self) -> None:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                owner.handle_request(self, send_body=True)

            def do_HEAD(self) -> None:
                owner.handle_request(self, send_body=False)

            def log_message(self, format: str, *args: object) -> None:
                return

        class Server(ThreadingHTTPServer):
            allow_reuse_address = True
            request_queue_size = 64

        started: queue.Queue[ThreadingHTTPServer | BaseException] = queue.Queue(maxsize=1)

        def run() -> None:
            try:
                with Server((self.host, 0), Handler) as httpd:
                    self._server = httpd
                    started.put(httpd)
                    httpd.serve_forever()
            except BaseException as exc:
                started.put(exc)

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        result = started.get(timeout=5)
        if isinstance(result, BaseException):
            raise result

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def handle_request(self, handler: BaseHTTPRequestHandler, *, send_body: bool) -> None:
        status_code = 500
        try:
            if status_code := self.auth_failure_status(handler):
                headers = {}
                body = b"not authenticated"
                if status_code == 401:
                    headers["WWW-Authenticate"] = 'Basic realm="Test"'
                    body = b"no auth header received"
                self.send_response(
                    handler, status_code, body, headers=headers, send_body=send_body
                )
                return

            status_code = self.serve_file(handler, send_body=send_body)
        finally:
            self.record_request(handler, status_code)

    def auth_failure_status(self, handler: BaseHTTPRequestHandler) -> int | None:
        if self.mode == "none":
            return None

        if self.mode == "basic":
            if handler.headers.get("Authorization") == self.expected_basic_header:
                return None
            return 401

        if handler.headers.get(self.token_header) == self.expected_token_value:
            return None
        return 403

    def serve_file(self, handler: BaseHTTPRequestHandler, *, send_body: bool) -> int:
        path = unquote(urlsplit(handler.path).path).lstrip("/")
        file_path = (self.root / path).resolve()

        try:
            file_path.relative_to(self.root.resolve())
        except ValueError:
            return self.send_response(handler, 404, b"not found", send_body=send_body)

        if not file_path.is_file():
            return self.send_response(handler, 404, b"not found", send_body=send_body)

        content = file_path.read_bytes()
        content_type = (
            "application/json" if file_path.suffix == ".json" else "application/octet-stream"
        )
        return self.send_response(
            handler,
            200,
            content,
            headers={"Content-Type": content_type},
            send_body=send_body,
        )

    def send_response(
        self,
        handler: BaseHTTPRequestHandler,
        status_code: int,
        body: bytes,
        *,
        headers: dict[str, str] | None = None,
        send_body: bool,
    ) -> int:
        handler.send_response(status_code)
        for name, value in (headers or {}).items():
            handler.send_header(name, value)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        if send_body:
            handler.wfile.write(body)
        return status_code

    def record_request(self, handler: BaseHTTPRequestHandler, status_code: int) -> None:
        with self._lock:
            self.records.append(
                RequestRecord(
                    method=handler.command,
                    path=handler.path,
                    headers={name: value for name, value in handler.headers.items()},
                    status_code=status_code,
                )
            )
