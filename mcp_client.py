"""MCP client for REA.

Spawns the REA MCP server over stdio and exposes list_tools() / call_tool().
The whole connection lives inside ONE asyncio task (anyio cancel scopes must
be entered and exited by the same task), which waits on a stop event.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import config


@dataclass
class ToolDef:
    name: str
    description: str
    input_schema: dict[str, Any]
    title: str = ""
    annotations: dict[str, Any] = field(default_factory=dict)

    @property
    def destructive(self) -> bool:
        return bool(self.annotations.get("destructiveHint"))

    @property
    def read_only(self) -> bool:
        return bool(self.annotations.get("readOnlyHint"))

    @property
    def open_world(self) -> bool:
        return bool(self.annotations.get("openWorldHint"))

    @property
    def examples(self) -> list[dict]:
        return [e for e in (self.input_schema.get("examples") or []) if isinstance(e, dict)]


@dataclass
class ToolResult:
    data: Any
    is_error: bool = False

    def pretty(self) -> str:
        if isinstance(self.data, (dict, list)):
            return json.dumps(self.data, indent=2, ensure_ascii=False)
        return str(self.data)


def _leaf(e: BaseException) -> BaseException:
    """Dig the real error out of (nested) exception groups."""
    while isinstance(e, BaseExceptionGroup) and e.exceptions:
        e = e.exceptions[0]
    return e


def _attr(obj: Any, *names: str) -> Any:
    """Read a field that is camelCase in mcp 1.x and snake_case in mcp 2.x."""
    for n in names:
        if hasattr(obj, n):
            return getattr(obj, n)
    return None


def _annotations(tool: Any) -> dict[str, Any]:
    """Tool annotations with camelCase keys (readOnlyHint...) on any SDK version."""
    a = getattr(tool, "annotations", None)
    if a is None:
        return {}
    try:
        d = a.model_dump(by_alias=True, exclude_none=True)
    except Exception:  # noqa: BLE001
        d = dict(a) if isinstance(a, dict) else {}
    return {re.sub(r"_([a-z])", lambda m: m.group(1).upper(), k): v for k, v in d.items()}


class ReaClient:
    def __init__(self, command: str, args: list[str], env: dict[str, str] | None = None,
                 cwd: str | None = None):
        self.params = StdioServerParameters(command=command, args=args, env=env, cwd=cwd)
        self._session: ClientSession | None = None
        self._task: asyncio.Task | None = None
        self._ready: asyncio.Event | None = None
        self._stop: asyncio.Event | None = None
        self._error: BaseException | None = None
        self._tools: list[ToolDef] = []

    @classmethod
    def from_config(cls, cfg: dict) -> "ReaClient":
        command, args = config.server_command(cfg)
        return cls(command, args, config.server_env(cfg), cfg.get("rea_root") or None)

    # ---- lifecycle -------------------------------------------------
    @property
    def connected(self) -> bool:
        return self._session is not None

    async def start(self, timeout: float = 90.0) -> None:
        await self.stop()
        self._error = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._task = asyncio.create_task(self._run())
        try:
            await asyncio.wait_for(self._ready.wait(), timeout)
        except asyncio.TimeoutError:
            await self.stop()
            raise RuntimeError(f"REA did not answer the MCP handshake within {timeout:.0f}s")
        if self._error is not None:
            err = self._error
            await self.stop()
            raise RuntimeError(f"Could not start REA MCP server: {err}")

    async def _run(self) -> None:
        errlog = None
        try:
            logdir = config.APP_DIR / "logs"
            logdir.mkdir(exist_ok=True)
            errlog = open(logdir / "rea-server.stderr.log", "a", encoding="utf-8")
        except OSError:
            errlog = open(os.devnull, "w")
        try:
            async with stdio_client(self.params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self._session = session
                    self._ready.set()
                    await self._stop.wait()
        except BaseException as e:  # noqa: BLE001 - report everything to start()
            self._error = _leaf(e)
            if not isinstance(e, Exception):
                raise
        finally:
            self._session = None
            self._ready.set()
            errlog.close()

    async def stop(self) -> None:
        if self._task is None:
            return
        if self._stop is not None:
            self._stop.set()
        try:
            await asyncio.wait_for(self._task, 10)
        except BaseException:  # noqa: BLE001
            self._task.cancel()
        self._task = None
        self._session = None

    async def __aenter__(self) -> "ReaClient":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()

    # ---- protocol --------------------------------------------------
    async def _list_page(self, cursor: str | None):
        if cursor is None:
            return await self._session.list_tools()
        try:  # mcp 1.x: list_tools(cursor)
            return await self._session.list_tools(cursor)
        except TypeError:  # mcp 2.x: list_tools(params=PaginatedRequestParams)
            from mcp.types import PaginatedRequestParams
            return await self._session.list_tools(params=PaginatedRequestParams(cursor=cursor))

    async def list_tools(self) -> list[ToolDef]:
        tools: list[ToolDef] = []
        cursor = None
        while True:
            res = await self._list_page(cursor)
            for t in res.tools:
                tools.append(ToolDef(t.name, t.description or "",
                                     _attr(t, "inputSchema", "input_schema") or {},
                                     getattr(t, "title", None) or "", _annotations(t)))
            cursor = _attr(res, "nextCursor", "next_cursor")
            if not cursor:
                break
        self._tools = sorted(tools, key=lambda t: t.name)
        return self._tools

    @property
    def tools(self) -> list[ToolDef]:
        return self._tools

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> ToolResult:
        if self._session is None:
            raise RuntimeError("Not connected to REA")
        res = await self._session.call_tool(name, arguments or {})
        texts = [b.text for b in res.content if getattr(b, "type", None) == "text"]
        data: Any
        if len(texts) == 1:
            try:
                data = json.loads(texts[0])
            except json.JSONDecodeError:
                data = texts[0]
        elif texts:
            data = "\n".join(texts)
        elif _attr(res, "structuredContent", "structured_content") is not None:
            data = _attr(res, "structuredContent", "structured_content")
        else:
            data = [b.model_dump() for b in res.content]
        return ToolResult(data, bool(_attr(res, "isError", "is_error")))
