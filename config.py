"""Configuration for REA Studio.

Order of precedence (highest first): environment variables, then
rea-studio.config.json next to the app, then built-in defaults.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "rea-studio.config.json"

DEFAULTS: dict = {
    "rea_root": r"C:\Users\Administrator\Downloads\rea-main",
    "ghidra_install_dir": r"C:\Tools\ghidra-master\ghidra_12.1.2_PUBLIC_20260605\ghidra_12.1.2_PUBLIC",
    "java_home": r"C:\Program Files\Java\jdk-25.0.4",
    "provider": "ghidra",
    "node": "node",
}

ENV_MAP = {
    "rea_root": "REA_ROOT",
    "ghidra_install_dir": "GHIDRA_INSTALL_DIR",
    "java_home": "JAVA_HOME",
    "provider": "REA_ANALYSIS_PROVIDER",
    "node": "REA_NODE",
}


def load() -> dict:
    cfg = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except Exception:
            pass
    for key, env_name in ENV_MAP.items():
        if os.environ.get(env_name):
            cfg[key] = os.environ[env_name]
    return cfg


def save(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def ensure_config_file() -> None:
    """Write the defaults once so the user has a file to edit."""
    if not CONFIG_PATH.exists():
        try:
            save(DEFAULTS)
        except OSError:
            pass


def launcher_path(cfg: dict) -> str:
    return os.path.join(cfg["rea_root"], "scripts", "rea.mjs")


def server_command(cfg: dict) -> tuple[str, list[str]]:
    """Command + args that start the REA MCP server.

    Set "server_command" / "server_args" in the config file to point at a
    different MCP server (used by the test-suite's fake server).
    """
    if cfg.get("server_command"):
        return cfg["server_command"], list(cfg.get("server_args", []))
    return cfg.get("node", "node"), [launcher_path(cfg), "mcp"]


def server_env(cfg: dict) -> dict[str, str]:
    env = dict(os.environ)
    if cfg.get("ghidra_install_dir"):
        env["GHIDRA_INSTALL_DIR"] = cfg["ghidra_install_dir"]
    if cfg.get("java_home"):
        env["JAVA_HOME"] = cfg["java_home"]
    if cfg.get("provider"):
        env["REA_ANALYSIS_PROVIDER"] = cfg["provider"]
    return env
