"""Runs the pipeline loop and the control API for whichever app is being protected."""
from __future__ import annotations

import importlib
import json
import logging
import os
import sys
import threading
from pathlib import Path

import uvicorn

from .ai import DefenderAI
from .alerts import Alerts
from .bus import Bus
from .config import Settings
from .control_api import create_control_app
from .memory import Memory
from .pipeline import Pipeline
from .prove import GoldenRequest
from .safety import PromptScreen
from .store import Store


def load_object(spec: str):
    """Loads 'package.module:name'."""
    module_name, _, attribute = spec.partition(":")
    if not attribute:
        raise ValueError(f"Expected 'module:name', got {spec!r}")
    return getattr(importlib.import_module(module_name), attribute)


def load_golden(spec: str) -> list[GoldenRequest]:
    """Normal traffic, from a JSON file or a 'module:name' list."""
    if spec.endswith(".json"):
        return [GoldenRequest(**item) for item in json.loads(Path(spec).read_text(encoding="utf-8"))]
    return list(load_object(spec))


def build_pipeline(settings: Settings, store: Store) -> Pipeline:
    return Pipeline(settings, store, Memory(settings, store), DefenderAI(settings), PromptScreen(settings),
                    Alerts(settings), load_object(settings.target_app), load_golden(settings.target_golden))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    for noisy in ("httpx", "httpx2"):  # Every replayed request would otherwise be logged.
        logging.getLogger(noisy).setLevel(logging.WARNING)
    # Installed commands do not look in the current folder, but your app is probably there.
    sys.path.insert(0, os.getcwd())
    settings = Settings()
    store = Store(settings.db_path)
    bus = Bus(settings, store)
    pipeline = build_pipeline(settings, store)
    logging.getLogger("mayajaal").info("Protecting %s. %s, bus=%s", settings.target_app, pipeline.status(), bus.name)

    stop = threading.Event()
    loop = threading.Thread(target=pipeline.run, args=(bus, stop), name="mayajaal-pipeline", daemon=True)
    loop.start()
    try:
        uvicorn.run(create_control_app(pipeline), host=settings.control_host, port=settings.control_port,
                    log_level="warning")
    finally:
        stop.set()
        loop.join(timeout=10)


if __name__ == "__main__":
    main()
