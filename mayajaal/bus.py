"""Trap events travel over Redis Streams. If Redis is missing or fails mid-publish the
event goes to the SQLite outbox instead, so a trap firing is never lost."""
from __future__ import annotations

import json
import logging

from .config import Settings
from .store import Store

log = logging.getLogger("mayajaal.bus")
STREAM = "mayajaal:traps"
GROUP = "pipeline"
CONSUMER = "worker-1"


class Bus:
    def __init__(self, settings: Settings, store: Store):
        self.store = store
        self.redis = None
        self.name = "sqlite-outbox"
        if settings.redis_url:
            try:
                import redis

                client = redis.Redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=2)
                client.ping()
                try:
                    client.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
                except redis.ResponseError as exc:
                    if "BUSYGROUP" not in str(exc):
                        raise
                self.redis = client
                self.name = "redis-streams"
            except Exception as exc:
                log.warning("Redis unavailable (%s); using the SQLite outbox", exc)

    def publish(self, event: dict) -> None:
        if self.redis is not None:
            try:
                self.redis.xadd(STREAM, {"payload": json.dumps(event)}, maxlen=100000, approximate=True)
                return
            except Exception as exc:
                log.warning("Redis publish failed (%s); using the SQLite outbox", exc)
        self.store.add_event(event)

    def consume(self) -> list[dict]:
        events = self.store.take_events()
        if self.redis is not None:
            try:
                batches = self.redis.xreadgroup(GROUP, CONSUMER, {STREAM: ">"}, count=50, block=200)
                for _stream, entries in batches or []:
                    for entry_id, fields in entries:
                        events.append(json.loads(fields["payload"]))
                        self.redis.xack(STREAM, GROUP, entry_id)
            except Exception as exc:
                log.warning("Redis read failed: %s", exc)
        return events
