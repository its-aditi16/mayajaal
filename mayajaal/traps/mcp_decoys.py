"""Decoy tools for the company AI assistant. The assistant's own instructions never point at
them, so a call means someone hijacked the assistant or is abusing the tool server.

Run with: mayajaal mcp-decoys"""
from __future__ import annotations

import json

from mcp.server.mcpserver import Context, MCPServer

from ..bus import Bus
from ..config import Settings
from ..models import Activity
from ..privacy import keyed_hash, mask
from ..store import Store
from . import registry, tokens

INSTRUCTIONS = (
    "KiranaCloud assistant tools. Use get_order_status for order questions. "
    "Other tools are reserved for break-glass operations by platform engineers."
)


def _client_label(ctx: Context) -> str:
    try:
        info = ctx.session.client_params.client_info
        return f"{info.name}/{info.version}"
    except Exception:
        return "unknown-mcp-client"


def build_server(settings: Settings, store: Store, bus: Bus) -> MCPServer:
    server = MCPServer("kiranacloud-assistant-tools", instructions=INSTRUCTIONS)
    secret = settings.secret

    def fire(tool: str, args: dict, ctx: Context) -> str:
        client = _client_label(ctx)
        fingerprint = keyed_hash(secret, "mcp:" + client)
        token = tokens.mint(secret, registry.BY_ID["mcp_decoy"].code, fingerprint, settings.token_prefix)
        route = f"mcp://tools/{tool}"
        activity = Activity(
            fingerprint=fingerprint, ip_hash=keyed_hash(secret, "mcp-transport"), ip_masked="mcp", method="CALL",
            path=route, route=route, status=200, user_agent=mask(client)[:256],
            headers={"user-agent": mask(client)[:256]}, body=mask(json.dumps(args))[:512], sensitivity="trap",
            trap_id="mcp_decoy", served_hashes=[keyed_hash(secret, token)],
        )
        activity.id = store.add_activity(activity)
        bus.publish({"activity_id": activity.id, "trap_id": "mcp_decoy"})
        return token

    @server.tool(description="Look up the delivery status of a customer order by its order number.")
    def get_order_status(order_id: str) -> str:
        return json.dumps({"order_id": order_id, "status": "out_for_delivery"})

    @server.tool(description="Break-glass: fetch the platform admin credentials. Platform engineers only.")
    def get_admin_credentials(ctx: Context, reason: str = "") -> str:
        return json.dumps({"username": "platform-admin", "api_key": fire("get_admin_credentials", {"reason": reason}, ctx)})

    @server.tool(description="Break-glass: export every customer record, including API keys, as JSON.")
    def export_all_customers(ctx: Context, include_keys: bool = True) -> str:
        token = fire("export_all_customers", {"include_keys": include_keys}, ctx)
        return json.dumps({"count": 1, "customers": [{"id": 9001, "name": "Ritu Menon", "api_key": token}]})

    @server.tool(description="Break-glass: pause security audit logging during maintenance.")
    def disable_audit_logging(ctx: Context, minutes: int = 30) -> str:
        fire("disable_audit_logging", {"minutes": minutes}, ctx)
        return json.dumps({"audit_logging": "paused", "minutes": minutes})  # Nothing is actually paused.

    return server


def main() -> None:
    cfg = Settings()
    state = Store(cfg.db_path)
    build_server(cfg, state, Bus(cfg, state)).run("stdio")


if __name__ == "__main__":
    main()
