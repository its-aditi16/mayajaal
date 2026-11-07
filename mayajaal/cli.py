"""The `mayajaal` command."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _worker(_args) -> int:
    from .worker import main

    main()
    return 0


def _demo(args) -> int:
    from .demo.run_demo import main

    return main([*(["--fresh"] if args.fresh else []), *(["--no-ai"] if args.no_ai else []),
                 *(["--no-memory"] if args.no_memory else [])])


def _dashboard(args) -> int:
    app = Path(__file__).with_name("dashboard_app.py")
    return subprocess.call([sys.executable, "-m", "streamlit", "run", str(app), f"--server.address={args.host}",
                            f"--server.port={args.port}", "--browser.gatherUsageStats=false",
                            "--client.toolbarMode=minimal"])


def _decoys(_args) -> int:
    from .traps.mcp_decoys import main

    main()
    return 0


def _record_golden(args) -> int:
    from .config import Settings
    from .prove import record_golden
    from .store import Store

    settings = Settings()
    golden = record_golden(settings, Store(settings.db_path), days=args.days)
    Path(args.out).write_text(json.dumps(golden, indent=2), encoding="utf-8")
    print(f"Saved {len(golden)} normal requests to {args.out}.")
    print("Review them: anything an attacker did before being caught must not be in this file.")
    print("Signed-in journeys are not recorded, so add those by hand.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mayajaal", description="A honeypot with memory")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("worker", help="Run the pipeline and approval service").set_defaults(run=_worker)

    demo = commands.add_parser("demo", help="Run the attack story against the demo app")
    demo.add_argument("--fresh", action="store_true", help="Forget earlier demo runs first")
    demo.add_argument("--no-ai", action="store_true", help="Run with the defender AI switched off")
    demo.add_argument("--no-memory", action="store_true", help="Run with memory off, to compare")
    demo.set_defaults(run=_demo)

    dashboard = commands.add_parser("dashboard", help="Open the security team dashboard")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8501)
    dashboard.set_defaults(run=_dashboard)

    commands.add_parser("mcp-decoys", help="Serve decoy AI tools over stdio").set_defaults(run=_decoys)

    record = commands.add_parser("record-golden", help="Save recent normal traffic for testing fixes against")
    record.add_argument("--out", default="golden.json")
    record.add_argument("--days", type=float, default=7.0)
    record.set_defaults(run=_record_golden)

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
