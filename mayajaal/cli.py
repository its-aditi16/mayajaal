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


def _suggest_traps(args) -> int:
    import os
    import tempfile

    from .ai import DefenderAI
    from .config import Settings
    from .traps import site_bait
    from .worker import load_object

    sys.path.insert(0, os.getcwd())
    factory = load_object(args.app)
    scratch = Settings(data_dir=tempfile.mkdtemp(prefix="mayajaal-suggest-"), secret_key="suggest",
                       memory_backend="local", llm_provider="none", redis_url="", _env_file=None)
    real = site_bait.app_paths(factory(scratch))
    ai = DefenderAI(Settings())
    source = ai.label
    ideas = site_bait.parse_ai_suggestions(ai.suggest_decoys({"real_routes": real})) if ai.available else []
    if not ideas:
        source, ideas = "built-in rules", site_bait.rule_suggestions(real)
    accepted, rejected = site_bait.validate(ideas, real)
    print(f"Read {len(real)} real routes. Suggestions from {source}:")
    for decoy in accepted:
        print(f"  KEEP  {decoy.path:<40} {decoy.kind:<7} {decoy.reason}")
    for path, why in rejected:
        print(f"  DROP  {path:<40} {why}")
    Path(args.out).write_text(json.dumps([d.model_dump() for d in accepted], indent=2), encoding="utf-8")
    print(f"\nSaved {len(accepted)} decoys to {args.out}. Nothing is live yet.")
    print(f"Review the file, then deploy it with MAYAJAAL_DECOYS_FILE={args.out}")
    return 0 if accepted else 1


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

    suggest = commands.add_parser("suggest-traps", help="Suggest decoys that fit your app, for a person to review")
    suggest.add_argument("--app", required=True, help="Your app factory, as module:create_app")
    suggest.add_argument("--out", default="decoys.json")
    suggest.set_defaults(run=_suggest_traps)

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
