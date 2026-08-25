from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .codex_analyzer import CodexAnalysisError, CodexInventoryAnalyzer
from .explorer import AutoExplorer, ExplorerConfig


DEFAULT_CONFIG = Path(__file__).with_name("config.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m automation",
        description="Policy-gated Android UI + Frida + GLM planner + Codex analyzer",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in ("doctor", "explore"):
        child = subparsers.add_parser(command)
        child.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
        child.add_argument("--glm", action="store_true", help="Enable the configured GLM endpoint")
        child.add_argument(
            "--vision",
            action="store_true",
            help="Unsupported in the GLM-5.1-only configuration; rejected before API calls",
        )
        child.add_argument("--goal", help="High-level exploration goal sent to GLM")
        child.add_argument(
            "--max-auto-risk",
            choices=["safe", "unknown", "state_change", "external_effect", "critical"],
            help="Explicit approval ceiling for unattended actions",
        )
    explore = subparsers.choices["explore"]
    explore.add_argument("--max-steps", type=int, help="Maximum executed UI transitions")
    explore.add_argument(
        "--no-codex-analysis",
        action="store_true",
        help="Collect observations without running Codex analysis after exploration",
    )
    analyze = subparsers.add_parser(
        "analyze", help="Analyze a saved run with Codex and merge the feature inventory"
    )
    analyze.add_argument("run_dir", nargs="?", type=Path, help="Run directory; defaults to latest")
    analyze.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    analyze.add_argument("--force", action="store_true", help="Re-analyze steps that already have Codex output")
    return parser


def load_config(args: argparse.Namespace) -> ExplorerConfig:
    return ExplorerConfig.from_file(
        args.config,
        max_steps=getattr(args, "max_steps", None),
        max_auto_risk=getattr(args, "max_auto_risk", None),
        glm_enabled=True if getattr(args, "glm", False) else None,
        vision=True if getattr(args, "vision", False) else None,
        goal=getattr(args, "goal", None),
    )


def codex_analyzer(config: ExplorerConfig) -> CodexInventoryAnalyzer:
    return CodexInventoryAnalyzer(
        config=config.codex,
        workspace_dir=config.config_path.parent.parent,
        inventory_path=config.inventory_path,
        schema_path=config.codex_schema,
    )


def latest_run(output_dir: Path) -> Path:
    candidates = sorted(
        (
            path
            for path in output_dir.glob("*-auto-explore*")
            if path.is_dir() and any(path.glob("step-*"))
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise CodexAnalysisError(f"No saved exploration run found under {output_dir}")
    return candidates[0]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args)
        analyzer = codex_analyzer(config)

        if args.command == "analyze":
            run_dir = args.run_dir.resolve() if args.run_dir else latest_run(config.output_dir)
            result = analyzer.analyze_run(run_dir, force=args.force)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result.get("status") in {"completed", "already_analyzed"} else 1

        explorer = AutoExplorer(config)
        if args.command == "doctor":
            result = explorer.doctor()
            result["codex"] = analyzer.doctor()
            result["ok"] = bool(result.get("ok") and result["codex"].get("ok"))
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result.get("ok") else 1

        print(f"[AUTO] output: {explorer.run_dir}")
        print(f"[AUTO] policy ceiling: {config.max_auto_risk}")
        if config.glm.enabled:
            print(f"[AUTO] GLM: {config.glm.model or '<missing model>'}")
        else:
            print("[AUTO] GLM disabled; deterministic heuristic fallback will be used")
        result = explorer.run()
        should_analyze = bool(
            config.codex.enabled
            and config.codex.auto_analyze_after_explore
            and not args.no_codex_analysis
            and result.get("executed_steps", 0) > 0
        )
        if should_analyze:
            codex_result = analyzer.analyze_run(explorer.run_dir)
            result["codex_analysis"] = codex_result
            result["normal_behavior_analyzer"] = "codex"
        elif result.get("executed_steps", 0) > 0:
            result["normal_behavior_analyzer"] = "pending_codex"
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("status") == "completed" else 1
    except Exception as exc:
        print(f"[AUTO] failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
