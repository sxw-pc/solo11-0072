"""argparse 命令行入口。"""
from __future__ import annotations
import argparse
import sys
from dataclasses import replace
from .audit import outcome_json, run_audit
from .config import ALLOWED_FAIL_ON, load_config
from .util import QianshenError

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qianshen", description="迁签审台：本地 SQL 迁移脚本静态评审与审计留痕"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit = subparsers.add_parser("audit", help="评审一个迁移目录")
    audit.add_argument("--config", default="qianshen.yml", help="主配置 YAML")
    audit.add_argument("--migrations", help="覆盖 migrations_dir")
    audit.add_argument("--out", help="覆盖报告输出目录")
    audit.add_argument("--ledger", help="覆盖 SQLite 台账路径")
    audit.add_argument("--now", help="注入确定性 ISO 8601 时钟")
    audit.add_argument("--fail-on", choices=ALLOWED_FAIL_ON, help="覆盖退出阈值")
    audit.add_argument("--no-cache", action="store_true", help="禁用本地解析与类型状态缓存")
    audit.add_argument("--quiet", action="store_true", help="不输出摘要")
    demo = subparsers.add_parser("demo", help="运行六个内置 fixture 的离线演示")
    demo.add_argument("--out", default=".qianshen-demo", help="演示输出目录")
    demo.add_argument("--now", default="2026-01-01T00:00:00Z", help="演示固定时钟")
    return parser

def _run_audit(args: argparse.Namespace) -> int:
    config = load_config(
        args.config,
        migrations_override=args.migrations,
        out_override=args.out,
        ledger_override=args.ledger,
        now_override=args.now,
    )
    if args.fail_on:
        config = replace(config, fail_on=args.fail_on)
    if args.no_cache:
        config = replace(config, cache_enabled=False)
    outcome = run_audit(config)
    if not args.quiet:
        print(outcome_json(outcome))
        print(f"报告目录: {config.output_dir}")
    return outcome.exit_code

def _run_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo
    result = run_demo(args.out, now=args.now)
    print(result["summary_text"])
    print(f"演示目录: {result['output_dir']}")
    return 0

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            return _run_demo(args)
        return _run_audit(args)
    except QianshenError as exc:
        print(f"qianshen: {exc}", file=sys.stderr)
        return exc.exit_code
    except Exception as exc:  # 未预期内部错误按约定返回 3，不泄露堆栈到 CI 日志
        print(f"qianshen: 内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
if __name__ == "__main__":
    raise SystemExit(main())
