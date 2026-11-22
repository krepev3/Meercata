"""CLI-only operator interface for implemented v2 capabilities."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence, TextIO

from meercata import __version__
from meercata.errors import HealthConfigurationError, MeercataError
from meercata.health import HealthService
from meercata.health_models import HealthReport, render_health_report
from meercata.monitor import MonitorService
from meercata.monitor_delivery import DeliveryOutbox
from meercata.paths import MeercataPaths
from meercata.rule_models import RuleDiff
from meercata.ruleops import RuleOpsService
from meercata.state_store import StateStore


class HealthProvider(Protocol):
    def collect(self) -> HealthReport: ...


class RuleProvider(Protocol):
    def status(self) -> dict[str, object]: ...
    def stage(self) -> dict[str, object]: ...
    def diff(self, candidate_id: str) -> RuleDiff: ...
    def validate(self, candidate_id: str) -> dict[str, object]: ...
    def regress(self, candidate_id: str, pack_id: str) -> dict[str, object]: ...
    def promote(self, candidate_id: str) -> None: ...


class MonitorProvider(Protocol):
    def run(self) -> dict[str, object]: ...
    def status(self) -> dict[str, object]: ...
    def events(self, limit: int) -> list[dict[str, object]]: ...
    def freshness(self) -> dict[str, object]: ...


class DeliveryProvider(Protocol):
    def deliver(self) -> dict[str, object]: ...
    def status(self) -> dict[str, object]: ...
    def dead_letters(self, limit: int) -> list[dict[str, object]]: ...
    def health(self) -> dict[str, object]: ...


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meercata",
        description="CLI-only transactional Suricata control plane",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("menu", help="open the interactive terminal dashboard")

    paths_parser = commands.add_parser("paths", help="show fixed production paths")
    paths_parser.add_argument("--json", action="store_true", dest="as_json")

    health_parser = commands.add_parser("health", help="collect read-only production health")
    health_parser.add_argument("--json", action="store_true", dest="as_json")
    health_parser.add_argument("--watch", action="store_true")
    health_parser.add_argument(
        "--interval",
        type=float,
        help="watch interval in seconds (0.5 to 300; defaults to configuration)",
    )

    monitor_parser = commands.add_parser(
        "monitor", help="record and inspect durable health transitions"
    )
    monitor_commands = monitor_parser.add_subparsers(dest="monitor_command")
    monitor_run = monitor_commands.add_parser(
        "run", help="collect health and durably record a changed condition"
    )
    monitor_run.add_argument("--json", action="store_true", dest="as_json")
    monitor_status = monitor_commands.add_parser(
        "status", help="show the most recently observed monitor state"
    )
    monitor_status.add_argument("--json", action="store_true", dest="as_json")
    monitor_events = monitor_commands.add_parser(
        "events", help="show the most recent transition events"
    )
    monitor_events.add_argument("--json", action="store_true", dest="as_json")
    monitor_events.add_argument("--limit", type=int, default=20)
    monitor_freshness = monitor_commands.add_parser(
        "freshness", help="verify that scheduled monitor observations are current"
    )
    monitor_freshness.add_argument("--json", action="store_true", dest="as_json")
    monitor_deliver = monitor_commands.add_parser(
        "deliver", help="deliver due transition envelopes from the durable outbox"
    )
    monitor_deliver.add_argument("--json", action="store_true", dest="as_json")
    monitor_delivery_status = monitor_commands.add_parser(
        "delivery-status", help="show bounded outbox and dead-letter counts"
    )
    monitor_delivery_status.add_argument(
        "--json", action="store_true", dest="as_json"
    )
    monitor_delivery_health = monitor_commands.add_parser(
        "delivery-health", help="evaluate bounded outbox and dead-letter pressure"
    )
    monitor_delivery_health.add_argument(
        "--json", action="store_true", dest="as_json"
    )
    monitor_dead_letters = monitor_commands.add_parser(
        "dead-letters", help="inspect bounded undeliverable transition envelopes"
    )
    monitor_dead_letters.add_argument("--json", action="store_true", dest="as_json")
    monitor_dead_letters.add_argument("--limit", type=int, default=20)

    transaction_parser = commands.add_parser(
        "transactions",
        help="inspect durable transaction state",
    )
    transaction_commands = transaction_parser.add_subparsers(dest="transaction_command")
    list_parser = transaction_commands.add_parser("list", help="list transactions")
    list_filter = list_parser.add_mutually_exclusive_group()
    list_filter.add_argument("--incomplete", action="store_true")
    list_filter.add_argument("--recovery-required", action="store_true")
    list_parser.add_argument("--json", action="store_true", dest="as_json")
    show_parser = transaction_commands.add_parser("show", help="show one transaction")
    show_parser.add_argument("transaction_id")
    show_parser.add_argument("--json", action="store_true", dest="as_json")

    rules_parser = commands.add_parser("rules", help="stage and inspect Suricata rules")
    rules_commands = rules_parser.add_subparsers(dest="rules_command")
    rules_status = rules_commands.add_parser("status", help="show active and candidate status")
    rules_status.add_argument("--json", action="store_true", dest="as_json")
    rules_stage = rules_commands.add_parser("stage", help="build an ET/Open candidate")
    rules_stage.add_argument("--json", action="store_true", dest="as_json")
    rules_diff = rules_commands.add_parser("diff", help="compare a candidate with active rules")
    rules_diff.add_argument("candidate_id")
    rules_diff.add_argument("--json", action="store_true", dest="as_json")
    rules_validate = rules_commands.add_parser("validate", help="validate a staged candidate")
    rules_validate.add_argument("candidate_id")
    rules_validate.add_argument("--json", action="store_true", dest="as_json")
    rules_regress = rules_commands.add_parser(
        "regress", help="run an immutable PCAP pack against a validated candidate"
    )
    rules_regress.add_argument("candidate_id")
    rules_regress.add_argument("pack_id")
    rules_regress.add_argument("--json", action="store_true", dest="as_json")
    rules_promote = rules_commands.add_parser(
        "promote", help="promote a validated candidate (privileged helper required)"
    )
    rules_promote.add_argument("candidate_id")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    paths: MeercataPaths | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    stdin: TextIO | None = None,
    health_factory: Callable[[MeercataPaths], HealthProvider] | None = None,
    monitor_factory: Callable[[MeercataPaths], MonitorProvider] | None = None,
    delivery_factory: Callable[[MeercataPaths], DeliveryProvider] | None = None,
    rules_factory: Callable[[MeercataPaths], RuleProvider] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    watch_iterations: int | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    stdin = stdin or sys.stdin
    parser = build_parser()
    arguments = parser.parse_args(argv)
    selected_paths = paths or MeercataPaths.production()
    try:
        if arguments.command == "menu" or (
            arguments.command is None and stdin.isatty() and stdout.isatty()
        ):
            if not stdin.isatty() or not stdout.isatty():
                print("meercata: menu requires an interactive input and output terminal; "
                      "use --help for scriptable commands", file=stderr)
                return 2
            from meercata.menu import TerminalMenu

            def invoke(menu_args: Sequence[str], out: TextIO, err: TextIO) -> int:
                return main(
                    menu_args, paths=selected_paths, stdout=out, stderr=err,
                    stdin=stdin, health_factory=health_factory,
                    monitor_factory=monitor_factory, delivery_factory=delivery_factory,
                    rules_factory=rules_factory, sleeper=sleeper,
                    watch_iterations=watch_iterations,
                )

            return TerminalMenu(selected_paths, invoke, stdin, stdout, stderr).run()
        if arguments.command == "paths":
            return _show_paths(selected_paths, arguments.as_json, stdout)
        if arguments.command == "health":
            return _run_health(
                selected_paths,
                as_json=arguments.as_json,
                watch=arguments.watch,
                interval=arguments.interval,
                stdout=stdout,
                health_factory=health_factory or HealthService.from_paths,
                sleeper=sleeper,
                watch_iterations=watch_iterations,
            )
        if arguments.command == "monitor":
            if arguments.monitor_command is None:
                parser.print_help(stdout)
                return 2
            monitor = None
            if arguments.monitor_command in {"run", "status", "events", "freshness"}:
                monitor = (monitor_factory or MonitorService.from_paths)(selected_paths)
            if arguments.monitor_command == "run":
                assert monitor is not None
                value = monitor.run()
                _print_monitor(value, arguments.as_json, stdout)
                return int(value["exit_code"])
            if arguments.monitor_command == "status":
                assert monitor is not None
                value = monitor.status()
                _print_monitor(value, arguments.as_json, stdout)
                return 3 if value.get("status") == "uninitialized" else 0
            if arguments.monitor_command == "events":
                assert monitor is not None
                events = monitor.events(arguments.limit)
                if arguments.as_json:
                    print(json.dumps(events, sort_keys=True), file=stdout)
                else:
                    for event in events:
                        print(
                            f"{event['sequence']} {event['generated_utc']} "
                            f"{event['reason']} {event['current']['status']}",
                            file=stdout,
                        )
                return 0
            if arguments.monitor_command == "freshness":
                assert monitor is not None
                value = monitor.freshness()
                _print_monitor(value, arguments.as_json, stdout)
                return int(value["exit_code"])
            delivery = (delivery_factory or DeliveryOutbox.from_paths)(selected_paths)
            if arguments.monitor_command == "deliver":
                value = delivery.deliver()
                _print_delivery(value, arguments.as_json, stdout)
                return 2 if int(value["dead_lettered"]) else 0
            if arguments.monitor_command == "delivery-status":
                value = delivery.status()
                _print_delivery(value, arguments.as_json, stdout)
                return 2 if int(value["dead_letters"]) else 0
            if arguments.monitor_command == "delivery-health":
                value = delivery.health()
                _print_delivery(value, arguments.as_json, stdout)
                return int(value["exit_code"])
            if arguments.monitor_command == "dead-letters":
                values = delivery.dead_letters(arguments.limit)
                if arguments.as_json:
                    print(json.dumps(values, sort_keys=True), file=stdout)
                else:
                    for value in values:
                        print(
                            f"{value['sequence']} {value['event_id']} "
                            f"attempts={value['attempts']} error={value['last_error']}",
                            file=stdout,
                        )
                return 0
        if arguments.command == "transactions":
            if arguments.transaction_command == "list":
                return _list_transactions(
                    StateStore(selected_paths),
                    arguments.incomplete,
                    arguments.recovery_required,
                    arguments.as_json,
                    stdout,
                )
            if arguments.transaction_command == "show":
                return _show_transaction(
                    StateStore(selected_paths),
                    arguments.transaction_id,
                    arguments.as_json,
                    stdout,
                )
        if arguments.command == "rules":
            if arguments.rules_command is None:
                parser.print_help(stdout)
                return 2
            rules = (rules_factory or RuleOpsService.from_paths)(selected_paths)
            if arguments.rules_command == "status":
                return _print_rule_value(rules.status(), arguments.as_json, stdout)
            if arguments.rules_command == "stage":
                return _print_rule_value(rules.stage(), arguments.as_json, stdout)
            if arguments.rules_command == "diff":
                value = rules.diff(arguments.candidate_id)
                return _print_rule_value(value.to_dict(), arguments.as_json, stdout)
            if arguments.rules_command == "validate":
                return _print_rule_value(
                    rules.validate(arguments.candidate_id), arguments.as_json, stdout
                )
            if arguments.rules_command == "regress":
                return _print_rule_value(
                    rules.regress(arguments.candidate_id, arguments.pack_id),
                    arguments.as_json,
                    stdout,
                )
            if arguments.rules_command == "promote":
                rules.promote(arguments.candidate_id)
                return 0
        parser.print_help(stdout)
        return 2
    except MeercataError as exc:
        print(f"meercata: {exc}", file=stderr)
        return 3


def _show_paths(paths: MeercataPaths, as_json: bool, stdout: TextIO) -> int:
    values = {
        "config_dir": str(paths.config_dir),
        "package_dir": str(paths.package_dir),
        "state_dir": str(paths.state_dir),
        "log_dir": str(paths.log_dir),
        "run_dir": str(paths.run_dir),
    }
    if as_json:
        print(json.dumps(values, sort_keys=True), file=stdout)
    else:
        for name, value in values.items():
            print(f"{name}: {value}", file=stdout)
    return 0


def _run_health(
    paths: MeercataPaths,
    *,
    as_json: bool,
    watch: bool,
    interval: float | None,
    stdout: TextIO,
    health_factory: Callable[[MeercataPaths], HealthProvider],
    sleeper: Callable[[float], None],
    watch_iterations: int | None,
) -> int:
    if interval is not None and not 0.5 <= interval <= 300:
        report = HealthReport.configuration_error(
            "health watch interval must be between 0.5 and 300 seconds"
        )
        _print_health(report, as_json, stdout)
        return report.exit_code
    try:
        provider = health_factory(paths)
    except HealthConfigurationError as exc:
        report = HealthReport.configuration_error(str(exc))
        _print_health(report, as_json, stdout)
        return report.exit_code

    configured_interval = (
        provider.collector.config.thresholds.watch_interval_seconds
        if isinstance(provider, HealthService)
        else 5.0
    )
    selected_interval = interval if interval is not None else configured_interval
    iterations = 0
    last_exit = 3
    while True:
        try:
            report = provider.collect()
        except Exception as exc:
            report = HealthReport.configuration_error(
                f"health collection failed: {type(exc).__name__}"
            )
        _print_health(report, as_json, stdout)
        last_exit = report.exit_code
        iterations += 1
        if not watch or (watch_iterations is not None and iterations >= watch_iterations):
            return last_exit
        try:
            sleeper(selected_interval)
        except KeyboardInterrupt:
            return 130


def _print_health(report: HealthReport, as_json: bool, stdout: TextIO) -> None:
    if as_json:
        print(json.dumps(report.to_dict(), sort_keys=True), file=stdout, flush=True)
    else:
        print(render_health_report(report), file=stdout, flush=True)


def _print_monitor(value: Mapping[str, object], as_json: bool, stdout: TextIO) -> None:
    if as_json:
        print(json.dumps(value, sort_keys=True), file=stdout, flush=True)
        return
    status = str(value.get("status", "unknown")).upper()
    sequence = value.get("sequence", "-")
    emitted = value.get("transition_emitted")
    suffix = "" if emitted is None else f" transition={'yes' if emitted else 'no'}"
    print(f"Meercata monitor: {status} sequence={sequence}{suffix}", file=stdout)


def _print_delivery(value: Mapping[str, object], as_json: bool, stdout: TextIO) -> None:
    if as_json:
        print(json.dumps(value, sort_keys=True), file=stdout, flush=True)
        return
    print(
        "Meercata delivery: "
        f"pending={value.get('pending', 0)} "
        f"delivered={value.get('delivered', 0)} "
        f"dead_letters={value.get('dead_letters', value.get('dead_lettered', 0))}",
        file=stdout,
    )


def _list_transactions(
    store: StateStore,
    incomplete: bool,
    recovery_required: bool,
    as_json: bool,
    stdout: TextIO,
) -> int:
    if recovery_required:
        records = store.list_recovery_required()
    elif incomplete:
        records = store.list_incomplete()
    else:
        records = store.list_records()
    if as_json:
        print(json.dumps([record.to_dict() for record in records], sort_keys=True), file=stdout)
        return 0
    if not records:
        print("No transactions found.", file=stdout)
        return 0
    for record in records:
        print(
            f"{record.transaction_id} {record.state.value} {record.operation} {record.updated_utc}",
            file=stdout,
        )
    return 0


def _show_transaction(
    store: StateStore,
    transaction_id: str,
    as_json: bool,
    stdout: TextIO,
) -> int:
    record = store.load(transaction_id)
    if as_json:
        print(json.dumps(record.to_dict(), indent=2, sort_keys=True), file=stdout)
    else:
        print(f"transaction_id: {record.transaction_id}", file=stdout)
        print(f"operation: {record.operation}", file=stdout)
        print(f"state: {record.state.value}", file=stdout)
        print(f"actor: uid={record.actor.uid} gid={record.actor.gid}", file=stdout)
        print(f"created_utc: {record.created_utc}", file=stdout)
        print(f"updated_utc: {record.updated_utc}", file=stdout)
    return 0


def _print_rule_value(value: dict[str, object], as_json: bool, stdout: TextIO) -> int:
    if as_json:
        print(json.dumps(value, sort_keys=True), file=stdout)
        return 0
    if "candidate_id" in value:
        print(f"candidate_id: {value['candidate_id']}", file=stdout)
    if "status" in value:
        print(f"status: {value['status']}", file=stdout)
    if "source" in value:
        print(f"source: {value['source']}", file=stdout)
    active = value.get("active")
    if isinstance(active, dict):
        print(f"active_exists: {str(active.get('exists', False)).lower()}", file=stdout)
        if active.get("exists"):
            print(f"active_rules: {active.get('active_rules', 0)}", file=stdout)
            print(f"active_sha256: {active.get('sha256', '')}", file=stdout)
    if "candidate_count" in value:
        print(f"candidate_count: {value['candidate_count']}", file=stdout)
    for key in (
        "baseline_count",
        "candidate_count",
        "added_total",
        "removed_total",
        "changed_total",
        "reduction_percent",
        "policy_allowed",
    ):
        if key in value and not (key == "candidate_count" and "active" in value):
            print(f"{key}: {value[key]}", file=stdout)
    for key in ("added", "removed", "changed", "policy_reasons"):
        values = value.get(key)
        if isinstance(values, list):
            print(f"{key}: {', '.join(str(item) for item in values) or '-'}", file=stdout)
    return 0
