"""Interactive terminal presentation of the existing, gated v2 CLI.

Opening or navigating the menu does not collect health, start services, or
create state. Every executable action delegates to a fixed CLI argument list.
"""

from __future__ import annotations

import io
import json
import os
from typing import Callable, Sequence, TextIO
from uuid import UUID

from meercata import __version__
from meercata.errors import MeercataError
from meercata.health_config import load_health_config
from meercata.paths import MeercataPaths
from meercata.pcap_regression import IDENTIFIER

BANNER = r"""
  |  \/  |  ___   ___  _ __  ___  __ _ | |_  __ _
  | |\/| | / _ \ / _ \| '__|/ __|/ _` || __|/ _` |
  | |  | ||  __/|  __/| |  | (__| (_| || |_| (_| |
  |_|  |_| \___| \___||_|   \___|\__,_| \__|\__,_|
  developer: Kreczlyxt
"""
Invoke = Callable[[Sequence[str], TextIO, TextIO], int]
Action = Callable[[], None]


def _plain(value: object) -> str:
    """Prevent configuration, event, and error text from controlling the terminal."""
    return "".join(
        char if char in "\n\t" or (ord(char) >= 32 and not 127 <= ord(char) <= 159)
        else f"\\x{ord(char):02x}"
        for char in str(value)
    )


class _Output:
    """Stream CLI output without accumulating a continuous health watch."""

    def __init__(self, stream: TextIO) -> None:
        self.stream = stream

    def write(self, value: str) -> int:
        self.stream.write(_plain(value))
        return len(value)

    def flush(self) -> None:
        self.stream.flush()


class TerminalMenu:
    def __init__(
        self, paths: MeercataPaths, invoke: Invoke,
        stdin: TextIO, stdout: TextIO, stderr: TextIO,
    ) -> None:
        self.paths = paths
        self.invoke = invoke
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.last_health = "NOT CHECKED (select Check requirements / health)"
        self.last_service = "NOT CHECKED"
        self.terminal = stdout.isatty() and os.environ.get("TERM", "dumb") != "dumb"
        self.color = self.terminal and "NO_COLOR" not in os.environ

    def run(self) -> int:
        try:
            self._menu("Main menu", (
                ("Suricata control", self._suricata),
                ("Threat Monitoring / health events", self._monitoring),
                ("Rules / YAML", self._rules),
                ("Hooks / firewall", self._firewall),
                ("Systemd / supervision", self._systemd),
                ("Configuration / paths (read-only)", lambda: self._perform(self._configuration)),
                ("Check requirements / health", self._health),
                ("Transactions / recovery", self._transactions),
            ), root=True)
        except EOFError:
            self._print("\nInput closed. Bye.")
            return 0
        except KeyboardInterrupt:
            self._print("\nBye.")
            return 130
        self._print("Bye.")
        return 0

    def _print(self, value: object = "") -> None:
        print(_plain(value), file=self.stdout, flush=True)

    def _read(self, prompt: str) -> str:
        print(prompt, end="", file=self.stdout, flush=True)
        value = self.stdin.readline()
        if value == "":
            raise EOFError
        return value.strip()

    def _header(self, title: str) -> None:
        if self.terminal:
            print("\033[2J\033[H", end="", file=self.stdout)
        if self.color:
            print(f"\033[38;5;208m{BANNER}\033[0m", file=self.stdout)
        else:
            self._print(BANNER)
        self._print(f"  MEERCATA v2.00 | {__version__} | interactive")
        self._print(f"  Configuration : {self.paths.controller_config_file}")
        try:
            config = load_health_config(self.paths)
            self._print(f"  Profile       : {config.mode.upper()} | interface={config.interface} "
                        f"| queue={config.queue} | backend=nftables")
        except (MeercataError, OSError):
            self._print("  Profile       : UNCONFIGURED / UNREADABLE (menu remains available)")
        self._print(f"  Last health   : {self.last_health}")
        self._print(f"  Last service  : {self.last_service}")
        self._print("  Development build: public IDS/IPS start and live rule promotion unavailable.")
        self._print(f"\n-- {title} --\n")

    def _menu(self, title: str, items: Sequence[tuple[str, Action]], *, root: bool = False) -> None:
        while True:
            self._header(title)
            for number, (label, _) in enumerate(items, 1):
                self._print(f"{number}) {label}")
            self._print("0) Quit" if root else "0) Back")
            try:
                choice = self._read("\nSelect option: ")
            except KeyboardInterrupt:
                if root:
                    raise
                return
            if choice in {"0", ""}:
                return
            actions = {str(number): action for number, (_, action) in enumerate(items, 1)}
            action = actions.get(choice)
            if action is None:
                self._perform(lambda: self._print("[ERR] Invalid selection."))
            else:
                action()

    def _perform(self, action: Action, confirmation: str | None = None) -> None:
        try:
            self._print()
            if confirmation and self._read(f"{confirmation} [y/N]: ").lower() not in {"y", "yes"}:
                self._print("Cancelled.")
            else:
                action()
        except KeyboardInterrupt:
            self._print("\nInterrupted. Returning to the menu.")
        except PermissionError:
            self._print("[ERR] Access denied. This action needs the installed service/operator permissions.")
        except (MeercataError, OSError, ValueError) as exc:
            self._print(f"[ERR] {exc}")
        try:
            self._read("\nPress Enter to continue...")
        except KeyboardInterrupt:
            self._print()

    def _execute(self, argv: Sequence[str], *, pretty: bool = False) -> None:
        self._print("$ meercata " + " ".join(argv))
        output = io.StringIO() if pretty else _Output(self.stdout)
        code = self.invoke(argv, output, _Output(self.stderr))
        if pretty:
            text = output.getvalue()
            if text.strip():
                try:
                    self._print(json.dumps(json.loads(text), indent=2, ensure_ascii=True))
                except ValueError:
                    self._print(text)
        self._print(f"\nCommand exit code: {code}")
        if code == 3:
            self._print("Check configuration, installed permissions, and the reported error.")
        elif code == 130:
            self._print("Watch stopped.")

    def _command(self, *argv: str, confirmation: str | None = None, pretty: bool = False) -> Action:
        return lambda: self._perform(lambda: self._execute(argv, pretty=pretty), confirmation)

    def _unavailable(self, reason: str) -> Action:
        return lambda: self._perform(lambda: self._print(f"[UNAVAILABLE] {reason}"))

    def _health(self) -> None:
        self._perform(self._refresh_health)

    def _refresh_health(self) -> None:
        self.last_health = "UNKNOWN (refresh did not complete)"
        self.last_service = "UNKNOWN"
        output = io.StringIO()
        code = self.invoke(("health", "--json"), output, _Output(self.stderr))
        if not output.getvalue().strip():
            self._print(f"Health collection returned no report (exit {code}).")
            return
        report = json.loads(output.getvalue())
        self.last_health = f"{report['status'].upper()} at {report['generated_local']}"
        self._print(f"Health: {report['status'].upper()} | mode={report['mode']} | exit={code}")
        for check in report["checks"]:
            self._print(f"  {check['status'].upper():8} {check['id']:22} {check['summary']}")
            if check.get("remediation"):
                self._print(f"           -> {check['remediation']}")
            if check["id"] == "service":
                self.last_service = str(check["summary"])
        self._print("\nThis is a point-in-time health check; use health watch for continuous sampling.")

    def _suricata(self) -> None:
        self._menu("Suricata control", (
            ("IDS (sniff-only) [unavailable]", self._unavailable(
                "The public IDS start/stop workflow has not been migrated. "
                "Installed lab IDS runs through the configured Suricata systemd service.")),
            ("IPS (NFQUEUE inline) [gated]", self._unavailable(
                "Public IPS activation is release-gated. The private qualification target is not exposed here.")),
            ("Status / refresh health", self._health),
            ("Watch health (Ctrl+C to stop)", self._command("health", "--watch")),
            ("Monitoring", self._monitoring),
        ))

    def _monitoring(self) -> None:
        self._menu("Threat Monitoring / health events", (
            ("Threat evidence viewer [not migrated]", self._unavailable(
                "The v1 EVE alert/drop evidence viewer has not been migrated. "
                "The working entries below show controller health events, not packet alerts.")),
            ("Last monitoring state", self._command("monitor", "status", "--json", pretty=True)),
            ("Recent health transitions", self._command("monitor", "events", "--json", "--limit", "20", pretty=True)),
            ("Collect and record health now", self._command("monitor", "run", "--json", pretty=True,
                confirmation="Record a health observation and enqueue any new transition?")),
            ("Check monitoring freshness", self._command("monitor", "freshness", "--json", pretty=True)),
            ("Watch health (Ctrl+C to stop)", self._command("health", "--watch")),
            ("HTTPS delivery", self._delivery),
        ))

    def _delivery(self) -> None:
        self._menu("HTTPS delivery", (
            ("Queue status", self._command("monitor", "delivery-status", "--json", pretty=True)),
            ("Delivery health", self._command("monitor", "delivery-health", "--json", pretty=True)),
            ("Undeliverable events", self._command("monitor", "dead-letters", "--json", "--limit", "20", pretty=True)),
            ("Deliver due events now", self._command("monitor", "deliver", "--json", pretty=True,
                confirmation="Send due health events to the root-configured HTTPS collector?")),
        ))

    def _rules(self) -> None:
        self._menu("Rules / YAML", (
            ("Active rules / latest candidate", self._command("rules", "status", "--json", pretty=True)),
            ("Stage an ET/Open candidate", self._command("rules", "stage", "--json", pretty=True,
                confirmation="Download and stage ET/Open rules, writing candidate state and audit records?")),
            ("Compare candidate with active rules", lambda: self._perform(lambda: self._candidate("diff"))),
            ("Validate candidate", lambda: self._perform(lambda: self._candidate("validate"))),
            ("Test candidate against a PCAP pack", lambda: self._perform(lambda: self._candidate("regress"))),
            ("Promote candidate [gated]", self._unavailable("Live rule promotion remains release-gated.")),
            ("Edit rules / YAML [not migrated]", self._unavailable(
                "Direct YAML editing and rule toggles have not been migrated to the v2 transaction workflow.")),
        ))

    def _uuid(self, prompt: str) -> str | None:
        value = self._read(prompt + " (blank cancels): ")
        if not value:
            self._print("Cancelled.")
            return None
        try:
            if str(UUID(value)) != value:
                raise ValueError
        except ValueError:
            raise ValueError("Enter a canonical lowercase UUID from the status/list output.") from None
        return value

    def _candidate(self, operation: str) -> None:
        candidate = self._uuid("Candidate ID")
        if candidate is None:
            return
        argv = ["rules", operation, candidate]
        if operation == "regress":
            pack = self._read("PCAP pack ID (for example production-baseline-v1; blank cancels): ")
            if not pack:
                self._print("Cancelled.")
                return
            if IDENTIFIER.fullmatch(pack) is None:
                raise ValueError("Pack ID must start with a lowercase letter or digit and contain "
                                 "1-64 lowercase letters, digits, dots, hyphens or underscores.")
            argv.append(pack)
        if operation != "diff" and self._read(
            "Run candidate testing and write its result/audit records? [y/N]: "
        ).lower() not in {"y", "yes"}:
            self._print("Cancelled.")
            return
        self._execute((*argv, "--json"), pretty=True)

    def _firewall(self) -> None:
        self._menu("Hooks / firewall", (
            ("Inspect configured capture health (includes hooks in IPS mode)", self._health),
            ("Activation / cleanup / bypass [gated]", self._unavailable(
                "The menu exposes no firewall mutations. v2 owns only its nftables table; "
                "the transaction-bound activation and bypass helpers remain private.")),
        ))

    def _systemd(self) -> None:
        self._menu("Systemd / supervision", (
            ("Suricata readiness / health", self._health),
            ("Monitor freshness", self._command("monitor", "freshness", "--json", pretty=True)),
            ("Delivery health", self._command("monitor", "delivery-health", "--json", pretty=True)),
            ("Enable / start / stop services [unavailable]", self._unavailable(
                "Service lifecycle changes are not exposed in the v2 menu. "
                "Package installation enables no services or timers.")),
        ))

    def _configuration(self) -> None:
        self._print("Configuration is read-only here; no v1 home-directory defaults are imported.")
        self._print(f"Controller configuration: {self.paths.controller_config_file}")
        self._print(f"Suricata configuration: {self.paths.suricata_config_file}")
        self._execute(("paths",))
        config = load_health_config(self.paths)
        self._print(f"Mode: {config.mode} | interface: {config.interface} | queue: {config.queue}")
        self._print(f"EVE: {config.eve_path}\nSocket: {config.socket_path}")
        self._print("Configuration editing is not migrated. Credentials are never displayed.")

    def _transactions(self) -> None:
        self._menu("Transactions / recovery", (
            ("List transactions", self._command("transactions", "list")),
            ("Incomplete transactions", self._command("transactions", "list", "--incomplete")),
            ("Recovery-required transactions", self._command("transactions", "list", "--recovery-required")),
            ("Inspect a transaction", lambda: self._perform(self._transaction)),
        ))

    def _transaction(self) -> None:
        transaction = self._uuid("Transaction ID")
        if transaction is not None:
            self._execute(("transactions", "show", transaction, "--json"), pretty=True)
