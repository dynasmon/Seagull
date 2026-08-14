from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from .config import env as _env
from .stack import compose as _compose
from .config import state as _state
from .security import tokens as _tokens
from .stack import deps as _deps
from .stack import geoip as _geoip
from .stack import health as _health
from .config import wizard as _wizard


class _MissingHostDependency:
    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, attr: str):
        raise RuntimeError(
            f"python package {self._name!r} is not installed on this host; "
            f"fix: {_deps.INSTALL_HINT}"
        )


try:
    from .stack import preflight as _preflight
    from .stack import prepare as _prepare
except ModuleNotFoundError as exc:
    _preflight = _MissingHostDependency(exc.name or "cryptography")
    _prepare = _MissingHostDependency(exc.name or "cryptography")


def _clear_bootstrap_tokens() -> None:
    bootstrap_dir = _env.root() / "secrets" / "bootstrap"
    if bootstrap_dir.exists():
        for f in bootstrap_dir.glob("*.token"):
            f.unlink()


def _reload_edge_certificates(files: list[str], reissued: bool) -> None:
    if not reissued:
        return
    print("[edge] restarting caddy to serve the reissued mTLS server certificate")
    _compose.run(files, ["restart", "caddy"])


def _up_dev(
    files: list[str],
    persist: bool,
) -> int:
    mtls_reissued = _preflight.run()

    rc = _compose.run(
        files, ["up", "-d", "--build", "--remove-orphans"], persist_redis=persist
    ).returncode
    if rc != 0:
        return rc

    _reload_edge_certificates(files, mtls_reissued)

    print()
    if not _health.wait_healthy(files, _health.ESSENTIAL_DEV):
        print()
        _health.print_summary(files)
        return 1

    print()
    _health.print_summary(files)
    return 0


def _up_prod(fresh: bool) -> int:
    mtls_reissued = _prepare.run()

    if fresh:
        _compose.run(_compose.STACK_FILES, ["down", "-v", "--remove-orphans"])
        _clear_bootstrap_tokens()
        _state.clear()
    else:
        result, msg = _state.check()
        if result in (_state.DRIFT, _state.ORPHAN_VOLUMES):
            print(msg, file=sys.stderr)
            print(
                "[up] refusing to start: the runtime volumes were initialized with a "
                "different configuration\n"
                "     review the change, then rerun with ./seagull up --fresh to drop "
                "the named volumes and start clean (all stored data is lost),\n"
                "     or restore the previous values so the running data stays usable",
                file=sys.stderr,
            )
            return 1

    rc = _compose.run(
        _compose.STACK_FILES,
        ["up", "-d", "--build", "--remove-orphans"] + _compose.PROD_CORE_SERVICES,
    ).returncode
    if rc != 0:
        return rc

    _reload_edge_certificates(_compose.STACK_FILES, mtls_reissued)

    print()
    if not _health.wait_healthy(_compose.STACK_FILES, _health.ESSENTIAL_PROD, timeout=180):
        print()
        _health.print_summary(_compose.STACK_FILES)
        return 1

    _state.commit()
    print()
    _health.print_summary(_compose.STACK_FILES)
    return 0


def cmd_up(args: argparse.Namespace) -> int:
    _env.bootstrap()
    _geoip.ensure()

    mode = getattr(args, "mode", None) or _env.environment()
    persist = getattr(args, "persist", False)
    dev_reload = getattr(args, "dev_reload", False)
    fresh = getattr(args, "fresh", False)

    if mode in _env.PRODUCTION_ENVIRONMENTS:
        return _up_prod(fresh=fresh)

    files = _compose.DEV_RELOAD_FILES if dev_reload else _compose.STACK_FILES
    return _up_dev(files=files, persist=persist)



def cmd_status(args: argparse.Namespace) -> int:
    _health.print_summary(_compose.STACK_FILES)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    _env.bootstrap()
    deps_rc = _deps.check_and_report()
    print()
    if _env.is_production():
        _prepare.run()
    _preflight.run()
    result, msg = _state.check()
    if msg:
        print(msg)
    print(f"[doctor] state: {result}")
    return deps_rc


def cmd_reset(args: argparse.Namespace) -> int:
    volumes = getattr(args, "volumes", False)
    if volumes:
        print("[reset] removing containers and all named volumes (data will be lost)")
        return _compose.run(
            _compose.STACK_FILES, ["down", "-v", "--remove-orphans"]
        ).returncode
    return _compose.run(
        _compose.STACK_FILES, ["down", "--remove-orphans"]
    ).returncode



def cmd_dev(args: argparse.Namespace) -> int:
    persist: bool = getattr(args, "persist", False)
    dev_reload: bool = getattr(args, "dev_reload", False)

    _env.bootstrap()
    _geoip.ensure()
    files = _compose.DEV_RELOAD_FILES if dev_reload else _compose.STACK_FILES
    return _up_dev(files=files, persist=persist)


def cmd_prod(args: argparse.Namespace) -> int:
    fresh: bool = getattr(args, "fresh", False)
    _env.bootstrap()
    _geoip.ensure()
    return _up_prod(fresh=fresh)


def cmd_prod_setup(args: argparse.Namespace) -> int:
    _env.bootstrap()
    _wizard.run()
    _geoip.ensure()
    _prepare.run()
    print("[prod-setup] environment wizard completed and production config validated")
    return 0



def cmd_down(args: argparse.Namespace) -> int:
    return _compose.run(_compose.STACK_FILES, ["down", "--remove-orphans"]).returncode


def cmd_restart(args: argparse.Namespace) -> int:
    persist: bool = getattr(args, "persist", False)
    quick: bool = getattr(args, "quick", False)
    dev_reload: bool = getattr(args, "dev_reload", False)

    _env.bootstrap()
    _geoip.ensure()
    _preflight.run()

    files = _compose.DEV_RELOAD_FILES if dev_reload else _compose.STACK_FILES

    if quick:
        rc = _compose.run(
            files,
            ["up", "-d", "--force-recreate", "--remove-orphans"],
            persist_redis=persist,
        ).returncode
        if rc != 0:
            return rc
        return 0

    _compose.run(files, ["down", "--remove-orphans"], persist_redis=persist)
    rc = _compose.run(
        files,
        ["up", "-d", "--build", "--remove-orphans"],
        persist_redis=persist,
    ).returncode
    if rc != 0:
        return rc
    return 0


def cmd_ps(args: argparse.Namespace) -> int:
    return _compose.run(_compose.STACK_FILES, ["ps"]).returncode


def cmd_logs(args: argparse.Namespace) -> int:
    svc: str | None = getattr(args, "svc", None)
    log_args = ["logs", "-f"]
    if svc:
        log_args.append(svc)
    return _compose.run(_compose.STACK_FILES, log_args).returncode


def cmd_build(args: argparse.Namespace) -> int:
    return _compose.run(_compose.STACK_FILES, ["build"]).returncode


def cmd_pull(args: argparse.Namespace) -> int:
    return _compose.run(_compose.STACK_FILES, ["pull"]).returncode


def cmd_clean(args: argparse.Namespace) -> int:
    return _compose.run(_compose.STACK_FILES, ["down", "--remove-orphans"]).returncode


def cmd_nuke(args: argparse.Namespace) -> int:
    return _compose.run(_compose.STACK_FILES, ["down", "-v", "--remove-orphans"]).returncode


def cmd_psql(args: argparse.Namespace) -> int:
    pg_user = _env.read("POSTGRES_USER", "seagull")
    pg_db = _env.read("POSTGRES_DB", "seagull")
    return _compose.run(
        _compose.STACK_FILES,
        ["exec", "postgres", "psql", "-U", pg_user, "-d", pg_db],
    ).returncode


def cmd_env(args: argparse.Namespace) -> int:
    sub: str = args.env_cmd
    if sub == "bootstrap":
        _env.bootstrap()
        return 0
    if sub == "wizard":
        _wizard.run()
        return 0
    if sub == "prepare":
        _env.bootstrap()
        _prepare.run()
        return 0
    print(f"[seagull] unknown env subcommand: {sub}", file=sys.stderr)
    return 1


def cmd_geoip(args: argparse.Namespace) -> int:
    _env.bootstrap()
    sub: str = args.geoip_cmd
    if sub == "install":
        _geoip.ensure(force=getattr(args, "force", False))
        return 0
    if sub == "status":
        return 0 if _geoip.status() else 1
    print(f"[seagull] unknown geoip subcommand: {sub}", file=sys.stderr)
    return 1


def cmd_agent(args: argparse.Namespace) -> int:
    sub: str = args.agent_cmd
    if sub == "tokens":
        _env.bootstrap()
        output_dir = Path(args.output_dir) if getattr(args, "output_dir", None) else None
        _tokens.mint(args.agent_ids, output_dir=output_dir)
        return 0
    print(f"[seagull] unknown agent subcommand: {sub}", file=sys.stderr)
    return 1


def cmd_admin(args: argparse.Namespace) -> int:
    sub: str = args.admin_cmd
    if sub == "reset":
        _env.bootstrap()
        return _compose.run(
            _compose.STACK_FILES,
            ["run", "--rm", "--build", "-T", "seagull-backend",
             "python", "-m", "app.cli", "admin-reset"],
        ).returncode
    print(f"[seagull] unknown admin subcommand: {sub}", file=sys.stderr)
    return 1


def cmd_state(args: argparse.Namespace) -> int:
    sub: str = args.state_cmd
    if sub == "clear":
        _state.clear()
        print("[state] cleared")
        return 0
    if sub == "check":
        result, msg = _state.check()
        if msg:
            print(msg)
        print(f"[state] {result}")
        return 0 if result == _state.OK else 1
    print(f"[seagull] unknown state subcommand: {sub}", file=sys.stderr)
    return 1


def cmd_db(args: argparse.Namespace) -> int:
    sub: str = args.db_cmd
    if sub == "upgrade":
        return _compose.run(
            _compose.STACK_FILES,
            ["run", "--rm", "--build", "seagull-backend",
             "python", "-m", "alembic", "upgrade", "head"],
        ).returncode
    if sub == "current":
        return _compose.run(
            _compose.STACK_FILES,
            ["run", "--rm", "--build", "seagull-backend",
             "python", "-m", "app.core.db.schema_report"],
        ).returncode
    print(f"[seagull] unknown db subcommand: {sub}", file=sys.stderr)
    return 1


def cmd_lint(args: argparse.Namespace) -> int:
    root = _env.root()
    steps = [
        (["python3", "-m", "ruff", "check", "app", "tests"], root / "backend"),
        (["lint-imports"], root / "backend"),
        (["npm", "run", "lint"], root / "frontend"),
    ]
    for cmd, cwd in steps:
        rc = subprocess.run(cmd, cwd=str(cwd)).returncode
        if rc != 0:
            return rc
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    detections: bool = getattr(args, "detections", False)
    root = _env.root()
    if detections:
        return subprocess.run(
            [
                "python3", "-m", "pytest", "-q",
                "tests/test_rules_and_correlations.py",
                "tests/test_detection_catalog.py",
            ],
            cwd=str(root / "backend"),
        ).returncode
    steps = [(["python3", "-m", "pytest", "-q"], root / "backend")]
    steps.append((["npm", "run", "smoke"], root / "frontend"))
    for cmd, cwd in steps:
        rc = subprocess.run(cmd, cwd=str(cwd)).returncode
        if rc != 0:
            return rc
    return 0


def cmd_ci(args: argparse.Namespace) -> int:
    for fn in (cmd_lint, cmd_test):
        rc = fn(args)
        if rc != 0:
            return rc
    return cmd_build(argparse.Namespace())


def cmd_deps(args: argparse.Namespace) -> int:
    if getattr(args, "install", False):
        return _deps.install()
    return _deps.check_and_report()


def _accepted_advisories(backend: Path) -> list[str]:
    accepted = backend / "pip-audit-accepted.txt"
    if not accepted.is_file():
        return []
    args: list[str] = []
    for line in accepted.read_text(encoding="utf-8").splitlines():
        advisory = line.split()[0] if line.split() else ""
        if advisory:
            args.extend(["--ignore-vuln", advisory])
    return args


def cmd_deps_check(args: argparse.Namespace) -> int:
    root = _env.root()
    backend = root / "backend"
    steps = [
        (
            ["python3", "-m", "pip_audit", "-r", "requirements.lock", "--strict"]
            + _accepted_advisories(backend),
            backend,
        ),
        (["npm", "audit", "--audit-level=high"], root / "frontend"),
    ]
    for cmd, cwd in steps:
        rc = subprocess.run(cmd, cwd=str(cwd)).returncode
        if rc != 0:
            return rc
    return 0


def cmd_redis(args: argparse.Namespace) -> int:
    sub: str = args.redis_cmd
    if sub == "repair-aof":
        return subprocess.run(
            ["sh", str(_env.root() / "scripts" / "redis" / "repair-aof.sh")],
            cwd=str(_env.root()),
        ).returncode
    print(f"[seagull] unknown redis subcommand: {sub}", file=sys.stderr)
    return 1


def cmd_observability(args: argparse.Namespace) -> int:
    _env.bootstrap()
    _preflight.run()
    return _compose.run(
        _compose.STACK_FILES,
        ["--profile", "observability", "up", "-d", "--build", "grafana", "kibana"],
    ).returncode



def _print_help() -> None:
    print(
        "Usage: seagull <command> [options]\n"
        "\n"
        "Host setup (new machines):\n"
        "  -d | deps            check host dependencies\n"
        "  -d --install         install missing host dependencies (uses sudo)\n"
        "\n"
        "Stack:\n"
        "  up [--mode dev|prod] [--persist] [--dev-reload] [--fresh]\n"
        "  down\n"
        "  restart [--quick] [--persist]\n"
        "  status\n"
        "  logs [service]\n"
        "  doctor\n"
        "  reset [--volumes]\n"
        "\n"
        "Management:\n"
        "  env bootstrap | wizard | prepare\n"
        "  geoip install [--force] | status\n"
        "  agent tokens --agent-id id [--agent-id id] [--output-dir path]\n"
        "  admin reset\n"
        "  state check | clear\n"
        "  db upgrade | current\n"
        "\n"
        "Dev / CI:\n"
        "  build | pull | psql\n"
        "  lint | test [--detections] | ci | deps-check\n"
        "  observability\n"
        "  redis repair-aof\n"
        "\n"
        "Run ./seagull <command> --help for command-specific options."
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="seagull",
        add_help=False,
    )
    p.add_argument("-h", "--help", action="store_true", default=False)
    sub = p.add_subparsers(dest="command", metavar="command")

    deps_p = sub.add_parser("deps", help="check or install host dependencies (alias: -d)")
    deps_p.add_argument(
        "--install", action="store_true",
        help="install missing host dependencies via deploy/install-deps.sh (uses sudo)",
    )
    up_p = sub.add_parser("up", help="start the stack (first run and reruns)")
    up_p.add_argument(
        "--mode", choices=["dev", "prod", "production"], default=None,
        help="runtime mode (default: value of SEAGULL_ENV in .env, or dev)",
    )
    up_p.add_argument("--persist", action="store_true", help="enable persistent Redis storage (dev)")
    up_p.add_argument(
        "--dev-reload", action="store_true", dest="dev_reload",
        help="enable frontend hot reload via compose.dev-reload.yml overlay (dev)",
    )
    up_p.add_argument("--fresh", action="store_true", help="drop volumes before starting (prod)")
    sub.add_parser("status", help="show running container status")
    sub.add_parser("doctor", help="check dependencies, TLS, secrets, and compose config")
    reset_p = sub.add_parser("reset", help="stop the stack")
    reset_p.add_argument(
        "--volumes", action="store_true",
        help="also remove named volumes (all data will be lost)",
    )
    sub.add_parser("down", help="stop and remove containers")

    restart_p = sub.add_parser("restart", help="rebuild and restart the stack")
    restart_p.add_argument("--quick", action="store_true", help="recreate containers without rebuild")
    restart_p.add_argument(
        "--dev-reload", action="store_true", dest="dev_reload",
        help="include hot reload overlay",
    )
    restart_p.add_argument("--persist", action="store_true")

    logs_p = sub.add_parser("logs", help="follow service logs")
    logs_p.add_argument("svc", nargs="?", default=None, help="specific service name")
    sub.add_parser("ps", help="list service containers (alias for status)")
    dev_p = sub.add_parser("dev", help="[legacy] start stack in dev mode — prefer: up --mode dev")
    dev_p.add_argument("--persist", action="store_true")
    dev_p.add_argument("--dev-reload", action="store_true", dest="dev_reload")

    prod_p = sub.add_parser("prod", help="[legacy] start stack in prod mode — prefer: up --mode prod")
    prod_p.add_argument("--fresh", action="store_true")

    sub.add_parser("prod-setup", help="run env wizard then validate production config")
    sub.add_parser("build", help="build service images")
    sub.add_parser("pull", help="pull base images")
    sub.add_parser("clean", help="stop and remove containers, keep volumes")
    sub.add_parser("nuke", help="stop and remove containers and volumes (DANGEROUS)")
    sub.add_parser("psql", help="open psql shell inside the postgres container")

    env_p = sub.add_parser("env", help="environment file management")
    env_sub = env_p.add_subparsers(dest="env_cmd", metavar="env_cmd")
    env_sub.add_parser("bootstrap", help="sync .env from .env.example")
    env_sub.add_parser("wizard", help="interactive environment setup wizard")
    env_sub.add_parser("prepare", help="validate production environment secrets")

    geoip_p = sub.add_parser("geoip", help="manage local MaxMind GeoLite2 databases")
    geoip_sub = geoip_p.add_subparsers(dest="geoip_cmd", metavar="geoip_cmd")
    geoip_install = geoip_sub.add_parser("install", help="download missing GeoLite2 databases")
    geoip_install.add_argument("--force", action="store_true", help="download even when databases are valid")
    geoip_sub.add_parser("status", help="validate installed GeoLite2 databases")

    agent_p = sub.add_parser("agent", help="agent control-plane operations")
    agent_sub = agent_p.add_subparsers(dest="agent_cmd", metavar="agent_cmd")
    tok_p = agent_sub.add_parser("tokens", help="mint agent bootstrap tokens")
    tok_p.add_argument(
        "--agent-id",
        dest="agent_ids",
        action="append",
        required=True,
        help="registered agent identifier; repeat for multiple agents",
    )
    tok_p.add_argument("--output-dir", dest="output_dir", default=None)

    admin_p = sub.add_parser("admin", help="admin account operations")
    admin_sub = admin_p.add_subparsers(dest="admin_cmd", metavar="admin_cmd")
    admin_sub.add_parser("reset", help="reset or sync bootstrap admin password")

    state_p = sub.add_parser("state", help="production runtime state management")
    state_sub = state_p.add_subparsers(dest="state_cmd", metavar="state_cmd")
    state_sub.add_parser("check", help="check production state for drift")
    state_sub.add_parser("clear", help="clear production state marker")

    db_p = sub.add_parser("db", help="database migration operations")
    db_sub = db_p.add_subparsers(dest="db_cmd", metavar="db_cmd")
    db_sub.add_parser("upgrade", help="run alembic upgrade head")
    db_sub.add_parser("current", help="compare the database revision against this build's head")

    sub.add_parser("lint", help="lint backend and frontend")

    test_p = sub.add_parser("test", help="run automated test suite")
    test_p.add_argument("--detections", action="store_true")

    sub.add_parser("ci", help="lint + test + build")
    sub.add_parser("deps-check", help="run dependency vulnerability checks")

    redis_p = sub.add_parser("redis", help="Redis operations")
    redis_sub = redis_p.add_subparsers(dest="redis_cmd", metavar="redis_cmd")
    redis_sub.add_parser("repair-aof", help="back up and repair persistent Redis AOF state")

    sub.add_parser("observability", help="start Grafana/Kibana observability profile")

    return p


_DISPATCH = {
    "deps": cmd_deps,
    "up": cmd_up,
    "status": cmd_status,
    "doctor": cmd_doctor,
    "reset": cmd_reset,
    "dev": cmd_dev,
    "prod": cmd_prod,
    "prod-setup": cmd_prod_setup,
    "down": cmd_down,
    "restart": cmd_restart,
    "ps": cmd_ps,
    "logs": cmd_logs,
    "build": cmd_build,
    "pull": cmd_pull,
    "clean": cmd_clean,
    "nuke": cmd_nuke,
    "psql": cmd_psql,
    "env": cmd_env,
    "geoip": cmd_geoip,
    "agent": cmd_agent,
    "admin": cmd_admin,
    "state": cmd_state,
    "db": cmd_db,
    "lint": cmd_lint,
    "test": cmd_test,
    "ci": cmd_ci,
    "deps-check": cmd_deps_check,
    "redis": cmd_redis,
    "observability": cmd_observability,
}


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] in ("-d", "--deps"):
        argv = ["deps"] + argv[1:]

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.help or not args.command:
        _print_help()
        return 0

    handler = _DISPATCH.get(args.command)
    if not handler:
        print(f"[seagull] unknown command: {args.command}", file=sys.stderr)
        return 1

    try:
        return handler(args) or 0
    except KeyboardInterrupt:
        print("\n[seagull] interrupted", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print(f"[seagull] error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[seagull] unexpected error: {exc}", file=sys.stderr)
        return 1
