"""
CLI entry point for EnvShield.

Provides the command-line interface using the Click framework with
commands for encryption, decryption, auditing, scanning, environment
variable management, Git hooks, and dashboard display.
"""

import json
import os
import sys
from pathlib import Path

import click

from envshield import __version__
from envshield.auditor import SecurityAuditor
from envshield.config import Config
from envshield.crypto import (
    CryptoError,
    PasswordStrengthError,
    decrypt_env_file,
    decrypt_to_memory,
    encrypt_env_file,
    inject_env_vars,
    validate_password_strength,
)
from envshield.dashboard import render_dashboard
from envshield.git_hook import GitHookManager
from envshield.manager import EnvManager, EnvManagerError
from envshield.scanner import SourceScanner
from envshield.utils import ensure_directory, format_table, mask_sensitive_value


def _load_config(ctx: click.Context) -> Config:
    """Load configuration from the current directory.

    Args:
        ctx: Click context.

    Returns:
        Loaded Config object.
    """
    config = Config(project_dir=ctx.obj.get("project_dir") if ctx.obj else None)
    config.load()
    return config


def _print_error(message: str) -> None:
    """Print an error message to stderr.

    Args:
        message: Error message to display.
    """
    click.echo(click.style(f"Error: {message}", fg="red"), err=True)


def _print_success(message: str) -> None:
    """Print a success message.

    Args:
        message: Success message to display.
    """
    click.echo(click.style(message, fg="green"))


def _print_warning(message: str) -> None:
    """Print a warning message.

    Args:
        message: Warning message to display.
    """
    click.echo(click.style(f"Warning: {message}", fg="yellow"))


@click.group()
@click.version_option(version=__version__, prog_name="envshield")
@click.option(
    "--project-dir", "-p",
    type=click.Path(exists=True),
    default=None,
    help="Project root directory.",
)
@click.pass_context
def cli(ctx: click.Context, project_dir: str) -> None:
    """EnvShield - Lightweight Environment Variable Security Management CLI.

    Encrypt, audit, and manage your environment variables securely.
    """
    ctx.ensure_object(dict)
    ctx.obj["project_dir"] = project_dir


@cli.command()
@click.option("--name", "-n", default="", help="Project name for configuration.")
@click.pass_context
def init(ctx: click.Context, name: str) -> None:
    """Initialize EnvShield configuration in the current project."""
    config = Config(project_dir=ctx.obj.get("project_dir"))
    if config.exists():
        if not click.confirm("Configuration already exists. Overwrite?"):
            click.echo("Initialization cancelled.")
            return

    if not name:
        name = Path(ctx.obj.get("project_dir") or os.getcwd()).name

    if config.init(project_name=name):
        _print_success(f"EnvShield initialized in {config.config_path}")
        _print_success(f"Project: {name}")
        click.echo(f"Configuration file: {config.config_path}")

        # Create .envshield directory structure
        env_dir = config.config_path.parent / ".envshield" / "envs"
        ensure_directory(env_dir)
        click.echo(f"Environment directory: {env_dir}")

        # Create initial .env.example
        example_path = config._project_dir / ".env.example"
        if not example_path.exists():
            example_content = (
                "# EnvShield - Environment Variables Template\n"
                "# Copy this file to .env and fill in your values\n"
                "# Use 'envshield encrypt' to create .env.vault\n"
                "\n"
                "# Database\n"
                "DATABASE_URL=\n"
                "DB_USER=\n"
                "DB_PASSWORD=\n"
                "\n"
                "# API\n"
                "API_KEY=\n"
                "API_SECRET=\n"
                "\n"
                "# App\n"
                "APP_ENV=dev\n"
                "DEBUG=false\n"
                "SECRET_KEY=\n"
            )
            example_path.write_text(example_content, encoding="utf-8")
            click.echo(f"Example file created: {example_path}")
    else:
        _print_error("Failed to initialize configuration.")


@cli.command()
@click.argument("file", type=click.Path(exists=True), required=False, default=".env")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output vault file path.")
@click.option("--password", type=str, default=None, help="Encryption password (not recommended on CLI).")
@click.pass_context
def encrypt(ctx: click.Context, file: str, output: str, password: str) -> None:
    """Encrypt a .env file into .env.vault format."""
    try:
        result_path = encrypt_env_file(
            input_path=file,
            output_path=output,
            password=password,
        )
        _print_success(f"Encrypted file created: {result_path}")
    except FileNotFoundError as e:
        _print_error(str(e))
        sys.exit(1)
    except PasswordStrengthError as e:
        _print_error(str(e))
        sys.exit(1)
    except CryptoError as e:
        _print_error(str(e))
        sys.exit(1)


@cli.command()
@click.argument("file", type=click.Path(exists=True), required=False, default=".env.vault")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output .env file path.")
@click.option("--password", type=str, default=None, help="Decryption password (not recommended on CLI).")
@click.pass_context
def decrypt(ctx: click.Context, file: str, output: str, password: str) -> None:
    """Decrypt a .env.vault file back to .env format."""
    try:
        result_path = decrypt_env_file(
            input_path=file,
            output_path=output,
            password=password,
        )
        _print_success(f"Decrypted file created: {result_path}")
    except FileNotFoundError as e:
        _print_error(str(e))
        sys.exit(1)
    except CryptoError as e:
        _print_error(str(e))
        sys.exit(1)


@cli.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option("--json", "output_json", is_flag=True, help="Output results in JSON format.")
@click.pass_context
def audit(ctx: click.Context, files, output_json: bool) -> None:
    """Run security audit on environment files."""
    config = _load_config(ctx)
    auditor = SecurityAuditor(whitelist=config.get_audit_whitelist())

    all_findings = []
    manager = EnvManager(project_dir=ctx.obj.get("project_dir"))

    targets = list(files) if files else [".env"]
    for target in targets:
        target_path = Path(target)
        if not target_path.exists():
            _print_warning(f"File not found, skipping: {target}")
            continue

        try:
            env_vars = manager.load(file_path=str(target_path))
            result = auditor.audit(env_vars)
            all_findings.extend(result.to_dict()["findings"])
        except (FileNotFoundError, EnvManagerError) as e:
            _print_warning(f"Could not load {target}: {e}")

    # Compute overall score
    from envshield.utils import calculate_security_score
    score = calculate_security_score(
        [{"severity": f["severity"]} for f in all_findings]
    )

    # Count by severity
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f["severity"].upper()
        if sev in stats:
            stats[sev] += 1

    if output_json:
        output_data = {
            "score": score,
            "total_findings": len(all_findings),
            "stats": stats,
            "findings": all_findings,
        }
        click.echo(json.dumps(output_data, indent=2, ensure_ascii=False))
    else:
        # Display results
        click.echo()
        click.echo(click.style("=" * 60, fg="cyan"))
        click.echo(click.style("  EnvShield Security Audit Report", fg="cyan", bold=True))
        click.echo(click.style("=" * 60, fg="cyan"))
        click.echo()

        # Score
        if score >= 80:
            score_color = "green"
        elif score >= 60:
            score_color = "yellow"
        else:
            score_color = "red"
        click.echo(f"  Security Score: {click.style(str(score), fg=score_color, bold=True)} / 100")
        click.echo()

        # Stats
        click.echo("  Risk Summary:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = stats[sev]
            color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}[sev]
            click.echo(f"    {click.style(sev, fg=color):<12} {count}")
        click.echo()

        # Findings
        if all_findings:
            click.echo("  Findings:")
            headers = ["Severity", "Rule", "Key", "Description"]
            rows = []
            for f in all_findings:
                rows.append([
                    f["severity"],
                    f["rule_id"],
                    f["key"],
                    f["description"][:60],
                ])
            click.echo(format_table(headers, rows))
            click.echo()

            # Recommendations
            click.echo("  Recommendations:")
            seen = set()
            for f in all_findings:
                rec = f.get("recommendation", "")
                if rec and rec not in seen:
                    seen.add(rec)
                    click.echo(f"    - {rec}")
        else:
            _print_success("  No security issues found!")

        click.echo()
        click.echo(click.style("=" * 60, fg="cyan"))

    # Exit with non-zero if critical issues found
    if stats["CRITICAL"] > 0:
        sys.exit(2)
    elif stats["HIGH"] > 0:
        sys.exit(1)


@cli.command()
@click.argument("directory", type=click.Path(exists=True), default=".")
@click.option("--json", "output_json", is_flag=True, help="Output results in JSON format.")
@click.pass_context
def scan(ctx: click.Context, directory: str, output_json: bool) -> None:
    """Scan source code for hardcoded secrets."""
    config = _load_config(ctx)
    scanner = SourceScanner(
        exclude_dirs=config.get_exclude_dirs(),
        extensions=config.get_scan_extensions(),
    )

    try:
        findings = scanner.scan(directory)
    except (FileNotFoundError, NotADirectoryError) as e:
        _print_error(str(e))
        sys.exit(1)

    stats = scanner.get_scan_stats(findings)

    if output_json:
        output_data = {
            "target": str(Path(directory).resolve()),
            "stats": stats,
            "findings": [f.to_dict() for f in findings],
        }
        click.echo(json.dumps(output_data, indent=2, ensure_ascii=False))
    else:
        click.echo()
        click.echo(click.style("=" * 60, fg="cyan"))
        click.echo(click.style("  EnvShield Source Code Scan", fg="cyan", bold=True))
        click.echo(click.style("=" * 60, fg="cyan"))
        click.echo()
        click.echo(f"  Scanned: {directory}")
        click.echo(f"  Total findings: {stats['total']}")
        click.echo()

        if stats["total"] > 0:
            click.echo("  Summary:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = stats[sev]
                if count > 0:
                    color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}[sev]
                    click.echo(f"    {click.style(sev, fg=color):<12} {count}")
            click.echo()

            headers = ["Severity", "File", "Line", "Pattern", "Match"]
            rows = []
            for f in findings:
                rows.append([
                    f.severity,
                    f.file_path,
                    str(f.line_number),
                    f.pattern_name,
                    f.matched_content[:50],
                ])
            click.echo(format_table(headers, rows))
        else:
            _print_success("  No hardcoded secrets detected!")

        click.echo()

    if stats["CRITICAL"] > 0:
        sys.exit(2)
    elif stats["HIGH"] > 0:
        sys.exit(1)


@cli.command(context_settings={"ignore_unknown_options": True})
@click.option("--vault", type=click.Path(exists=True), default=".env.vault", help="Vault file to decrypt.")
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
@click.pass_context
def run(ctx: click.Context, vault: str, command) -> None:
    """Run a command with decrypted environment variables injected (no disk write)."""
    try:
        env_vars = decrypt_to_memory(vault_path=vault)
    except FileNotFoundError as e:
        _print_error(str(e))
        sys.exit(1)
    except CryptoError as e:
        _print_error(str(e))
        sys.exit(1)

    if not env_vars:
        _print_warning("No environment variables found in vault.")
        sys.exit(1)

    click.echo(f"Injected {len(env_vars)} environment variables from {vault}")

    # Inject into current process
    inject_env_vars(env_vars)

    # Execute the command
    import subprocess
    cmd_list = list(command)
    try:
        result = subprocess.run(cmd_list)
        sys.exit(result.returncode)
    except FileNotFoundError:
        _print_error(f"Command not found: {cmd_list[0]}")
        sys.exit(127)


@cli.command(name="set")
@click.argument("key")
@click.argument("value")
@click.option("--env", "-e", default=None, help="Target environment name.")
@click.pass_context
def set_var(ctx: click.Context, key: str, value: str, env: str) -> None:
    """Set an environment variable."""
    config = _load_config(ctx)
    env_name = env or config.get_current_env()
    project_dir = ctx.obj.get("project_dir") if ctx.obj else None
    manager = EnvManager(
        project_dir=project_dir,
        env_name=env_name,
    )

    # Try to load existing file
    env_file = manager._get_env_file_path(env_name)
    if env_file.exists():
        try:
            manager.load(env_name=env_name)
        except (FileNotFoundError, EnvManagerError):
            pass

    try:
        manager.set(key, value)
        saved_path = manager.save(env_name=env_name)
        _print_success(f"Set {key} in {env_name} environment")
        click.echo(f"File: {saved_path}")
    except EnvManagerError as e:
        _print_error(str(e))
        sys.exit(1)


@cli.command()
@click.argument("key")
@click.option("--env", "-e", default=None, help="Target environment name.")
@click.option("--reveal", is_flag=True, help="Show the actual value (not masked).")
@click.pass_context
def get(ctx: click.Context, key: str, env: str, reveal: bool) -> None:
    """Get an environment variable value."""
    config = _load_config(ctx)
    env_name = env or config.get_current_env()
    manager = EnvManager(
        project_dir=ctx.obj.get("project_dir"),
        env_name=env_name,
    )

    try:
        manager.load(env_name=env_name)
    except FileNotFoundError:
        _print_error(f"Environment '{env_name}' not found.")
        sys.exit(1)

    value = manager.get(key, resolve_refs=True)
    if value is None:
        _print_error(f"Variable '{key}' not found in '{env_name}' environment.")
        sys.exit(1)

    if reveal:
        click.echo(value)
    else:
        click.echo(f"{key}={mask_sensitive_value(value)}")


@cli.command()
@click.argument("key")
@click.option("--env", "-e", default=None, help="Target environment name.")
@click.pass_context
def delete(ctx: click.Context, key: str, env: str) -> None:
    """Delete an environment variable."""
    config = _load_config(ctx)
    env_name = env or config.get_current_env()
    manager = EnvManager(
        project_dir=ctx.obj.get("project_dir"),
        env_name=env_name,
    )

    try:
        manager.load(env_name=env_name)
    except FileNotFoundError:
        _print_error(f"Environment '{env_name}' not found.")
        sys.exit(1)

    if manager.delete(key):
        manager.save(env_name=env_name)
        _print_success(f"Deleted '{key}' from '{env_name}' environment.")
    else:
        _print_error(f"Variable '{key}' not found in '{env_name}' environment.")
        sys.exit(1)


@cli.command("list")
@click.option("--env", "-e", default=None, help="Target environment name.")
@click.option("--reveal", is_flag=True, help="Show actual values (not masked).")
@click.pass_context
def list_vars(ctx: click.Context, env: str, reveal: bool) -> None:
    """List all environment variables."""
    config = _load_config(ctx)
    env_name = env or config.get_current_env()
    manager = EnvManager(
        project_dir=ctx.obj.get("project_dir"),
        env_name=env_name,
    )

    try:
        manager.load(env_name=env_name)
    except FileNotFoundError:
        _print_error(f"Environment '{env_name}' not found.")
        sys.exit(1)

    variables = manager.list_vars(mask_values=not reveal)
    if not variables:
        click.echo(f"No variables in '{env_name}' environment.")
        return

    click.echo(f"Environment: {env_name}")
    click.echo(f"Variables: {len(variables)}")
    click.echo()

    headers = ["Key", "Value"]
    rows = [[k, v] for k, v in sorted(variables.items())]
    click.echo(format_table(headers, rows))


@cli.command()
@click.argument("env_name")
@click.pass_context
def switch(ctx: click.Context, env_name: str) -> None:
    """Switch to a different environment."""
    config = _load_config(ctx)
    manager = EnvManager(
        project_dir=ctx.obj.get("project_dir"),
        env_name=config.get_current_env(),
    )

    try:
        variables = manager.switch_env(env_name)
        config.set_current_env(env_name)
        config.save()
        _print_success(f"Switched to '{env_name}' environment ({len(variables)} variables)")
    except FileNotFoundError:
        _print_error(f"Environment '{env_name}' not found.")
        _print_error(f"Available environments: {', '.join(manager.environments) or 'none'}")
        sys.exit(1)


@cli.group()
def hook() -> None:
    """Manage Git pre-commit hooks."""


@hook.command()
@click.option("--force", is_flag=True, help="Overwrite existing hook.")
@click.pass_context
def install(ctx: click.Context, force: bool) -> None:
    """Install the EnvShield Git pre-commit hook."""
    manager = GitHookManager(project_dir=ctx.obj.get("project_dir"))
    try:
        message = manager.install(force=force)
        _print_success(message)
    except GitHookError as e:
        _print_error(str(e))
        sys.exit(1)


@hook.command()
@click.pass_context
def uninstall(ctx: click.Context) -> None:
    """Uninstall the EnvShield Git pre-commit hook."""
    manager = GitHookManager(project_dir=ctx.obj.get("project_dir"))
    try:
        message = manager.uninstall()
        _print_success(message)
    except GitHookError as e:
        _print_error(str(e))
        sys.exit(1)


@cli.command()
@click.pass_context
def dashboard(ctx: click.Context) -> None:
    """Open the TUI security dashboard."""
    config = _load_config(ctx)
    manager = EnvManager(project_dir=ctx.obj.get("project_dir"))
    auditor = SecurityAuditor(whitelist=config.get_audit_whitelist())

    # Load environment variables
    env_vars = {}
    try:
        env_vars = manager.load_main_env()
    except (FileNotFoundError, EnvManagerError):
        try:
            env_vars = manager.load()
        except (FileNotFoundError, EnvManagerError):
            click.echo("No environment files found. Showing empty dashboard.")

    # Run audit
    result = auditor.audit(env_vars)
    audit_data = result.to_dict()

    # Load history (if available)
    history = []
    history_file = config.config_path.parent / ".envshield" / "audit_history.json"
    if history_file.exists():
        try:
            content = history_file.read_text(encoding="utf-8")
            history = json.loads(content)
        except (json.JSONDecodeError, IOError):
            pass

    # Save current audit to history
    from datetime import datetime
    history.append({
        "timestamp": datetime.now().isoformat(),
        "score": audit_data["score"],
        "total_findings": audit_data["total_findings"],
    })
    history_limit = config.get("dashboard", "history_limit", 20)
    history = history[-history_limit:]

    try:
        ensure_directory(history_file.parent)
        history_file.write_text(
            json.dumps(history, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except IOError:
        pass

    # Render dashboard
    render_dashboard(
        score=audit_data["score"],
        stats=audit_data["stats"],
        findings=audit_data["findings"],
        env_vars=env_vars,
        history=history,
    )


@cli.command()
@click.option("--format", "fmt", type=click.Choice(["json", "yaml"]), default="json", help="Export format.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path.")
@click.option("--env", "-e", default=None, help="Environment to export.")
@click.pass_context
def export(ctx: click.Context, fmt: str, output: str, env: str) -> None:
    """Export environment variables to JSON or YAML format."""
    config = _load_config(ctx)
    env_name = env or config.get_current_env()
    manager = EnvManager(
        project_dir=ctx.obj.get("project_dir"),
        env_name=env_name,
    )

    try:
        manager.load(env_name=env_name)
    except FileNotFoundError:
        _print_error(f"Environment '{env_name}' not found.")
        sys.exit(1)

    if output is None:
        output = f"env_export_{env_name}.{fmt}"

    try:
        if fmt == "json":
            result_path = manager.export_json(output)
        else:
            result_path = manager.export_yaml(output)
        _print_success(f"Exported to: {result_path}")
    except EnvManagerError as e:
        _print_error(str(e))
        sys.exit(1)


def main() -> None:
    """Entry point for the envshield CLI command."""
    cli(obj={})


if __name__ == "__main__":
    main()
