"""
TUI Dashboard for EnvShield.

Provides a rich terminal-based dashboard displaying security scores,
risk summaries, environment variable statistics, and audit history.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from envshield.utils import severity_to_color


class DashboardError(Exception):
    """Custom exception for dashboard errors."""
    pass


def _get_rich_console():
    """Lazy import and return a Rich Console instance.

    Returns:
        Rich Console object, or None if rich is not available.
    """
    try:
        from rich.console import Console
        return Console()
    except ImportError:
        return None


def _get_rich_table(*args, **kwargs):
    """Lazy import and return a Rich Table instance.

    Returns:
        Rich Table object, or None if rich is not available.
    """
    try:
        from rich.table import Table
        return Table(*args, **kwargs)
    except ImportError:
        return None


def _get_rich_panel(*args, **kwargs):
    """Lazy import and return a Rich Panel instance.

    Returns:
        Rich Panel object, or None if rich is not available.
    """
    try:
        from rich.panel import Panel
        return Panel(*args, **kwargs)
    except ImportError:
        return None


def _get_rich_columns(*args, **kwargs):
    """Lazy import and return a Rich Columns layout.

    Returns:
        Rich Columns object, or None if rich is not available.
    """
    try:
        from rich.columns import Columns
        return Columns(*args, **kwargs)
    except ImportError:
        return None


def _score_to_color(score: int) -> str:
    """Map a security score (0-100) to a color.

    Args:
        score: Security score.

    Returns:
        Color name for rich styling.
    """
    if score >= 80:
        return "green"
    elif score >= 60:
        return "yellow"
    elif score >= 40:
        return "orange3"
    else:
        return "red"


def _score_to_label(score: int) -> str:
    """Map a security score to a human-readable label.

    Args:
        score: Security score.

    Returns:
        Descriptive label string.
    """
    if score >= 90:
        return "Excellent"
    elif score >= 80:
        return "Good"
    elif score >= 60:
        return "Fair"
    elif score >= 40:
        return "Poor"
    else:
        return "Critical"


def _build_score_panel(score: int) -> Any:
    """Build a Rich panel displaying the security score.

    Args:
        score: Security score (0-100).

    Returns:
        Rich Panel object.
    """
    Panel = _get_rich_panel()
    if Panel is None:
        return None

    color = _score_to_color(score)
    label = _score_to_label(score)

    # Build a visual score bar
    filled = int(score / 5)
    empty = 20 - filled
    bar = "[" + "=" * filled + " " * empty + "]"

    content = (
        f"\n  [bold {color}]{score}[/bold {color}] / 100\n"
        f"  [{color}]{bar}[/]\n"
        f"  Status: [bold {color}]{label}[/bold {color}]\n"
    )

    return Panel(content, title="[bold]Security Score[/bold]", border_style=color)


def _build_stats_panel(stats: Dict[str, int], total: int) -> Any:
    """Build a Rich panel displaying risk statistics.

    Args:
        stats: Dictionary of severity counts.
        total: Total number of findings.

    Returns:
        Rich Panel object.
    """
    Panel = _get_rich_panel()
    if Panel is None:
        return None

    lines = [
        f"  Total Findings: [bold]{total}[/bold]",
        "",
    ]

    severity_colors = {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = stats.get(sev, 0)
        color = severity_colors.get(sev, "white")
        indicator = "!" * min(count, 5) if count > 0 else "-"
        lines.append(f"  [{color}]{sev:<10}[/] {indicator:<5} ({count})")

    return Panel("\n".join(lines), title="[bold]Risk Summary[/bold]", border_style="cyan")


def _build_findings_table(findings: List[Dict[str, str]]) -> Any:
    """Build a Rich table displaying individual findings.

    Args:
        findings: List of finding dictionaries.

    Returns:
        Rich Table object.
    """
    Table = _get_rich_table()
    if Table is None:
        return None

    table = Table(title="Detailed Findings", show_lines=True, expand=True)
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Rule ID", width=22)
    table.add_column("Key", width=20)
    table.add_column("Description", min_width=40)
    table.add_column("Recommendation", min_width=40)

    for finding in findings:
        severity = finding.get("severity", "LOW")
        color = severity_to_color(severity)
        table.add_row(
            f"[{color}]{severity}[/{color}]",
            finding.get("rule_id", ""),
            finding.get("key", ""),
            finding.get("description", ""),
            finding.get("recommendation", ""),
        )

    return table


def _build_env_stats_panel(env_vars: Dict[str, str]) -> Any:
    """Build a Rich panel displaying environment variable statistics.

    Args:
        env_vars: Dictionary of environment variables.

    Returns:
        Rich Panel object.
    """
    Panel = _get_rich_panel()
    if Panel is None:
        return None

    total = len(env_vars)
    empty = sum(1 for v in env_vars.values() if not v)
    has_defaults = sum(
        1 for k, v in env_vars.items()
        if v.lower() in ("changeme", "secret", "password", "test", "admin", "default", "")
    )

    # Categorize keys
    categories = {
        "Database": 0,
        "API": 0,
        "Auth": 0,
        "Other": 0,
    }
    for key in env_vars.keys():
        key_upper = key.upper()
        if any(w in key_upper for w in ["DB", "DATABASE", "REDIS", "MONGO", "POSTGRES", "MYSQL"]):
            categories["Database"] += 1
        elif any(w in key_upper for w in ["API", "ENDPOINT", "URL", "HOST"]):
            categories["API"] += 1
        elif any(w in key_upper for w in ["AUTH", "TOKEN", "SECRET", "KEY", "PASSWORD", "CERT"]):
            categories["Auth"] += 1
        else:
            categories["Other"] += 1

    lines = [
        f"  Total Variables: [bold]{total}[/bold]",
        f"  Empty Values: [yellow]{empty}[/yellow]",
        f"  Default/Placeholder Values: [red]{has_defaults}[/red]",
        "",
        "  Categories:",
    ]
    for cat, count in categories.items():
        if count > 0:
            lines.append(f"    {cat}: {count}")

    return Panel("\n".join(lines), title="[bold]Environment Variables[/bold]", border_style="green")


def _build_history_panel(history: List[Dict[str, Any]]) -> Any:
    """Build a Rich panel displaying audit history trends.

    Args:
        history: List of audit history entries.

    Returns:
        Rich Panel object.
    """
    Panel = _get_rich_panel()
    if Panel is None:
        return None

    if not history:
        return Panel(
            "  No audit history available yet.\n  Run 'envshield audit' to generate history.",
            title="[bold]Audit History[/bold]",
            border_style="dim",
        )

    lines = []
    for entry in history[-10:]:  # Show last 10 entries
        timestamp = entry.get("timestamp", "unknown")
        score = entry.get("score", 0)
        findings = entry.get("total_findings", 0)
        color = _score_to_color(score)

        # Build mini bar
        filled = int(score / 10)
        bar = "[" + "=" * filled + " " * (10 - filled) + "]"

        lines.append(
            f"  [{color}]{bar}[/] {score:>3}/100  "
            f"{findings:>3} findings  {timestamp}"
        )

    return Panel("\n".join(lines), title="[bold]Audit History[/bold]", border_style="blue")


def render_dashboard(
    score: int,
    stats: Dict[str, int],
    findings: List[Dict[str, str]],
    env_vars: Optional[Dict[str, str]] = None,
    history: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Render the full TUI dashboard.

    Args:
        score: Security score (0-100).
        stats: Dictionary of severity counts.
        findings: List of finding dictionaries.
        env_vars: Optional dictionary of environment variables for stats.
        history: Optional list of audit history entries.
    """
    console = _get_rich_console()
    if console is None:
        # Fallback to plain text output
        _render_plain_dashboard(score, stats, findings, env_vars)
        return

    console.clear()
    console.print()

    # Title
    from rich.text import Text
    title = Text()
    title.append("EnvShield", style="bold cyan")
    title.append(" Security Dashboard", style="bold white")
    console.print(Panel(title, border_style="cyan"))
    console.print()

    # Score and Stats panels side by side
    score_panel = _build_score_panel(score)
    stats_panel = _build_stats_panel(stats, len(findings))

    if score_panel and stats_panel:
        try:
            from rich.columns import Columns
            console.print(Columns([score_panel, stats_panel], padding=(0, 2)))
        except Exception:
            console.print(score_panel)
            console.print(stats_panel)
    console.print()

    # Environment stats
    if env_vars:
        env_panel = _build_env_stats_panel(env_vars)
        if env_panel:
            console.print(env_panel)
        console.print()

    # Findings table
    if findings:
        findings_table = _build_findings_table(findings)
        if findings_table:
            console.print(findings_table)
        console.print()

    # History
    if history:
        history_panel = _build_history_panel(history)
        if history_panel:
            console.print(history_panel)
        console.print()


def _render_plain_dashboard(
    score: int,
    stats: Dict[str, int],
    findings: List[Dict[str, str]],
    env_vars: Optional[Dict[str, str]] = None,
) -> None:
    """Render a plain-text fallback dashboard when rich is not available.

    Args:
        score: Security score (0-100).
        stats: Dictionary of severity counts.
        findings: List of finding dictionaries.
        env_vars: Optional dictionary of environment variables.
    """
    print()
    print("=" * 70)
    print("  EnvShield Security Dashboard")
    print("=" * 70)
    print()

    # Score
    label = _score_to_label(score)
    filled = int(score / 5)
    bar = "[" + "=" * filled + " " * (20 - filled) + "]"
    print(f"  Security Score: {score}/100 ({label})")
    print(f"  {bar}")
    print()

    # Stats
    print("  Risk Summary:")
    print(f"    Total Findings: {len(findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = stats.get(sev, 0)
        print(f"    {sev:<10} {count}")
    print()

    # Environment stats
    if env_vars:
        total = len(env_vars)
        empty = sum(1 for v in env_vars.values() if not v)
        print(f"  Environment Variables: {total} total, {empty} empty")
        print()

    # Findings
    if findings:
        print("  Findings:")
        print(f"  {'Severity':<12} {'Rule ID':<22} {'Key':<20} Description")
        print(f"  {'-'*12} {'-'*22} {'-'*20} {'-'*30}")
        for f in findings:
            print(
                f"  {f.get('severity', 'LOW'):<12} "
                f"{f.get('rule_id', ''):<22} "
                f"{f.get('key', ''):<20} "
                f"{f.get('description', '')[:50]}"
            )
        print()

    print("=" * 70)
