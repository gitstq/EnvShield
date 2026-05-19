"""
Utility functions for EnvShield.

Provides common helper functions used across multiple modules including
path resolution, file operations, and formatting utilities.
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def resolve_path(path: str, base_dir: Optional[str] = None) -> Path:
    """Resolve a file path to an absolute path.

    Args:
        path: The path to resolve.
        base_dir: Optional base directory. Defaults to current working directory.

    Returns:
        Resolved absolute Path object.
    """
    if base_dir:
        return Path(base_dir).resolve() / path
    return Path(path).resolve()


def ensure_directory(path: Path) -> Path:
    """Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path to ensure.

    Returns:
        The path object for the directory.
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_file_safe(path: Path, encoding: str = "utf-8") -> Optional[str]:
    """Safely read a file, returning None on failure.

    Args:
        path: Path to the file.
        encoding: File encoding. Defaults to utf-8.

    Returns:
        File contents as string, or None if reading failed.
    """
    try:
        return path.read_text(encoding=encoding)
    except (IOError, OSError, UnicodeDecodeError):
        return None


def write_file_safe(path: Path, content: str, encoding: str = "utf-8") -> bool:
    """Safely write content to a file.

    Args:
        path: Path to the file.
        content: Content to write.
        encoding: File encoding. Defaults to utf-8.

    Returns:
        True if writing succeeded, False otherwise.
    """
    try:
        ensure_directory(path.parent)
        path.write_text(content, encoding=encoding)
        return True
    except (IOError, OSError):
        return False


def write_file_binary(path: Path, content: bytes) -> bool:
    """Safely write binary content to a file.

    Args:
        path: Path to the file.
        content: Binary content to write.

    Returns:
        True if writing succeeded, False otherwise.
    """
    try:
        ensure_directory(path.parent)
        path.write_bytes(content)
        return True
    except (IOError, OSError):
        return False


def read_file_binary(path: Path) -> Optional[bytes]:
    """Safely read binary content from a file.

    Args:
        path: Path to the file.

    Returns:
        Binary content, or None if reading failed.
    """
    try:
        return path.read_bytes()
    except (IOError, OSError):
        return None


def find_env_file(start_dir: Optional[str] = None) -> Optional[Path]:
    """Search for .env file starting from a directory, walking up the tree.

    Args:
        start_dir: Directory to start searching from. Defaults to cwd.

    Returns:
        Path to the found .env file, or None.
    """
    current = Path(start_dir or os.getcwd()).resolve()
    while True:
        env_path = current / ".env"
        if env_path.exists():
            return env_path
        parent = current.parent
        if parent == current:
            return None
        current = parent


def mask_sensitive_value(value: str, visible_chars: int = 4) -> str:
    """Mask a sensitive value, showing only the first few characters.

    Args:
        value: The value to mask.
        visible_chars: Number of characters to show at the start.

    Returns:
        Masked string like 'abcd****'.
    """
    if not value or len(value) <= visible_chars:
        return "****"
    return value[:visible_chars] + "*" * min(len(value) - visible_chars, 8)


def severity_to_color(severity: str) -> str:
    """Map a severity level to a color name for terminal output.

    Args:
        severity: One of CRITICAL, HIGH, MEDIUM, LOW, INFO.

    Returns:
        Color name string compatible with rich library.
    """
    mapping = {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "green",
    }
    return mapping.get(severity.upper(), "white")


def severity_to_score_weight(severity: str) -> int:
    """Return a numeric weight for a severity level for score calculation.

    Args:
        severity: One of CRITICAL, HIGH, MEDIUM, LOW.

    Returns:
        Integer weight (higher = more severe).
    """
    mapping = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
    }
    return mapping.get(severity.upper(), 0)


def calculate_security_score(findings: List[Dict]) -> int:
    """Calculate a security score (0-100) based on audit findings.

    The score starts at 100 and is reduced based on the severity and
    count of findings.

    Args:
        findings: List of audit finding dictionaries with 'severity' key.

    Returns:
        Security score from 0 to 100.
    """
    score = 100
    for finding in findings:
        weight = severity_to_score_weight(finding.get("severity", "LOW"))
        score -= weight
    return max(0, min(100, score))


def parse_env_line(line: str) -> Optional[Tuple[str, str]]:
    """Parse a single .env file line into a key-value pair.

    Handles quoted values, inline comments, and various formats.

    Args:
        line: A single line from a .env file.

    Returns:
        Tuple of (key, value) or None if the line is empty or a comment.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Remove inline comments (but not inside quotes)
    if "=" not in line:
        return None

    key, _, value = line.partition("=")
    key = key.strip()
    value = value.strip()

    # Remove surrounding quotes
    if len(value) >= 2:
        if (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'"):
            value = value[1:-1]

    # Remove inline comments after value
    if " #" in value:
        value = value[: value.index(" #")].strip()
    if ' #' in value:
        value = value[: value.index(" #")].strip()

    return (key, value)


def is_valid_key_name(key: str) -> bool:
    """Validate an environment variable key name.

    Args:
        key: The key name to validate.

    Returns:
        True if the key name is valid.
    """
    if not key:
        return False
    pattern = r"^[A-Za-z_][A-Za-z0-9_]*$"
    return bool(re.match(pattern, key))


def format_table(headers: List[str], rows: List[List[str]]) -> str:
    """Format data as a simple text table.

    Args:
        headers: Column header strings.
        rows: List of row data, each row is a list of strings.

    Returns:
        Formatted table string.
    """
    if not rows:
        return "  (no data)"

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    separator = "  ".join("-" * w for w in col_widths)
    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, col_widths))

    lines = [header_line, separator]
    for row in rows:
        line = "  ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths))
        lines.append(line)

    return "\n".join(lines)


def get_python_version() -> Tuple[int, int, int]:
    """Get the current Python version as a tuple.

    Returns:
        Tuple of (major, minor, micro) version numbers.
    """
    return sys.version_info[:3]
