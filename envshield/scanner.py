"""
Source code scanner for EnvShield.

Recursively scans project directories to detect hardcoded secrets, API keys,
passwords, and other sensitive information in source code files.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from envshield.utils import read_file_safe


class ScanFinding:
    """Represents a single scan finding in source code.

    Attributes:
        file_path: Path to the file where the finding was detected.
        line_number: Line number in the file (1-based).
        matched_content: The actual matched text content.
        pattern_name: Name/description of the pattern that matched.
        severity: Risk severity level (HIGH, MEDIUM, LOW).
    """

    def __init__(
        self,
        file_path: str,
        line_number: int,
        matched_content: str,
        pattern_name: str,
        severity: str,
    ):
        self.file_path = file_path
        self.line_number = line_number
        self.matched_content = matched_content.strip()
        self.pattern_name = pattern_name
        self.severity = severity

    def to_dict(self) -> Dict[str, str]:
        """Convert finding to dictionary.

        Returns:
            Dictionary representation of the finding.
        """
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "matched_content": self.matched_content,
            "pattern_name": self.pattern_name,
            "severity": self.severity,
        }

    def __repr__(self) -> str:
        return (
            f"ScanFinding(file={self.file_path!r}, line={self.line_number}, "
            f"pattern={self.pattern_name!r}, severity={self.severity!r})"
        )


# Default directories to exclude from scanning
DEFAULT_EXCLUDE_DIRS: Set[str] = {
    "node_modules", ".git", "venv", "__pycache__", ".venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    ".eggs", "*.egg-info", ".envshield",
}

# Default file extensions to scan
DEFAULT_SCAN_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java",
    ".yml", ".yaml", ".json", ".toml", ".env", ".ini", ".cfg",
}

# Patterns for detecting hardcoded secrets
SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    # (pattern, name, severity)
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?', "Password assignment", "HIGH"),
    (r'(?:secret[_-]?key|secret)\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?', "Secret key assignment", "HIGH"),
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?', "API key assignment", "HIGH"),
    (r'(?:token|auth[_-]?token|access[_-]?token)\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?', "Token assignment", "HIGH"),
    (r'(?:private[_-]?key)\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?', "Private key assignment", "CRITICAL"),
    (r'(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?', "AWS secret key", "CRITICAL"),
    (r'(?:db[_-]?password|database[_-]?password)\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?', "Database password", "CRITICAL"),
    (r'(?:encryption[_-]?key|cipher[_-]?key)\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?', "Encryption key", "CRITICAL"),
    (r'(?:jdbc|postgres|mysql|mongodb|redis)://[^\s"\']+', "Database connection string", "HIGH"),
    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Private key PEM block", "CRITICAL"),
    (r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----', "EC private key PEM block", "CRITICAL"),
    (r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----', "OpenSSH private key block", "CRITICAL"),
    (r'(?:AKIA[0-9A-Z]{16})', "AWS Access Key ID", "CRITICAL"),
    (r'(?:AIza[0-9A-Za-z\-_]{35})', "Google API Key", "CRITICAL"),
    (r'(?:sk_live_[0-9a-zA-Z]{24,})', "Stripe Live Secret Key", "CRITICAL"),
    (r'(?:ghp_[A-Za-z0-9_]{36,})', "GitHub Personal Access Token", "CRITICAL"),
    (r'(?:xox[baprs]-[0-9]{10,}-[0-9A-Za-z]{24,})', "Slack Token", "HIGH"),
    (r'(?:SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})', "SendGrid API Key", "HIGH"),
    (r'(?:Bearer\s+[A-Za-z0-9\-._~+/]+=*)', "Bearer token", "HIGH"),
    (r'(?:Authorization\s*:\s*Basic\s+[A-Za-z0-9+/=]+)', "Basic auth header", "HIGH"),
]

# Patterns that indicate a value is a placeholder (not a real secret)
PLACEHOLDER_PATTERNS: List[str] = [
    r"^your[_-]?(?:secret|key|password|token)[_-]?here$",
    r"^change[_-]?me$",
    r"^placeholder$",
    r"^xxx+$",
    r"^\$\{.+\}$",
    r"^<.*>$",
    r"^\.\.\.$",
    r"^todo$",
    r"^none$",
    r"^nil$",
    r"^null$",
    r"^example$",
    r"^test[_-]?(?:value|key|secret|password)?$",
    r"^dummy$",
    r"^sample$",
]


def is_placeholder(value: str) -> bool:
    """Check if a value appears to be a placeholder rather than a real secret.

    Args:
        value: The value to check.

    Returns:
        True if the value looks like a placeholder.
    """
    if not value or len(value) < 4:
        return True
    value_lower = value.lower()
    for pattern in PLACEHOLDER_PATTERNS:
        if re.match(pattern, value_lower):
            return True
    return False


class SourceScanner:
    """Scans source code directories for hardcoded secrets and sensitive data.

    Recursively walks through a project directory, examining files with
    configured extensions and applying pattern matching to detect potential
    security issues.
    """

    def __init__(
        self,
        exclude_dirs: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
    ):
        """Initialize the scanner.

        Args:
            exclude_dirs: Directory names to exclude from scanning.
            extensions: File extensions to include in scanning.
        """
        self.exclude_dirs = set(exclude_dirs or DEFAULT_EXCLUDE_DIRS)
        self.extensions = set(extensions or DEFAULT_SCAN_EXTENSIONS)
        self._compiled_patterns: List[Tuple[re.Pattern, str, str]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns for efficiency."""
        self._compiled_patterns = []
        for pattern_str, name, severity in SECRET_PATTERNS:
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE)
                self._compiled_patterns.append((compiled, name, severity))
            except re.error:
                # Skip invalid patterns
                pass

    def scan(self, target_dir: str) -> List[ScanFinding]:
        """Scan a directory for hardcoded secrets.

        Args:
            target_dir: Root directory to scan.

        Returns:
            List of ScanFinding objects for all detected issues.
        """
        target = Path(target_dir).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target directory not found: {target_dir}")
        if not target.is_dir():
            raise NotADirectoryError(f"Target is not a directory: {target_dir}")

        findings: List[ScanFinding] = []
        for root, dirs, files in os.walk(target):
            # Filter out excluded directories (modify in-place to prevent os.walk from descending)
            dirs[:] = [
                d for d in dirs
                if d not in self.exclude_dirs and not d.startswith(".")
                and not d.endswith(".egg-info")
            ]

            for filename in files:
                file_path = Path(root) / filename
                ext = file_path.suffix.lower()
                if ext in self.extensions:
                    file_findings = self._scan_file(file_path)
                    findings.extend(file_findings)

        return findings

    def scan_file(self, file_path: str) -> List[ScanFinding]:
        """Scan a single file for hardcoded secrets.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of ScanFinding objects.
        """
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        return self._scan_file(path)

    def _scan_file(self, file_path: Path) -> List[ScanFinding]:
        """Internal method to scan a single file.

        Args:
            file_path: Path to the file.

        Returns:
            List of ScanFinding objects.
        """
        findings: List[ScanFinding] = []
        content = read_file_safe(file_path)
        if content is None:
            return findings

        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                # Still scan comment lines for accidentally committed secrets
                pass

            for pattern, name, severity in self._compiled_patterns:
                match = pattern.search(line)
                if match:
                    matched_text = match.group(0)
                    # For patterns with capture groups, check if the captured value is a placeholder
                    if match.lastindex and match.lastindex >= 1:
                        captured = match.group(1)
                        if is_placeholder(captured):
                            continue

                    findings.append(ScanFinding(
                        file_path=str(file_path),
                        line_number=line_num,
                        matched_content=matched_text[:100],  # Truncate long matches
                        pattern_name=name,
                        severity=severity,
                    ))

        return findings

    def get_scan_stats(self, findings: List[ScanFinding]) -> Dict[str, int]:
        """Compute statistics from scan findings.

        Args:
            findings: List of ScanFinding objects.

        Returns:
            Dictionary with severity counts and total.
        """
        stats: Dict[str, int] = {
            "total": len(findings),
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        for finding in findings:
            sev = finding.severity.upper()
            if sev in stats:
                stats[sev] += 1
        return stats
