"""
Configuration management for EnvShield.

Handles loading, saving, and managing the .envshield.toml configuration file
with support for project-specific settings, encryption parameters, audit
whitelists, and environment definitions.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from envshield.utils import read_file_safe, write_file_safe


# Default configuration template
DEFAULT_CONFIG = """\
[project]
name = ""
environments = ["dev", "staging", "prod"]
current_env = "dev"

[encryption]
algorithm = "AES-256-GCM"
key_derivation = "PBKDF2"
iterations = 600000
salt_length = 32

[audit]
# Whitelist rule IDs that should be skipped during audit
whitelist = []
# Directories to exclude from scanning
exclude_dirs = ["node_modules", ".git", "venv", "__pycache__", ".venv", "dist", "build"]
# File extensions to scan
scan_extensions = [
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java",
    ".yml", ".yaml", ".json", ".toml", ".env", ".ini", ".cfg"
]

[git_hook]
# Enable automatic .env file protection
block_env_commit = true
# Enable automatic audit on .env.vault commit
audit_vault_commit = true

[dashboard]
# Maximum number of audit history entries to display
history_limit = 20
"""


class Config:
    """Manages EnvShield project configuration.

    Handles loading and saving the .envshield.toml configuration file,
    providing access to all configuration sections with sensible defaults.

    Attributes:
        config_path: Path to the configuration file.
        data: Parsed configuration dictionary.
    """

    def __init__(self, config_path: Optional[str] = None, project_dir: Optional[str] = None):
        """Initialize Config with optional path override.

        Args:
            config_path: Explicit path to config file. If None, searches project dir.
            project_dir: Project root directory. Defaults to current working directory.
        """
        self._project_dir = Path(project_dir or os.getcwd()).resolve()
        if config_path:
            self.config_path = Path(config_path).resolve()
        else:
            self.config_path = self._project_dir / ".envshield.toml"
        self.data: Dict[str, Any] = {}

    def exists(self) -> bool:
        """Check if the configuration file exists.

        Returns:
            True if config file exists on disk.
        """
        return self.config_path.exists()

    def load(self) -> Dict[str, Any]:
        """Load configuration from the TOML file.

        Falls back to default configuration if the file does not exist
        or cannot be parsed.

        Returns:
            Configuration dictionary.
        """
        if not self.exists():
            self.data = self._parse_defaults()
            return self.data

        content = read_file_safe(self.config_path)
        if content is None:
            self.data = self._parse_defaults()
            return self.data

        self.data = self._parse_toml(content)
        return self.data

    def save(self) -> bool:
        """Save current configuration to the TOML file.

        Returns:
            True if saving succeeded.
        """
        content = self._serialize_toml(self.data)
        return write_file_safe(self.config_path, content)

    def init(self, project_name: str = "") -> bool:
        """Initialize a new configuration file with defaults.

        Args:
            project_name: Optional project name to embed in config.

        Returns:
            True if initialization succeeded.
        """
        self.load()
        if project_name:
            self.data.setdefault("project", {})["name"] = project_name
        return self.save()

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value.

        Args:
            section: Configuration section name.
            key: Key within the section.
            default: Default value if key is not found.

        Returns:
            The configuration value or default.
        """
        if not self.data:
            self.load()
        return self.data.get(section, {}).get(key, default)

    def set(self, section: str, key: str, value: Any) -> None:
        """Set a configuration value.

        Args:
            section: Configuration section name.
            key: Key within the section.
            value: Value to set.
        """
        if not self.data:
            self.load()
        if section not in self.data:
            self.data[section] = {}
        self.data[section][key] = value

    def get_environments(self) -> List[str]:
        """Get the list of configured environments.

        Returns:
            List of environment names (e.g., ['dev', 'staging', 'prod']).
        """
        envs = self.get("project", "environments", ["dev", "staging", "prod"])
        if isinstance(envs, str):
            return [e.strip() for e in envs.split(",")]
        return list(envs)

    def get_current_env(self) -> str:
        """Get the currently active environment name.

        Returns:
            Current environment name string.
        """
        return self.get("project", "current_env", "dev")

    def set_current_env(self, env_name: str) -> None:
        """Set the currently active environment.

        Args:
            env_name: Name of the environment to switch to.
        """
        self.set("project", "current_env", env_name)

    def get_exclude_dirs(self) -> List[str]:
        """Get directories to exclude from scanning.

        Returns:
            List of directory names to exclude.
        """
        dirs = self.get("audit", "exclude_dirs", [
            "node_modules", ".git", "venv", "__pycache__", ".venv", "dist", "build"
        ])
        if isinstance(dirs, str):
            return [d.strip() for d in dirs.split(",")]
        return list(dirs)

    def get_scan_extensions(self) -> List[str]:
        """Get file extensions to include in scanning.

        Returns:
            List of file extensions (with leading dot).
        """
        exts = self.get("audit", "scan_extensions", [
            ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java",
            ".yml", ".yaml", ".json", ".toml", ".env", ".ini", ".cfg"
        ])
        if isinstance(exts, str):
            return [e.strip() for e in exts.split(",")]
        return list(exts)

    def get_audit_whitelist(self) -> List[str]:
        """Get the list of whitelisted (skipped) audit rule IDs.

        Returns:
            List of rule ID strings.
        """
        rules = self.get("audit", "whitelist", [])
        if isinstance(rules, str):
            return [r.strip() for r in rules.split(",")]
        return list(rules)

    def get_encryption_iterations(self) -> int:
        """Get the PBKDF2 iteration count for key derivation.

        Returns:
            Integer iteration count (default: 600000).
        """
        return int(self.get("encryption", "iterations", 600000))

    def get_salt_length(self) -> int:
        """Get the salt length for key derivation.

        Returns:
            Integer salt length in bytes (default: 32).
        """
        return int(self.get("encryption", "salt_length", 32))

    def _parse_defaults(self) -> Dict[str, Any]:
        """Return the default configuration dictionary.

        Returns:
            Default configuration as a nested dictionary.
        """
        return {
            "project": {
                "name": "",
                "environments": ["dev", "staging", "prod"],
                "current_env": "dev",
            },
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_derivation": "PBKDF2",
                "iterations": 600000,
                "salt_length": 32,
            },
            "audit": {
                "whitelist": [],
                "exclude_dirs": [
                    "node_modules", ".git", "venv", "__pycache__",
                    ".venv", "dist", "build",
                ],
                "scan_extensions": [
                    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java",
                    ".yml", ".yaml", ".json", ".toml", ".env", ".ini", ".cfg",
                ],
            },
            "git_hook": {
                "block_env_commit": True,
                "audit_vault_commit": True,
            },
            "dashboard": {
                "history_limit": 20,
            },
        }

    def _parse_toml(self, content: str) -> Dict[str, Any]:
        """Parse TOML content into a dictionary.

        Uses the built-in tomllib (Python 3.11+) or falls back to a
        simple manual parser for older Python versions.

        Args:
            content: TOML-formatted string.

        Returns:
            Parsed dictionary.
        """
        # Try built-in tomllib first (Python 3.11+)
        try:
            import tomllib  # type: ignore
            return tomllib.loads(content)
        except ImportError:
            pass

        # Try tomli package
        try:
            import tomli  # type: ignore
            return tomli.loads(content)
        except ImportError:
            pass

        # Fallback: simple TOML parser for basic cases
        return self._simple_toml_parse(content)

    def _simple_toml_parse(self, content: str) -> Dict[str, Any]:
        """Simple TOML parser for basic key-value and section syntax.

        Handles [section] headers, string/integer/boolean/array values,
        and comments. Not a full TOML spec implementation.

        Args:
            content: TOML-formatted string.

        Returns:
            Parsed dictionary.
        """
        import re

        result: Dict[str, Any] = {}
        current_section: Optional[str] = None

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Section header
            section_match = re.match(r"^\[([^\]]+)\]$", line)
            if section_match:
                current_section = section_match.group(1).strip()
                if current_section not in result:
                    result[current_section] = {}
                continue

            # Key-value pair
            kv_match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$', line)
            if kv_match:
                key = kv_match.group(1)
                value_str = kv_match.group(2).strip()

                # Remove inline comments
                if " #" in value_str:
                    value_str = value_str[: value_str.index(" #")].strip()

                value = self._parse_toml_value(value_str)

                if current_section:
                    result[current_section][key] = value
                else:
                    result[key] = value

        return result

    def _parse_toml_value(self, value_str: str) -> Any:
        """Parse a single TOML value string into a Python object.

        Args:
            value_str: The raw value string from TOML.

        Returns:
            Parsed Python object (str, int, bool, list).
        """
        # Boolean
        if value_str.lower() == "true":
            return True
        if value_str.lower() == "false":
            return False

        # Integer
        try:
            return int(value_str)
        except ValueError:
            pass

        # Float
        try:
            return float(value_str)
        except ValueError:
            pass

        # String (strip quotes)
        if len(value_str) >= 2:
            if (value_str[0] == '"' and value_str[-1] == '"') or \
               (value_str[0] == "'" and value_str[-1] == "'"):
                return value_str[1:-1]

        # Array
        if value_str.startswith("[") and value_str.endswith("]"):
            inner = value_str[1:-1].strip()
            if not inner:
                return []
            items = []
            for item in inner.split(","):
                item = item.strip()
                if item:
                    items.append(self._parse_toml_value(item))
            return items

        return value_str

    def _serialize_toml(self, data: Dict[str, Any]) -> str:
        """Serialize a dictionary to TOML format.

        Args:
            data: Configuration dictionary.

        Returns:
            TOML-formatted string.
        """
        lines: List[str] = []

        for section, values in data.items():
            if isinstance(values, dict):
                lines.append(f"[{section}]")
                for key, value in values.items():
                    lines.append(f"{key} = {self._serialize_value(value)}")
                lines.append("")
            else:
                lines.append(f"{key} = {self._serialize_value(values)}")

        return "\n".join(lines)

    def _serialize_value(self, value: Any) -> str:
        """Serialize a Python value to TOML format.

        Args:
            value: Python value to serialize.

        Returns:
            TOML-formatted value string.
        """
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int):
            return str(value)
        if isinstance(value, float):
            return str(value)
        if isinstance(value, str):
            # Escape and quote strings
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        if isinstance(value, list):
            items = [self._serialize_value(v) for v in value]
            return f"[{', '.join(items)}]"
        return str(value)
