"""
Environment variable manager for EnvShield.

Provides CRUD operations for environment variables, multi-environment support,
variable reference resolution, .env file validation, and import/export capabilities.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from envshield.utils import is_valid_key_name, parse_env_line, read_file_safe, write_file_safe


class EnvManagerError(Exception):
    """Custom exception for environment manager errors."""
    pass


class EnvManager:
    """Manages environment variables across multiple environments.

    Supports loading/saving .env files, CRUD operations, variable reference
    resolution with ${VAR_NAME} syntax, multi-environment switching, and
    import/export in JSON and YAML formats.

    Attributes:
        project_dir: Root directory for the project.
        current_env: Currently active environment name.
        env_dir: Directory where environment-specific .env files are stored.
    """

    def __init__(self, project_dir: Optional[str] = None, env_name: str = "dev"):
        """Initialize the environment manager.

        Args:
            project_dir: Project root directory. Defaults to current directory.
            env_name: Initial environment name.
        """
        self.project_dir = Path(project_dir or os.getcwd()).resolve()
        self.current_env = env_name
        self.env_dir = self.project_dir / ".envshield" / "envs"
        self._vars: Dict[str, str] = {}

    def _get_env_file_path(self, env_name: Optional[str] = None) -> Path:
        """Get the path to the .env file for a given environment.

        Args:
            env_name: Environment name. Defaults to current_env.

        Returns:
            Path to the environment-specific .env file.
        """
        name = env_name or self.current_env
        return self.env_dir / f".env.{name}"

    def _get_main_env_path(self) -> Path:
        """Get the path to the main .env file in the project root.

        Returns:
            Path to the root .env file.
        """
        return self.project_dir / ".env"

    def load(self, env_name: Optional[str] = None, file_path: Optional[str] = None) -> Dict[str, str]:
        """Load environment variables from a file.

        Args:
            env_name: Environment name to load. Ignored if file_path is provided.
            file_path: Explicit file path to load from.

        Returns:
            Dictionary of loaded environment variables.

        Raises:
            FileNotFoundError: If the specified file does not exist.
            EnvManagerError: If the file cannot be parsed.
        """
        if file_path:
            path = Path(file_path).resolve()
        else:
            path = self._get_env_file_path(env_name)

        if not path.exists():
            raise FileNotFoundError(f"Environment file not found: {path}")

        content = read_file_safe(path)
        if content is None:
            raise EnvManagerError(f"Failed to read environment file: {path}")

        self._vars = self._parse_env_content(content)
        return dict(self._vars)

    def load_main_env(self) -> Dict[str, str]:
        """Load from the main .env file in the project root.

        Returns:
            Dictionary of loaded environment variables.

        Raises:
            FileNotFoundError: If .env does not exist.
        """
        return self.load(file_path=str(self._get_main_env_path()))

    def save(self, env_name: Optional[str] = None, file_path: Optional[str] = None) -> str:
        """Save current environment variables to a file.

        Args:
            env_name: Environment name to save to. Ignored if file_path is provided.
            file_path: Explicit file path to save to.

        Returns:
            Path to the saved file.

        Raises:
            EnvManagerError: If saving fails.
        """
        if file_path:
            path = Path(file_path).resolve()
        else:
            path = self._get_env_file_path(env_name)

        content = self._serialize_env(self._vars)
        if not write_file_safe(path, content):
            raise EnvManagerError(f"Failed to save environment file: {path}")

        return str(path)

    def save_main_env(self) -> str:
        """Save current variables to the main .env file.

        Returns:
            Path to the saved file.
        """
        return self.save(file_path=str(self._get_main_env_path()))

    def get(self, key: str, resolve_refs: bool = True) -> Optional[str]:
        """Get the value of an environment variable.

        Args:
            key: Variable name.
            resolve_refs: Whether to resolve ${VAR} references.

        Returns:
            Variable value or None if not found.
        """
        value = self._vars.get(key)
        if value is not None and resolve_refs:
            value = self.resolve_references(value)
        return value

    def set(self, key: str, value: str) -> None:
        """Set an environment variable.

        Args:
            key: Variable name.
            value: Variable value.

        Raises:
            EnvManagerError: If the key name is invalid.
        """
        if not is_valid_key_name(key):
            raise EnvManagerError(f"Invalid environment variable name: '{key}'")
        self._vars[key] = value

    def delete(self, key: str) -> bool:
        """Delete an environment variable.

        Args:
            key: Variable name to delete.

        Returns:
            True if the variable existed and was deleted, False otherwise.
        """
        if key in self._vars:
            del self._vars[key]
            return True
        return False

    def list_vars(self, mask_values: bool = True) -> Dict[str, str]:
        """List all environment variables.

        Args:
            mask_values: If True, mask sensitive values for display.

        Returns:
            Dictionary of all variables (masked if requested).
        """
        if mask_values:
            from envshield.utils import mask_sensitive_value
            return {k: mask_sensitive_value(v) for k, v in self._vars.items()}
        return dict(self._vars)

    def switch_env(self, env_name: str) -> Dict[str, str]:
        """Switch to a different environment.

        Saves current variables and loads the new environment.

        Args:
            env_name: Name of the environment to switch to.

        Returns:
            Dictionary of loaded variables for the new environment.
        """
        # Save current environment
        if self._vars:
            self.save()

        self.current_env = env_name
        return self.load()

    def resolve_references(self, value: str, max_depth: int = 10) -> str:
        """Resolve ${VAR_NAME} references in a value.

        Supports nested references up to the specified depth to prevent
        infinite recursion.

        Args:
            value: String potentially containing ${VAR_NAME} references.
            max_depth: Maximum recursion depth for nested references.

        Returns:
            String with all references resolved.
        """
        if max_depth <= 0:
            return value

        def replacer(match: re.Match) -> str:
            var_name = match.group(1)
            # Check environment variables first, then loaded vars
            ref_value = os.environ.get(var_name) or self._vars.get(var_name, "")
            if ref_value and "${" in ref_value:
                ref_value = self.resolve_references(ref_value, max_depth - 1)
            return ref_value

        return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", replacer, value)

    def validate_env_content(self, content: str) -> List[str]:
        """Validate .env file content for syntax errors.

        Args:
            content: Raw .env file content.

        Returns:
            List of validation error messages (empty if valid).
        """
        errors: List[str] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if "=" not in stripped:
                errors.append(f"Line {line_num}: Missing '=' separator: {stripped}")
                continue

            key, _, value = stripped.partition("=")
            key = key.strip()

            if not key:
                errors.append(f"Line {line_num}: Empty key name")
                continue

            if not is_valid_key_name(key):
                errors.append(
                    f"Line {line_num}: Invalid key name '{key}'. "
                    "Keys must start with a letter or underscore and contain only "
                    "alphanumeric characters and underscores."
                )

            # Check for unbalanced quotes
            value = value.strip()
            if value.startswith('"') and not value.endswith('"') and '"' not in value[1:]:
                errors.append(f"Line {line_num}: Unbalanced double quotes")
            elif value.startswith("'") and not value.endswith("'") and "'" not in value[1:]:
                errors.append(f"Line {line_num}: Unbalanced single quotes")

        return errors

    def export_json(self, output_path: str) -> str:
        """Export environment variables to a JSON file.

        Args:
            output_path: Path for the output JSON file.

        Returns:
            Path to the exported file.
        """
        data = {
            "environment": self.current_env,
            "variables": dict(self._vars),
        }
        content = json.dumps(data, indent=2, ensure_ascii=False)
        if not write_file_safe(Path(output_path), content):
            raise EnvManagerError(f"Failed to export to: {output_path}")
        return output_path

    def export_yaml(self, output_path: str) -> str:
        """Export environment variables to a YAML file.

        Args:
            output_path: Path for the output YAML file.

        Returns:
            Path to the exported file.
        """
        lines = [f"# EnvShield Export - Environment: {self.current_env}", ""]
        for key, value in sorted(self._vars.items()):
            # Quote values that might need it
            if any(c in value for c in ':#{}[]|>!&*?\'"\\@`'):
                escaped = value.replace("'", "''")
                lines.append(f"{key}: '{escaped}'")
            else:
                lines.append(f"{key}: {value}")

        content = "\n".join(lines) + "\n"
        if not write_file_safe(Path(output_path), content):
            raise EnvManagerError(f"Failed to export to: {output_path}")
        return output_path

    def import_json(self, input_path: str) -> Dict[str, str]:
        """Import environment variables from a JSON file.

        Args:
            input_path: Path to the JSON file to import.

        Returns:
            Dictionary of imported variables.

        Raises:
            EnvManagerError: If the file cannot be read or parsed.
        """
        content = read_file_safe(Path(input_path))
        if content is None:
            raise EnvManagerError(f"Failed to read import file: {input_path}")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise EnvManagerError(f"Invalid JSON in import file: {e}")

        if isinstance(data, dict):
            # Check if it's our export format with a 'variables' key
            if "variables" in data and isinstance(data["variables"], dict):
                imported = data["variables"]
            else:
                imported = data
        else:
            raise EnvManagerError("JSON import file must contain a dictionary")

        # Validate and set all imported variables
        for key, value in imported.items():
            if isinstance(value, str) and is_valid_key_name(key):
                self._vars[key] = value

        return dict(self._vars)

    def import_yaml(self, input_path: str) -> Dict[str, str]:
        """Import environment variables from a YAML file.

        Uses a simple YAML parser that handles basic key-value pairs.

        Args:
            input_path: Path to the YAML file to import.

        Returns:
            Dictionary of imported variables.

        Raises:
            EnvManagerError: If the file cannot be read or parsed.
        """
        content = read_file_safe(Path(input_path))
        if content is None:
            raise EnvManagerError(f"Failed to read import file: {input_path}")

        imported: Dict[str, str] = {}
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if ":" in stripped:
                key, _, value = stripped.partition(":")
                key = key.strip()
                value = value.strip()
                if not key or not is_valid_key_name(key):
                    continue

                # Remove surrounding quotes
                if len(value) >= 2:
                    if value[0] == "'" and value[-1] == "'":
                        value = value[1:-1].replace("''", "'")
                    elif value[0] == '"' and value[-1] == '"':
                        value = value[1:-1].replace('\\"', '"')

                imported[key] = value

        self._vars.update(imported)
        return dict(self._vars)

    def _parse_env_content(self, content: str) -> Dict[str, str]:
        """Parse .env file content into a dictionary.

        Args:
            content: Raw .env file content.

        Returns:
            Dictionary of parsed key-value pairs.
        """
        env_vars: Dict[str, str] = {}
        for line in content.splitlines():
            result = parse_env_line(line)
            if result:
                key, value = result
                env_vars[key] = value
        return env_vars

    def _serialize_env(self, env_vars: Dict[str, str]) -> str:
        """Serialize environment variables to .env file format.

        Args:
            env_vars: Dictionary of environment variables.

        Returns:
            Formatted .env file content string.
        """
        lines = ["# Managed by EnvShield", f"# Environment: {self.current_env}", ""]
        for key, value in sorted(env_vars.items()):
            # Quote values containing special characters
            if any(c in value for c in ' \t"\'#\\$') or not value:
                escaped = value.replace("\\", "\\\\").replace('"', '\\"')
                lines.append(f'{key}="{escaped}"')
            else:
                lines.append(f"{key}={value}")
        lines.append("")
        return "\n".join(lines)

    @property
    def variables(self) -> Dict[str, str]:
        """Get a copy of all current environment variables.

        Returns:
            Dictionary copy of all variables.
        """
        return dict(self._vars)

    @property
    def environments(self) -> List[str]:
        """List available environments based on existing .env.* files.

        Returns:
            Sorted list of environment names.
        """
        envs: List[str] = []
        if self.env_dir.exists():
            for f in self.env_dir.iterdir():
                if f.name.startswith(".env.") and f.is_file():
                    env_name = f.name[5:]  # Remove ".env." prefix
                    envs.append(env_name)
        return sorted(envs)
