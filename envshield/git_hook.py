"""
Git pre-commit hook management for EnvShield.

Provides installation and uninstallation of Git hooks that prevent
.env file commits and automatically audit .env.vault files.
"""

import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Optional


HOOK_TEMPLATE = """\
#!/usr/bin/env python3
\"\"\"EnvShield Git pre-commit hook.

This hook is automatically installed by EnvShield to protect against
accidental commits of sensitive environment files.
\"\"\"

import os
import subprocess
import sys


def main():
    \"\"\"Run EnvShield pre-commit checks.\"\"\"
    # Get list of staged files
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )
        staged_files = result.stdout.strip().split("\\n")
    except (subprocess.CalledProcessError, FileNotFoundError):
        # git not available or not in a repo, allow commit
        return 0

    blocked = False
    warnings = []

    # Check for .env files
    env_files = [f for f in staged_files if f.endswith(".env") and not f.endswith(".env.vault") and not f.endswith(".env.example")]
    if env_files:
        blocked = True
        for f in env_files:
            warnings.append(f"  BLOCKED: {f} - .env files should not be committed")

    # Check for .env.vault files - audit them
    vault_files = [f for f in staged_files if f.endswith(".env.vault")]
    if vault_files:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "envshield", "audit"] + vault_files,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                warnings.append(f"  WARNING: Audit issues found in vault files")
                if result.stdout:
                    for line in result.stdout.strip().split("\\n")[:5]:
                        warnings.append(f"    {line}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass  # envshield not available, skip audit

    if blocked:
        print("=" * 60)
        print("EnvShield: Pre-commit check FAILED")
        print("=" * 60)
        for w in warnings:
            print(w)
        print("")
        print("To fix:")
        print("  1. Add .env files to .gitignore")
        print("  2. Use 'envshield encrypt' to create .env.vault files")
        print("  3. Commit only .env.vault files")
        print("")
        print("To bypass this hook (not recommended):")
        print("  git commit --no-verify")
        print("=" * 60)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
"""


class GitHookError(Exception):
    """Custom exception for Git hook errors."""
    pass


class GitHookManager:
    """Manages Git pre-commit hooks for EnvShield.

    Installs and uninstalls a pre-commit hook that:
    - Blocks .env files from being committed
    - Audits .env.vault files before commit
    """

    def __init__(self, project_dir: Optional[str] = None):
        """Initialize the Git hook manager.

        Args:
            project_dir: Project root directory. Defaults to current directory.
        """
        self.project_dir = Path(project_dir or os.getcwd()).resolve()
        self.hooks_dir = self._find_git_hooks_dir()
        self.hook_path = self.hooks_dir / "pre-commit" if self.hooks_dir else None

    def _find_git_hooks_dir(self) -> Optional[Path]:
        """Find the Git hooks directory for the project.

        Returns:
            Path to the .git/hooks directory, or None if not in a Git repo.
        """
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                capture_output=True,
                text=True,
                cwd=str(self.project_dir),
                check=True,
            )
            git_dir = Path(result.stdout.strip())
            hooks_dir = git_dir / "hooks"
            if hooks_dir.exists():
                return hooks_dir
            return None
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    def is_installed(self) -> bool:
        """Check if the EnvShield pre-commit hook is installed.

        Returns:
            True if the hook is installed.
        """
        if not self.hook_path or not self.hook_path.exists():
            return False

        content = self.hook_path.read_text(encoding="utf-8", errors="ignore")
        return "EnvShield" in content

    def install(self, force: bool = False) -> str:
        """Install the EnvShield pre-commit hook.

        Args:
            force: If True, overwrite an existing hook.

        Returns:
            Status message.

        Raises:
            GitHookError: If installation fails.
        """
        if not self.hooks_dir:
            raise GitHookError(
                "Not in a Git repository. Cannot install hooks."
            )

        if self.hook_path and self.hook_path.exists():
            if self.is_installed():
                if not force:
                    return "EnvShield hook is already installed. Use --force to reinstall."
                # Backup existing hook
                backup_path = self.hook_path.with_suffix(".pre-envshield.bak")
                try:
                    backup_path.write_text(
                        self.hook_path.read_text(encoding="utf-8", errors="ignore"),
                        encoding="utf-8",
                    )
                except IOError:
                    pass

        # Ensure hooks directory exists
        self.hooks_dir.mkdir(parents=True, exist_ok=True)

        # Write the hook
        try:
            self.hook_path.write_text(HOOK_TEMPLATE, encoding="utf-8")
            # Make the hook executable
            self.hook_path.chmod(
                self.hook_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
            )
        except IOError as e:
            raise GitHookError(f"Failed to install hook: {e}")

        return f"EnvShield pre-commit hook installed at: {self.hook_path}"

    def uninstall(self) -> str:
        """Uninstall the EnvShield pre-commit hook.

        Returns:
            Status message.

        Raises:
            GitHookError: If uninstallation fails.
        """
        if not self.hook_path or not self.hook_path.exists():
            return "No EnvShield hook found. Nothing to uninstall."

        if not self.is_installed():
            return "Existing pre-commit hook is not managed by EnvShield. Skipping."

        try:
            self.hook_path.unlink()
        except IOError as e:
            raise GitHookError(f"Failed to uninstall hook: {e}")

        # Restore backup if it exists
        backup_path = self.hook_path.with_suffix(".pre-envshield.bak")
        if backup_path.exists():
            try:
                backup_path.rename(self.hook_path)
                return (
                    f"EnvShield hook uninstalled. "
                    f"Previous hook restored from backup."
                )
            except IOError:
                pass

        return "EnvShield pre-commit hook uninstalled."

    def generate_hook_template(self, output_path: str) -> str:
        """Generate a hook template file without installing it.

        Args:
            output_path: Path to write the template to.

        Returns:
            Path to the generated template file.

        Raises:
            GitHookError: If writing fails.
        """
        path = Path(output_path).resolve()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(HOOK_TEMPLATE, encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IEXEC)
        except IOError as e:
            raise GitHookError(f"Failed to generate hook template: {e}")

        return str(path)
