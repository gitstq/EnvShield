"""Tests for the CLI module."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from envshield.cli import cli


class TestCLIInit(unittest.TestCase):
    """Tests for the 'init' command."""

    def setUp(self):
        """Create a temporary directory and runner."""
        self.test_dir = tempfile.mkdtemp()
        self.runner = CliRunner()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_init_creates_config(self):
        """Test that init creates configuration file."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            result = self.runner.invoke(cli, ["init", "--name", "testproject"])
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(os.path.exists(".envshield.toml"))

    def test_init_creates_example_env(self):
        """Test that init creates .env.example file."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            result = self.runner.invoke(cli, ["init"])
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(os.path.exists(".env.example"))

    def test_init_overwrite_prompt(self):
        """Test that init prompts for overwrite when config exists."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            # Create existing config
            Path(".envshield.toml").write_text("[project]\nname = \"old\"")
            result = self.runner.invoke(cli, ["init"], input="n\n")
            # Should cancel
            self.assertIn("cancelled", result.output.lower())


class TestCLIEncryptDecrypt(unittest.TestCase):
    """Tests for the 'encrypt' and 'decrypt' commands."""

    STRONG_PASSWORD = "TestPass123!@#xyz"

    def setUp(self):
        """Create a temporary directory and runner."""
        self.test_dir = tempfile.mkdtemp()
        self.runner = CliRunner()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_encrypt_creates_vault(self):
        """Test that encrypt creates a .env.vault file."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            Path(".env").write_text("KEY=value\nSECRET=mysecret\n")
            result = self.runner.invoke(
                cli, ["encrypt", ".env", "--password", self.STRONG_PASSWORD]
            )
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(os.path.exists(".env.vault"))

    def test_decrypt_restores_env(self):
        """Test that decrypt restores the .env file."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            Path(".env").write_text("KEY=value\nSECRET=mysecret\n")
            self.runner.invoke(
                cli, ["encrypt", ".env", "--password", self.STRONG_PASSWORD]
            )
            result = self.runner.invoke(
                cli, ["decrypt", ".env.vault", "--password", self.STRONG_PASSWORD]
            )
            self.assertEqual(result.exit_code, 0)
            content = Path(".env").read_text()
            self.assertIn("KEY=value", content)
            self.assertIn("SECRET=mysecret", content)

    def test_encrypt_nonexistent_file(self):
        """Test that encrypt on nonexistent file fails."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            result = self.runner.invoke(
                cli, ["encrypt", "nonexistent.env", "--password", self.STRONG_PASSWORD]
            )
            self.assertNotEqual(result.exit_code, 0)

    def test_weak_password_rejected(self):
        """Test that weak password is rejected."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            Path(".env").write_text("KEY=value\n")
            result = self.runner.invoke(
                cli, ["encrypt", ".env", "--password", "weak"]
            )
            self.assertNotEqual(result.exit_code, 0)


class TestCLIAudit(unittest.TestCase):
    """Tests for the 'audit' command."""

    def setUp(self):
        """Create a temporary directory and runner."""
        self.test_dir = tempfile.mkdtemp()
        self.runner = CliRunner()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_audit_clean_env(self):
        """Test audit on clean environment shows no issues."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            Path(".env").write_text("APP_NAME=MyApp\nAPP_ENV=production\nPORT=8080\n")
            result = self.runner.invoke(cli, ["audit", ".env"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("100", result.output)

    def test_audit_finds_issues(self):
        """Test audit finds security issues."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            Path(".env").write_text(
                "DB_PASSWORD=short\n"
                "DATABASE_URL=postgres://admin:pass@host/db\n"
                "CORS_ORIGIN=*\n"
            )
            result = self.runner.invoke(cli, ["audit", ".env"])
            # Should have findings (non-zero exit or findings in output)
            self.assertIn("Finding", result.output) or self.assertNotEqual(result.exit_code, 0)

    def test_audit_json_output(self):
        """Test audit with JSON output format."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            Path(".env").write_text("DB_PASSWORD=short\n")
            result = self.runner.invoke(cli, ["audit", ".env", "--json"])
            # May exit with non-zero if issues found, but output should be valid JSON
            data = json.loads(result.output)
            self.assertIn("score", data)
            self.assertIn("findings", data)


class TestCLIScan(unittest.TestCase):
    """Tests for the 'scan' command."""

    def setUp(self):
        """Create a temporary directory and runner."""
        self.test_dir = tempfile.mkdtemp()
        self.runner = CliRunner()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_scan_clean_directory(self):
        """Test scan on clean directory shows no findings."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            Path("clean.py").write_text("x = 1\ny = 2\n")
            result = self.runner.invoke(cli, ["scan", "."])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No hardcoded secrets", result.output)

    def test_scan_finds_secrets(self):
        """Test scan detects hardcoded secrets."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            Path("config.py").write_text('password = "real_password_123"\n')
            result = self.runner.invoke(cli, ["scan", "."])
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("Password", result.output)

    def test_scan_json_output(self):
        """Test scan with JSON output format."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            Path("app.py").write_text('password = "real_password_123"\n')
            result = self.runner.invoke(cli, ["scan", ".", "--json"])
            data = json.loads(result.output)
            self.assertIn("stats", data)
            self.assertIn("findings", data)
            self.assertGreater(data["stats"]["total"], 0)


class TestCLISetGetDelete(unittest.TestCase):
    """Tests for the 'set', 'get', 'delete', and 'list' commands."""

    def setUp(self):
        """Create a temporary directory and runner."""
        self.test_dir = tempfile.mkdtemp()
        self.runner = CliRunner()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_set_and_get(self):
        """Test setting and getting a variable."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            self.runner.invoke(cli, ["init"])
            self.runner.invoke(cli, ["set", "TEST_KEY", "test_value"])
            result = self.runner.invoke(cli, ["get", "TEST_KEY"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("TEST_KEY", result.output)

    def test_get_nonexistent(self):
        """Test getting a nonexistent variable."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            self.runner.invoke(cli, ["init"])
            result = self.runner.invoke(cli, ["get", "NONEXISTENT"])
            self.assertNotEqual(result.exit_code, 0)

    def test_delete_variable(self):
        """Test deleting a variable."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            self.runner.invoke(cli, ["init"])
            self.runner.invoke(cli, ["set", "TO_DELETE", "value"])
            result = self.runner.invoke(cli, ["delete", "TO_DELETE"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Deleted", result.output)

    def test_list_variables(self):
        """Test listing all variables."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            self.runner.invoke(cli, ["init"])
            self.runner.invoke(cli, ["set", "KEY1", "value1"])
            self.runner.invoke(cli, ["set", "KEY2", "value2"])
            result = self.runner.invoke(cli, ["list"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("KEY1", result.output)
            self.assertIn("KEY2", result.output)


class TestCLIExport(unittest.TestCase):
    """Tests for the 'export' command."""

    def setUp(self):
        """Create a temporary directory and runner."""
        self.test_dir = tempfile.mkdtemp()
        self.runner = CliRunner()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_export_json(self):
        """Test exporting to JSON."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            self.runner.invoke(cli, ["init"])
            self.runner.invoke(cli, ["set", "KEY1", "value1"])
            result = self.runner.invoke(cli, ["export", "--format", "json"])
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(os.path.exists("env_export_dev.json"))

    def test_export_yaml(self):
        """Test exporting to YAML."""
        with self.runner.isolated_filesystem(temp_dir=self.test_dir):
            self.runner.invoke(cli, ["init"])
            self.runner.invoke(cli, ["set", "KEY1", "value1"])
            result = self.runner.invoke(cli, ["export", "--format", "yaml"])
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(os.path.exists("env_export_dev.yaml"))


class TestCLIVersion(unittest.TestCase):
    """Tests for version flag."""

    def test_version(self):
        """Test that --version shows version info."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("1.0.0", result.output)


if __name__ == "__main__":
    unittest.main()
