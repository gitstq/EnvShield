"""Tests for the scanner module."""

import os
import tempfile
import unittest
from pathlib import Path

from envshield.scanner import (
    DEFAULT_EXCLUDE_DIRS,
    DEFAULT_SCAN_EXTENSIONS,
    ScanFinding,
    SourceScanner,
    is_placeholder,
)


class TestIsPlaceholder(unittest.TestCase):
    """Tests for the is_placeholder helper function."""

    def test_empty_value(self):
        """Test that empty string is a placeholder."""
        self.assertTrue(is_placeholder(""))

    def test_short_value(self):
        """Test that very short values are placeholders."""
        self.assertTrue(is_placeholder("ab"))

    def test_change_me(self):
        """Test that 'changeme' is a placeholder."""
        self.assertTrue(is_placeholder("changeMe"))

    def test_your_secret_here(self):
        """Test that 'your-secret-here' is a placeholder."""
        self.assertTrue(is_placeholder("your-secret-here"))

    def test_real_value(self):
        """Test that a realistic secret is not a placeholder."""
        self.assertFalse(is_placeholder("sk_test_51AbcDefGhiJklMnoPqrStuVwXyZ"))

    def test_variable_reference(self):
        """Test that ${VAR} syntax is a placeholder."""
        self.assertTrue(is_placeholder("${DATABASE_PASSWORD}"))


class TestScanFinding(unittest.TestCase):
    """Tests for the ScanFinding class."""

    def test_to_dict(self):
        """Test finding serialization."""
        finding = ScanFinding(
            file_path="/tmp/test.py",
            line_number=10,
            matched_content="password=secret123",
            pattern_name="Password assignment",
            severity="HIGH",
        )
        d = finding.to_dict()
        self.assertEqual(d["file_path"], "/tmp/test.py")
        self.assertEqual(d["line_number"], 10)
        self.assertEqual(d["pattern_name"], "Password assignment")
        self.assertEqual(d["severity"], "HIGH")

    def test_repr(self):
        """Test finding repr."""
        finding = ScanFinding(
            file_path="/tmp/test.py", line_number=1,
            matched_content="test", pattern_name="Test", severity="LOW",
        )
        self.assertIn("/tmp/test.py", repr(finding))


class TestSourceScanner(unittest.TestCase):
    """Tests for the SourceScanner class."""

    def setUp(self):
        """Create a temporary directory with test files."""
        self.test_dir = tempfile.mkdtemp()
        self.scanner = SourceScanner()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_file(self, relative_path: str, content: str) -> str:
        """Helper to create a test file.

        Args:
            relative_path: Relative path within test directory.
            content: File content.

        Returns:
            Full path to the created file.
        """
        full_path = os.path.join(self.test_dir, relative_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
        return full_path

    def test_scan_password_in_python(self):
        """Test detecting password assignment in Python file."""
        self._create_file("app.py", 'DB_PASSWORD = "my_secret_password"\n')
        findings = self.scanner.scan(self.test_dir)
        self.assertTrue(len(findings) >= 1)
        self.assertTrue(any("Password" in f.pattern_name for f in findings))

    def test_scan_api_key_in_javascript(self):
        """Test detecting API key in JavaScript file."""
        self._create_file("config.js", 'const apiKey = "sk_test_abc123def456ghi789";\n')
        findings = self.scanner.scan(self.test_dir)
        self.assertTrue(len(findings) >= 1)

    def test_scan_private_key_pem(self):
        """Test detecting PEM private key block."""
        self._create_file("keys.py", 'PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"\n')
        findings = self.scanner.scan(self.test_dir)
        self.assertTrue(any("Private key" in f.pattern_name for f in findings))

    def test_scan_aws_key(self):
        """Test detecting AWS Access Key ID."""
        self._create_file("config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = self.scanner.scan(self.test_dir)
        self.assertTrue(any("AWS" in f.pattern_name for f in findings))

    def test_scan_database_uri(self):
        """Test detecting database connection string."""
        self._create_file("settings.py", 'DATABASE_URL = "postgres://admin:pass@host/db"\n')
        findings = self.scanner.scan(self.test_dir)
        self.assertTrue(any("Database" in f.pattern_name for f in findings))

    def test_scan_excludes_node_modules(self):
        """Test that node_modules directory is excluded."""
        self._create_file("node_modules/pkg/config.js", 'apiKey = "secret_key_12345";\n')
        findings = self.scanner.scan(self.test_dir)
        self.assertEqual(len(findings), 0)

    def test_scan_excludes_git(self):
        """Test that .git directory is excluded."""
        self._create_file(".git/config", 'password = "secret"\n')
        findings = self.scanner.scan(self.test_dir)
        self.assertEqual(len(findings), 0)

    def test_scan_excludes_venv(self):
        """Test that venv directory is excluded."""
        self._create_file("venv/lib/config.py", 'SECRET = "mysecretvalue"\n')
        findings = self.scanner.scan(self.test_dir)
        self.assertEqual(len(findings), 0)

    def test_scan_placeholder_not_flagged(self):
        """Test that placeholder values are not flagged."""
        self._create_file("app.py", 'password = "your-password-here"\n')
        findings = self.scanner.scan(self.test_dir)
        pw_findings = [f for f in findings if "Password" in f.pattern_name]
        self.assertEqual(len(pw_findings), 0)

    def test_scan_multiple_files(self):
        """Test scanning multiple files with different issues."""
        self._create_file("app.py", 'password = "real_password_123"\n')
        self._create_file("config.js", 'api_key = "sk_test_abc123def456ghi789jkl012mno345"\n')
        self._create_file("settings.yaml", "secret_key: my_super_secret_value\n")
        findings = self.scanner.scan(self.test_dir)
        self.assertTrue(len(findings) >= 3)

    def test_scan_nonexistent_dir(self):
        """Test that scanning nonexistent directory raises error."""
        with self.assertRaises(FileNotFoundError):
            self.scanner.scan("/nonexistent/directory")

    def test_scan_file_instead_of_dir(self):
        """Test that scanning a file instead of directory raises error."""
        file_path = self._create_file("test.py", "x = 1\n")
        with self.assertRaises(NotADirectoryError):
            self.scanner.scan(file_path)

    def test_scan_file_directly(self):
        """Test scanning a single file."""
        file_path = self._create_file("test.py", 'password = "real_password_123"\n')
        findings = self.scanner.scan_file(file_path)
        self.assertTrue(len(findings) >= 1)

    def test_scan_nonexistent_file(self):
        """Test that scanning nonexistent file raises error."""
        with self.assertRaises(FileNotFoundError):
            self.scanner.scan_file("/nonexistent/file.py")

    def test_scan_stats(self):
        """Test scan statistics computation."""
        self._create_file("app.py", 'password = "real_password_123"\n')
        findings = self.scanner.scan(self.test_dir)
        stats = self.scanner.get_scan_stats(findings)
        self.assertEqual(stats["total"], len(findings))
        self.assertIn("HIGH", stats)
        self.assertIn("CRITICAL", stats)

    def test_custom_exclude_dirs(self):
        """Test custom exclude directories."""
        scanner = SourceScanner(exclude_dirs=["custom_exclude"])
        self._create_file("custom_exclude/test.py", 'password = "real_password_123"\n')
        findings = scanner.scan(self.test_dir)
        self.assertEqual(len(findings), 0)

    def test_custom_extensions(self):
        """Test custom file extensions."""
        scanner = SourceScanner(extensions=[".py"])
        self._create_file("app.js", 'password = "real_password_123"\n')
        findings = scanner.scan(self.test_dir)
        self.assertEqual(len(findings), 0)

    def test_scan_bearer_token(self):
        """Test detecting Bearer tokens."""
        self._create_file("app.py", 'auth = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"\n')
        findings = self.scanner.scan(self.test_dir)
        self.assertTrue(any("Bearer" in f.pattern_name for f in findings))

    def test_scan_github_token(self):
        """Test detecting GitHub tokens."""
        self._create_file("config.py", 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh123456"\n')
        findings = self.scanner.scan(self.test_dir)
        self.assertTrue(any("GitHub" in f.pattern_name for f in findings))


if __name__ == "__main__":
    unittest.main()
