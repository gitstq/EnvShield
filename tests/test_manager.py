"""Tests for the manager module."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from envshield.manager import EnvManager, EnvManagerError


class TestEnvManager(unittest.TestCase):
    """Tests for the EnvManager class."""

    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp()
        self.manager = EnvManager(project_dir=self.test_dir, env_name="dev")

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_env_file(self, content: str, filename: str = ".env") -> str:
        """Helper to create a test .env file.

        Args:
            content: File content.
            filename: Name of the file.

        Returns:
            Full path to the created file.
        """
        path = os.path.join(self.test_dir, filename)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_set_and_get(self):
        """Test setting and getting environment variables."""
        self.manager.set("DATABASE_URL", "postgres://localhost/mydb")
        self.manager.set("API_KEY", "secret123")
        self.assertEqual(self.manager.get("DATABASE_URL"), "postgres://localhost/mydb")
        self.assertEqual(self.manager.get("API_KEY"), "secret123")

    def test_get_nonexistent(self):
        """Test getting a nonexistent variable returns None."""
        self.assertIsNone(self.manager.get("NONEXISTENT_VAR"))

    def test_delete(self):
        """Test deleting a variable."""
        self.manager.set("TEST_VAR", "test_value")
        self.assertTrue(self.manager.delete("TEST_VAR"))
        self.assertIsNone(self.manager.get("TEST_VAR"))

    def test_delete_nonexistent(self):
        """Test deleting a nonexistent variable returns False."""
        self.assertFalse(self.manager.delete("NONEXISTENT_VAR"))

    def test_set_invalid_key(self):
        """Test that setting an invalid key raises error."""
        with self.assertRaises(EnvManagerError):
            self.manager.set("123invalid", "value")

        with self.assertRaises(EnvManagerError):
            self.manager.set("has-space", "value")

    def test_list_vars_masked(self):
        """Test listing variables with masked values."""
        self.manager.set("PASSWORD", "mysecretpassword123")
        self.manager.set("APP_NAME", "MyApp")
        result = self.manager.list_vars(mask_values=True)
        self.assertEqual(result["APP_NAME"], "MyAp*")  # Short values get masked
        self.assertTrue(result["PASSWORD"].endswith("****"))

    def test_list_vars_unmasked(self):
        """Test listing variables without masking."""
        self.manager.set("PASSWORD", "mysecretpassword123")
        result = self.manager.list_vars(mask_values=False)
        self.assertEqual(result["PASSWORD"], "mysecretpassword123")

    def test_save_and_load(self):
        """Test saving and loading environment variables."""
        self.manager.set("KEY1", "value1")
        self.manager.set("KEY2", "value2")
        saved_path = self.manager.save()

        new_manager = EnvManager(project_dir=self.test_dir, env_name="dev")
        loaded = new_manager.load()
        self.assertEqual(loaded["KEY1"], "value1")
        self.assertEqual(loaded["KEY2"], "value2")

    def test_load_from_file(self):
        """Test loading from a specific file."""
        content = "DB_HOST=localhost\nDB_PORT=5432\nDB_USER=admin\n"
        path = self._create_env_file(content)
        loaded = self.manager.load(file_path=path)
        self.assertEqual(loaded["DB_HOST"], "localhost")
        self.assertEqual(loaded["DB_PORT"], "5432")
        self.assertEqual(loaded["DB_USER"], "admin")

    def test_load_nonexistent_file(self):
        """Test loading from nonexistent file raises error."""
        with self.assertRaises(FileNotFoundError):
            self.manager.load(file_path="/nonexistent/.env")

    def test_parse_quoted_values(self):
        """Test parsing quoted values."""
        content = 'KEY1="value with spaces"\nKEY2=\'single quoted\'\nKEY3=no_quotes\n'
        path = self._create_env_file(content)
        loaded = self.manager.load(file_path=path)
        self.assertEqual(loaded["KEY1"], "value with spaces")
        self.assertEqual(loaded["KEY2"], "single quoted")
        self.assertEqual(loaded["KEY3"], "no_quotes")

    def test_parse_comments(self):
        """Test that comments are skipped."""
        content = "# This is a comment\nKEY1=value1\n# Another comment\nKEY2=value2\n"
        path = self._create_env_file(content)
        loaded = self.manager.load(file_path=path)
        self.assertNotIn("# This is a comment", loaded)
        self.assertEqual(loaded["KEY1"], "value1")
        self.assertEqual(loaded["KEY2"], "value2")

    def test_parse_empty_lines(self):
        """Test that empty lines are skipped."""
        content = "\n\nKEY1=value1\n\n\nKEY2=value2\n"
        path = self._create_env_file(content)
        loaded = self.manager.load(file_path=path)
        self.assertEqual(len(loaded), 2)

    def test_resolve_references(self):
        """Test ${VAR} reference resolution."""
        self.manager.set("BASE_URL", "https://api.example.com")
        self.manager.set("API_ENDPOINT", "${BASE_URL}/v1/users")
        result = self.manager.get("API_ENDPOINT", resolve_refs=True)
        self.assertEqual(result, "https://api.example.com/v1/users")

    def test_resolve_nested_references(self):
        """Test nested ${VAR} reference resolution."""
        self.manager.set("HOST", "example.com")
        self.manager.set("BASE_URL", "https://${HOST}")
        self.manager.set("API_URL", "${BASE_URL}/v1")
        result = self.manager.get("API_URL", resolve_refs=True)
        self.assertEqual(result, "https://example.com/v1")

    def test_resolve_with_env_var(self):
        """Test resolution falls back to os.environ."""
        os.environ["TEST_ENVSHIELD_RESOLVE"] = "resolved_value"
        try:
            self.manager.set("REF_KEY", "${TEST_ENVSHIELD_RESOLVE}")
            result = self.manager.get("REF_KEY", resolve_refs=True)
            self.assertEqual(result, "resolved_value")
        finally:
            del os.environ["TEST_ENVSHIELD_RESOLVE"]

    def test_validate_valid_content(self):
        """Test validation of valid .env content."""
        content = "VALID_KEY=value\nANOTHER_KEY=value2\n"
        errors = self.manager.validate_env_content(content)
        self.assertEqual(len(errors), 0)

    def test_validate_missing_equals(self):
        """Test validation catches missing equals sign."""
        content = "INVALID_LINE_NO_EQUALS\n"
        errors = self.manager.validate_env_content(content)
        self.assertTrue(len(errors) >= 1)
        self.assertTrue(any("Missing" in e for e in errors))

    def test_validate_invalid_key(self):
        """Test validation catches invalid key names."""
        content = "123invalid=value\n"
        errors = self.manager.validate_env_content(content)
        self.assertTrue(len(errors) >= 1)
        self.assertTrue(any("Invalid" in e for e in errors))

    def test_export_json(self):
        """Test exporting to JSON format."""
        self.manager.set("KEY1", "value1")
        self.manager.set("KEY2", "value2")
        output_path = os.path.join(self.test_dir, "export.json")
        result = self.manager.export_json(output_path)

        with open(result, "r") as f:
            data = json.load(f)
        self.assertEqual(data["environment"], "dev")
        self.assertEqual(data["variables"]["KEY1"], "value1")
        self.assertEqual(data["variables"]["KEY2"], "value2")

    def test_export_yaml(self):
        """Test exporting to YAML format."""
        self.manager.set("KEY1", "value1")
        self.manager.set("KEY2", "value with spaces")
        output_path = os.path.join(self.test_dir, "export.yaml")
        result = self.manager.export_yaml(output_path)

        with open(result, "r") as f:
            content = f.read()
        self.assertIn("KEY1: value1", content)
        self.assertIn("KEY2:", content)

    def test_import_json(self):
        """Test importing from JSON format."""
        import_data = {
            "environment": "test",
            "variables": {
                "IMPORTED_KEY": "imported_value",
                "ANOTHER_KEY": "another_value",
            },
        }
        json_path = os.path.join(self.test_dir, "import.json")
        with open(json_path, "w") as f:
            json.dump(import_data, f)

        result = self.manager.import_json(json_path)
        self.assertEqual(result["IMPORTED_KEY"], "imported_value")
        self.assertEqual(result["ANOTHER_KEY"], "another_value")

    def test_import_yaml(self):
        """Test importing from YAML format."""
        yaml_content = "KEY1: value1\nKEY2: value2\n# comment\nKEY3: value3\n"
        yaml_path = os.path.join(self.test_dir, "import.yaml")
        with open(yaml_path, "w") as f:
            f.write(yaml_content)

        result = self.manager.import_yaml(yaml_path)
        self.assertEqual(result["KEY1"], "value1")
        self.assertEqual(result["KEY2"], "value2")
        self.assertEqual(result["KEY3"], "value3")

    def test_variables_property(self):
        """Test that variables property returns a copy."""
        self.manager.set("KEY1", "value1")
        vars_copy = self.manager.variables
        vars_copy["KEY1"] = "modified"
        self.assertEqual(self.manager.get("KEY1"), "value1")

    def test_switch_env(self):
        """Test switching between environments."""
        # Set up dev environment
        self.manager.set("DEV_VAR", "dev_value")
        self.manager.save()

        # Create staging environment file first
        staging_manager = EnvManager(project_dir=self.test_dir, env_name="staging")
        staging_manager.set("STAGING_VAR", "staging_value")
        staging_manager.save()

        # Switch to staging
        loaded = self.manager.switch_env("staging")
        self.assertEqual(loaded.get("STAGING_VAR"), "staging_value")
        self.assertIsNone(loaded.get("DEV_VAR"))

        # Switch back to dev
        loaded = self.manager.switch_env("dev")
        self.assertEqual(loaded.get("DEV_VAR"), "dev_value")
        self.assertIsNone(loaded.get("STAGING_VAR"))

    def test_environments_list(self):
        """Test listing available environments."""
        self.manager.set("KEY1", "value1")
        self.manager.save()  # Save dev environment

        # Create staging environment
        staging_manager = EnvManager(project_dir=self.test_dir, env_name="staging")
        staging_manager.set("KEY2", "value2")
        staging_manager.save()  # Save staging environment

        envs = self.manager.environments
        self.assertIn("dev", envs)
        self.assertIn("staging", envs)

    def test_save_main_env(self):
        """Test saving to main .env file."""
        self.manager.set("MAIN_KEY", "main_value")
        result = self.manager.save_main_env()

        self.assertTrue(os.path.exists(result))
        with open(result, "r") as f:
            content = f.read()
        self.assertIn("MAIN_KEY=main_value", content)

    def test_load_main_env(self):
        """Test loading from main .env file."""
        content = "MAIN_KEY=main_value\n"
        self._create_env_file(content, ".env")
        loaded = self.manager.load_main_env()
        self.assertEqual(loaded["MAIN_KEY"], "main_value")


if __name__ == "__main__":
    unittest.main()
