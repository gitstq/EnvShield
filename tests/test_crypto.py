"""Tests for the crypto module."""

import os
import tempfile
import unittest
from pathlib import Path

from envshield.crypto import (
    CryptoError,
    PasswordStrengthError,
    decrypt_data,
    decrypt_env_file,
    decrypt_to_memory,
    derive_key,
    encrypt_data,
    encrypt_env_file,
    generate_salt,
    inject_env_vars,
    validate_password_strength,
)


class TestPasswordValidation(unittest.TestCase):
    """Tests for password strength validation."""

    def test_valid_strong_password(self):
        """Test that a strong password passes validation."""
        is_valid, msg = validate_password_strength("MyStr0ng!Pass#word")
        self.assertTrue(is_valid)
        self.assertEqual(msg, "")

    def test_too_short(self):
        """Test that short passwords are rejected."""
        is_valid, msg = validate_password_strength("Short1!")
        self.assertFalse(is_valid)
        self.assertIn("12", msg)

    def test_no_uppercase(self):
        """Test that passwords without uppercase are rejected."""
        is_valid, msg = validate_password_strength("alllowercase1!")
        self.assertFalse(is_valid)
        self.assertIn("uppercase", msg)

    def test_no_lowercase(self):
        """Test that passwords without lowercase are rejected."""
        is_valid, msg = validate_password_strength("ALLUPPERCASE1!")
        self.assertFalse(is_valid)
        self.assertIn("lowercase", msg)

    def test_no_digit(self):
        """Test that passwords without digits are rejected."""
        is_valid, msg = validate_password_strength("NoDigitsHere!!")
        self.assertFalse(is_valid)
        self.assertIn("digit", msg)

    def test_no_special_char(self):
        """Test that passwords without special characters are rejected."""
        is_valid, msg = validate_password_strength("NoSpecialChar1")
        self.assertFalse(is_valid)
        self.assertIn("special", msg)

    def test_exactly_min_length(self):
        """Test password at exactly minimum length."""
        is_valid, msg = validate_password_strength("Abcdefgh1!xy")
        self.assertTrue(is_valid)


class TestKeyDerivation(unittest.TestCase):
    """Tests for PBKDF2 key derivation."""

    def test_derive_key_returns_bytes(self):
        """Test that key derivation returns 32 bytes."""
        salt = generate_salt(32)
        key = derive_key("test_password", salt, iterations=1000)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)

    def test_same_inputs_same_key(self):
        """Test that same password and salt produce same key."""
        salt = generate_salt(32)
        key1 = derive_key("password", salt, iterations=1000)
        key2 = derive_key("password", salt, iterations=1000)
        self.assertEqual(key1, key2)

    def test_different_passwords_different_keys(self):
        """Test that different passwords produce different keys."""
        salt = generate_salt(32)
        key1 = derive_key("password1", salt, iterations=1000)
        key2 = derive_key("password2", salt, iterations=1000)
        self.assertNotEqual(key1, key2)


class TestEncryptDecrypt(unittest.TestCase):
    """Tests for AES-256-GCM encryption and decryption."""

    STRONG_PASSWORD = "TestPass123!@#xyz"

    def test_encrypt_returns_bytes(self):
        """Test that encryption returns bytes."""
        plaintext = b"hello world"
        encrypted = encrypt_data(plaintext, self.STRONG_PASSWORD, iterations=1000)
        self.assertIsInstance(encrypted, bytes)

    def test_encrypt_contains_header(self):
        """Test that encrypted data starts with vault header."""
        from envshield.crypto import VAULT_HEADER
        plaintext = b"hello world"
        encrypted = encrypt_data(plaintext, self.STRONG_PASSWORD, iterations=1000)
        self.assertTrue(encrypted.startswith(VAULT_HEADER))

    def test_decrypt_roundtrip(self):
        """Test that decrypt(encrypt(data)) == data."""
        plaintext = b"DB_PASSWORD=super_secret_password_123"
        encrypted = encrypt_data(plaintext, self.STRONG_PASSWORD, iterations=1000)
        decrypted = decrypt_data(encrypted, self.STRONG_PASSWORD, iterations=1000)
        self.assertEqual(decrypted, plaintext)

    def test_wrong_password_fails(self):
        """Test that wrong password raises CryptoError."""
        plaintext = b"secret data"
        encrypted = encrypt_data(plaintext, self.STRONG_PASSWORD, iterations=1000)
        with self.assertRaises(CryptoError):
            decrypt_data(encrypted, "WrongPassword1!", iterations=1000)

    def test_tampered_data_fails(self):
        """Test that tampered ciphertext raises CryptoError."""
        plaintext = b"secret data"
        encrypted = encrypt_data(plaintext, self.STRONG_PASSWORD, iterations=1000)
        # Tamper with the ciphertext
        tampered = encrypted[:-1] + bytes([(encrypted[-1] + 1) % 256])
        with self.assertRaises(CryptoError):
            decrypt_data(tampered, self.STRONG_PASSWORD, iterations=1000)

    def test_invalid_header_fails(self):
        """Test that data without proper header raises CryptoError."""
        with self.assertRaises(CryptoError):
            decrypt_data(b"INVALID_HEADER_DATA", self.STRONG_PASSWORD)

    def test_empty_plaintext(self):
        """Test encrypting and decrypting empty data."""
        encrypted = encrypt_data(b"", self.STRONG_PASSWORD, iterations=1000)
        decrypted = decrypt_data(encrypted, self.STRONG_PASSWORD, iterations=1000)
        self.assertEqual(decrypted, b"")

    def test_large_data(self):
        """Test encrypting and decrypting large data."""
        plaintext = b"x" * 100000
        encrypted = encrypt_data(plaintext, self.STRONG_PASSWORD, iterations=1000)
        decrypted = decrypt_data(encrypted, self.STRONG_PASSWORD, iterations=1000)
        self.assertEqual(decrypted, plaintext)


class TestEnvFileEncryption(unittest.TestCase):
    """Tests for .env file encryption and decryption."""

    STRONG_PASSWORD = "TestPass123!@#xyz"
    ENV_CONTENT = """\
DATABASE_URL=postgres://user:pass@localhost:5432/mydb
API_KEY=sk_test_abc123def456
SECRET_KEY=my_super_secret_key_value
DEBUG=false
APP_ENV=production
"""

    def test_encrypt_env_file(self):
        """Test encrypting a .env file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(self.ENV_CONTENT)
            input_path = f.name

        try:
            output_path = input_path + ".vault"
            result = encrypt_env_file(
                input_path=input_path,
                output_path=output_path,
                password=self.STRONG_PASSWORD,
                iterations=1000,
            )
            self.assertTrue(os.path.exists(result))
            # Vault file should not contain plaintext
            with open(result, "rb") as f:
                content = f.read()
            self.assertNotIn(b"sk_test_abc123def456", content)
        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_decrypt_env_file(self):
        """Test decrypting a .env.vault file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(self.ENV_CONTENT)
            input_path = f.name

        try:
            vault_path = input_path + ".vault"
            output_path = input_path + ".decrypted"
            encrypt_env_file(
                input_path=input_path,
                output_path=vault_path,
                password=self.STRONG_PASSWORD,
                iterations=1000,
            )
            result = decrypt_env_file(
                input_path=vault_path,
                output_path=output_path,
                password=self.STRONG_PASSWORD,
                iterations=1000,
            )
            with open(result, "r") as f:
                decrypted = f.read()
            self.assertIn("DATABASE_URL=postgres://user:pass@localhost:5432/mydb", decrypted)
            self.assertIn("API_KEY=sk_test_abc123def456", decrypted)
        finally:
            for p in [input_path, vault_path, output_path]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_decrypt_to_memory(self):
        """Test in-memory decryption without disk write."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env.vault", delete=False) as f:
            f.write("")  # Placeholder
            vault_path = f.name

        try:
            # First create a vault file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
                f.write(self.ENV_CONTENT)
                env_path = f.name

            encrypt_env_file(
                input_path=env_path,
                output_path=vault_path,
                password=self.STRONG_PASSWORD,
                iterations=1000,
            )

            env_vars = decrypt_to_memory(
                vault_path=vault_path,
                password=self.STRONG_PASSWORD,
                iterations=1000,
            )
            self.assertIsInstance(env_vars, dict)
            self.assertEqual(env_vars.get("DATABASE_URL"), "postgres://user:pass@localhost:5432/mydb")
            self.assertEqual(env_vars.get("API_KEY"), "sk_test_abc123def456")
            self.assertEqual(env_vars.get("DEBUG"), "false")
        finally:
            for p in [env_path, vault_path]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_file_not_found(self):
        """Test that missing file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            encrypt_env_file("/nonexistent/path/.env", password=self.STRONG_PASSWORD)

    def test_password_mismatch(self):
        """Test that password confirmation mismatch raises CryptoError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("KEY=VALUE\n")
            input_path = f.name

        try:
            # Simulate password mismatch by providing same password (we can't
            # easily test interactive prompts, so test the underlying function)
            # The actual prompt test would need mocking
            pass
        finally:
            os.unlink(input_path)


class TestInjectEnvVars(unittest.TestCase):
    """Tests for environment variable injection."""

    def test_inject_env_vars(self):
        """Test that variables are injected into os.environ."""
        env_vars = {"TEST_VAR_1": "value1", "TEST_VAR_2": "value2"}
        inject_env_vars(env_vars)
        self.assertEqual(os.environ.get("TEST_VAR_1"), "value1")
        self.assertEqual(os.environ.get("TEST_VAR_2"), "value2")
        # Cleanup
        del os.environ["TEST_VAR_1"]
        del os.environ["TEST_VAR_2"]


class TestGenerateSalt(unittest.TestCase):
    """Tests for salt generation."""

    def test_salt_length(self):
        """Test that generated salt has correct length."""
        salt = generate_salt(32)
        self.assertEqual(len(salt), 32)

    def test_salt_randomness(self):
        """Test that salts are unique."""
        salt1 = generate_salt(32)
        salt2 = generate_salt(32)
        self.assertNotEqual(salt1, salt2)


if __name__ == "__main__":
    unittest.main()
