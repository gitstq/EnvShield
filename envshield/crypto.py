"""
AES-256-GCM encryption/decryption module for EnvShield.

Provides secure encryption and decryption of .env files using AES-256-GCM
with PBKDF2 key derivation. Supports file-based encryption and in-memory
decryption for runtime injection without writing to disk.
"""

import base64
import getpass
import hashlib
import os
import re
import struct
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

from envshield.utils import read_file_safe, read_file_binary, write_file_safe, write_file_binary


# Vault file format header
VAULT_HEADER = b"ENVS1"
# Minimum password strength requirements
MIN_PASSWORD_LENGTH = 12


class CryptoError(Exception):
    """Custom exception for cryptography-related errors."""
    pass


class PasswordStrengthError(CryptoError):
    """Exception raised when password does not meet strength requirements."""
    pass


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate that a password meets minimum strength requirements.

    Requirements:
    - At least 12 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character

    Args:
        password: The password to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, (
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long "
            f"(current: {len(password)})"
        )
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        return False, "Password must contain at least one special character"
    return True, ""


def derive_key(
    password: str,
    salt: bytes,
    iterations: int = 600000,
    key_length: int = 32,
) -> bytes:
    """Derive an encryption key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: User-provided password.
        salt: Random salt bytes.
        iterations: Number of PBKDF2 iterations (default: 600000).
        key_length: Derived key length in bytes (default: 32 for AES-256).

    Returns:
        Derived key as bytes.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=key_length,
    )


def generate_salt(length: int = 32) -> bytes:
    """Generate a cryptographically secure random salt.

    Args:
        length: Salt length in bytes.

    Returns:
        Random salt bytes.
    """
    return os.urandom(length)


def encrypt_data(plaintext: bytes, password: str, iterations: int = 600000) -> bytes:
    """Encrypt data using AES-256-GCM.

    The output format is:
        VAULT_HEADER (5 bytes) | salt (32 bytes) | nonce (12 bytes) | ciphertext+tag

    Args:
        plaintext: Data to encrypt.
        password: Encryption password.
        iterations: PBKDF2 iteration count.

    Returns:
        Encrypted data as bytes.

    Raises:
        PasswordStrengthError: If password does not meet strength requirements.
        CryptoError: If encryption fails.
    """
    is_valid, error_msg = validate_password_strength(password)
    if not is_valid:
        raise PasswordStrengthError(error_msg)

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise CryptoError(
            "The 'cryptography' package is required. "
            "Install it with: pip install cryptography"
        )

    try:
        salt = generate_salt(32)
        key = derive_key(password, salt, iterations)
        nonce = os.urandom(12)  # 96-bit nonce for GCM

        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

        # Pack: header + salt + nonce + ciphertext_with_tag
        encrypted = VAULT_HEADER + salt + nonce + ciphertext_with_tag
        return encrypted
    except Exception as e:
        if isinstance(e, (PasswordStrengthError, CryptoError)):
            raise
        raise CryptoError(f"Encryption failed: {e}")


def decrypt_data(encrypted_data: bytes, password: str, iterations: int = 600000) -> bytes:
    """Decrypt data that was encrypted with AES-256-GCM.

    Expects the format: VAULT_HEADER | salt | nonce | ciphertext+tag

    Args:
        encrypted_data: Encrypted data bytes.
        password: Decryption password.
        iterations: PBKDF2 iteration count (must match encryption).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        CryptoError: If decryption fails (wrong password, corrupted data, etc.).
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise CryptoError(
            "The 'cryptography' package is required. "
            "Install it with: pip install cryptography"
        )

    try:
        # Validate header
        if not encrypted_data.startswith(VAULT_HEADER):
            raise CryptoError("Invalid vault file format: unrecognized header")

        # Extract components
        offset = len(VAULT_HEADER)
        salt = encrypted_data[offset:offset + 32]
        offset += 32
        nonce = encrypted_data[offset:offset + 12]
        offset += 12
        ciphertext_with_tag = encrypted_data[offset:]

        # Derive key and decrypt
        key = derive_key(password, salt, iterations)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

        return plaintext
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"Decryption failed: {e}")


def encrypt_env_file(
    input_path: str,
    output_path: Optional[str] = None,
    password: Optional[str] = None,
    iterations: int = 600000,
) -> str:
    """Encrypt a .env file into .env.vault format.

    Args:
        input_path: Path to the input .env file.
        output_path: Path for the output .env.vault file. Defaults to input_path + '.vault'.
        password: Encryption password. If None, prompts the user.
        iterations: PBKDF2 iteration count.

    Returns:
        Path to the created vault file.

    Raises:
        FileNotFoundError: If the input file does not exist.
        CryptoError: If encryption fails.
    """
    input_file = Path(input_path).resolve()
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    if output_path is None:
        output_path = str(input_file) + ".vault"

    content = read_file_safe(input_file)
    if content is None:
        raise CryptoError(f"Failed to read input file: {input_path}")

    if password is None:
        password = getpass.getpass("Enter encryption password: ")
        confirm = getpass.getpass("Confirm encryption password: ")
        if password != confirm:
            raise CryptoError("Passwords do not match")

    encrypted = encrypt_data(content.encode("utf-8"), password, iterations)

    if not write_file_binary(Path(output_path), encrypted):
        raise CryptoError(f"Failed to write vault file: {output_path}")

    return output_path


def decrypt_env_file(
    input_path: str,
    output_path: Optional[str] = None,
    password: Optional[str] = None,
    iterations: int = 600000,
) -> str:
    """Decrypt a .env.vault file back to .env format.

    Args:
        input_path: Path to the .env.vault file.
        output_path: Path for the output .env file. Defaults to stripping '.vault'.
        password: Decryption password. If None, prompts the user.
        iterations: PBKDF2 iteration count.

    Returns:
        Path to the created .env file.

    Raises:
        FileNotFoundError: If the vault file does not exist.
        CryptoError: If decryption fails.
    """
    input_file = Path(input_path).resolve()
    if not input_file.exists():
        raise FileNotFoundError(f"Vault file not found: {input_path}")

    if output_path is None:
        output_path = str(input_file)
        if output_path.endswith(".vault"):
            output_path = output_path[:-6]

    content = read_file_binary(input_file)
    if content is None:
        raise CryptoError(f"Failed to read vault file: {input_path}")

    if password is None:
        password = getpass.getpass("Enter decryption password: ")

    encrypted_data = content
    decrypted = decrypt_data(encrypted_data, password, iterations)

    if not write_file_safe(Path(output_path), decrypted.decode("utf-8")):
        raise CryptoError(f"Failed to write output file: {output_path}")

    return output_path


def decrypt_to_memory(
    vault_path: str,
    password: Optional[str] = None,
    iterations: int = 600000,
) -> Dict[str, str]:
    """Decrypt a .env.vault file directly into memory without writing to disk.

    Parses the decrypted content as environment variables and returns
    them as a dictionary.

    Args:
        vault_path: Path to the .env.vault file.
        password: Decryption password. If None, prompts the user.
        iterations: PBKDF2 iteration count.

    Returns:
        Dictionary of environment variable key-value pairs.

    Raises:
        FileNotFoundError: If the vault file does not exist.
        CryptoError: If decryption fails.
    """
    vault_file = Path(vault_path).resolve()
    if not vault_file.exists():
        raise FileNotFoundError(f"Vault file not found: {vault_path}")

    content = read_file_binary(vault_file)
    if content is None:
        raise CryptoError(f"Failed to read vault file: {vault_path}")

    if password is None:
        password = getpass.getpass("Enter decryption password: ")

    encrypted_data = content
    decrypted = decrypt_data(encrypted_data, password, iterations)
    decrypted_text = decrypted.decode("utf-8")

    # Parse into key-value pairs
    env_vars: Dict[str, str] = {}
    for line in decrypted_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Remove surrounding quotes
            if len(value) >= 2:
                if (value[0] == '"' and value[-1] == '"') or \
                   (value[0] == "'" and value[-1] == "'"):
                    value = value[1:-1]
            env_vars[key] = value

    return env_vars


def inject_env_vars(env_vars: Dict[str, str]) -> None:
    """Inject environment variables into the current process.

    Args:
        env_vars: Dictionary of environment variables to inject.
    """
    for key, value in env_vars.items():
        os.environ[key] = value
