"""
Security audit engine for EnvShield.

Implements 15 security audit rules for environment variables and configuration
files. Each rule checks for a specific security vulnerability and returns
structured findings with severity levels and remediation suggestions.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from envshield.utils import calculate_security_score, severity_to_score_weight


class AuditFinding:
    """Represents a single security audit finding.

    Attributes:
        rule_id: Unique identifier for the audit rule.
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW).
        key: The environment variable key that triggered the finding.
        value: The value (or masked value) that was flagged.
        description: Human-readable description of the issue.
        recommendation: Suggested fix or remediation step.
    """

    def __init__(
        self,
        rule_id: str,
        severity: str,
        key: str,
        value: str,
        description: str,
        recommendation: str,
    ):
        self.rule_id = rule_id
        self.severity = severity
        self.key = key
        self.value = value
        self.description = description
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, str]:
        """Convert finding to a dictionary.

        Returns:
            Dictionary representation of the finding.
        """
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "key": self.key,
            "value": self.value,
            "description": self.description,
            "recommendation": self.recommendation,
        }

    def __repr__(self) -> str:
        return (
            f"AuditFinding(rule_id={self.rule_id!r}, severity={self.severity!r}, "
            f"key={self.key!r})"
        )


class AuditResult:
    """Aggregated result of a security audit.

    Attributes:
        findings: List of AuditFinding objects.
        score: Security score from 0 to 100.
        stats: Dictionary of finding counts by severity.
    """

    def __init__(self, findings: List[AuditFinding]):
        self.findings = findings
        self.score = calculate_security_score(
            [{"severity": f.severity} for f in findings]
        )
        self.stats = self._compute_stats()

    def _compute_stats(self) -> Dict[str, int]:
        """Count findings by severity level.

        Returns:
            Dictionary mapping severity to count.
        """
        stats: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in self.findings:
            sev = finding.severity.upper()
            if sev in stats:
                stats[sev] += 1
        return stats

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit result to a dictionary.

        Returns:
            Dictionary with score, stats, and findings.
        """
        return {
            "score": self.score,
            "total_findings": len(self.findings),
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }


class SecurityAuditor:
    """Security audit engine that evaluates environment variables against 15 rules.

    Each rule is implemented as a method that checks for a specific type of
    security vulnerability. Rules can be selectively disabled via a whitelist.
    """

    def __init__(self, whitelist: Optional[List[str]] = None):
        """Initialize the auditor.

        Args:
            whitelist: List of rule IDs to skip during audit.
        """
        self.whitelist = set(w.upper() for w in (whitelist or []))
        self._rules = [
            ("WEAK_PASSWORD", self._check_weak_password),
            ("HARD_CODED_SECRET", self._check_hard_coded_secret),
            ("EXPOSED_DB_URI", self._check_exposed_db_uri),
            ("HTTP_URL", self._check_http_url),
            ("PRIVATE_KEY_EXPOSED", self._check_private_key_exposed),
            ("API_KEY_PATTERN", self._check_api_key_pattern),
            ("JWT_SECRET_WEAK", self._check_jwt_secret_weak),
            ("DEFAULT_CREDENTIALS", self._check_default_credentials),
            ("SENSITIVE_IN_URL", self._check_sensitive_in_url),
            ("ENCRYPTION_KEY_EXPOSED", self._check_encryption_key_exposed),
            ("DEBUG_MODE_ENABLED", self._check_debug_mode_enabled),
            ("CORS_WILDCARD", self._check_cors_wildcard),
            ("OLD_TLS_VERSION", self._check_old_tls_version),
            ("MISSING_RATE_LIMIT", self._check_missing_rate_limit),
            ("INSECURE_COOKIE", self._check_insecure_cookie),
        ]

    def audit(self, env_vars: Dict[str, str]) -> AuditResult:
        """Run all enabled audit rules against the provided environment variables.

        Args:
            env_vars: Dictionary of environment variable key-value pairs.

        Returns:
            AuditResult with all findings, score, and statistics.
        """
        findings: List[AuditFinding] = []
        for rule_id, rule_func in self._rules:
            if rule_id in self.whitelist:
                continue
            rule_findings = rule_func(env_vars)
            findings.extend(rule_findings)
        return AuditResult(findings)

    # ---- Rule implementations ----

    def _check_weak_password(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 1: Check for password/secret values shorter than 8 characters.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for weak passwords.
        """
        findings = []
        password_keys = [
            "PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
            "PRIVATE_KEY", "ACCESS_KEY", "AUTH_TOKEN",
        ]
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(pk in key_upper for pk in password_keys):
                if value and len(value) < 8:
                    findings.append(AuditFinding(
                        rule_id="WEAK_PASSWORD",
                        severity="HIGH",
                        key=key,
                        value=value[:4] + "****",
                        description=f"Password/secret value for '{key}' is too short ({len(value)} chars)",
                        recommendation=(
                            f"Increase the length of '{key}' to at least 8 characters. "
                            "Use a strong, randomly generated value."
                        ),
                    ))
        return findings

    def _check_hard_coded_secret(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 2: Detect hardcoded secret values that look like real secrets in env.

        Checks for values that appear to be actual hardcoded secrets rather than
        placeholders.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for hardcoded secrets.
        """
        findings = []
        secret_keys = [
            "SECRET_KEY", "SECRET", "PRIVATE_KEY", "API_SECRET",
            "CLIENT_SECRET", "SIGNING_KEY",
        ]
        placeholder_patterns = [
            r"^your[_-]?secret[_-]?here$",
            r"^change[_-]?me$",
            r"^placeholder$",
            r"^xxx+$",
            r"^$",
            r"^\$\{.+\}$",
            r"^<.*>$",
        ]
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(sk in key_upper for sk in secret_keys):
                if value and not any(
                    re.match(p, value, re.IGNORECASE) for p in placeholder_patterns
                ):
                    # Value looks like a real secret stored in env
                    if len(value) > 3:
                        findings.append(AuditFinding(
                            rule_id="HARD_CODED_SECRET",
                            severity="CRITICAL",
                            key=key,
                            value=value[:4] + "****",
                            description=f"Potential hardcoded secret detected in '{key}'",
                            recommendation=(
                                f"Ensure '{key}' is loaded from a secure vault or "
                                "encrypted storage, not committed to source control."
                            ),
                        ))
        return findings

    def _check_exposed_db_uri(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 3: Check for database connection URIs containing plaintext passwords.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for exposed DB URIs.
        """
        findings = []
        db_keys = [
            "DATABASE_URL", "DB_URL", "DB_URI", "DATABASE_URI",
            "MONGO_URI", "MONGODB_URI", "REDIS_URL", "POSTGRES_URL",
            "MYSQL_URL", "SQLITE_URL",
        ]
        db_uri_pattern = re.compile(
            r"(?:postgres|mysql|mongodb|redis|sqlite|oracle)://[^:]+:([^@]+)@",
            re.IGNORECASE,
        )
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(dk in key_upper for dk in db_keys):
                if value and db_uri_pattern.search(value):
                    findings.append(AuditFinding(
                        rule_id="EXPOSED_DB_URI",
                        severity="CRITICAL",
                        key=key,
                        value=value[:20] + "****",
                        description=f"Database URI in '{key}' contains plaintext password",
                        recommendation=(
                            f"Use encrypted credentials for '{key}'. "
                            "Consider using a connection pool with SSL/TLS "
                            "and store credentials in a vault."
                        ),
                    ))
        return findings

    def _check_http_url(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 4: Check for HTTP (non-HTTPS) URLs in external service configurations.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for HTTP URLs.
        """
        findings = []
        url_keys = [
            "URL", "URI", "HOST", "ENDPOINT", "SERVER", "API_URL",
            "BASE_URL", "SITE_URL", "CALLBACK_URL", "WEBHOOK_URL",
        ]
        # Match http:// but not http://localhost or http://127.0.0.1
        http_pattern = re.compile(r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)", re.IGNORECASE)
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(uk in key_upper for uk in url_keys):
                if value and http_pattern.search(value):
                    if value.strip().lower().startswith("http://"):
                        findings.append(AuditFinding(
                            rule_id="HTTP_URL",
                            severity="MEDIUM",
                            key=key,
                            value=value[:30] + "****",
                            description=f"'{key}' uses insecure HTTP instead of HTTPS",
                            recommendation=(
                                f"Change '{key}' to use HTTPS. "
                                "Unencrypted HTTP traffic can be intercepted."
                            ),
                        ))
        return findings

    def _check_private_key_exposed(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 5: Detect private key content stored directly in environment variables.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for exposed private keys.
        """
        findings = []
        pk_keys = [
            "PRIVATE_KEY", "RSA_PRIVATE_KEY", "EC_PRIVATE_KEY",
            "SSH_PRIVATE_KEY", "PGP_PRIVATE_KEY", "SSL_KEY",
        ]
        pk_patterns = [
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
            r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
            r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
            r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
        ]
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(pk in key_upper for pk in pk_keys):
                if value and any(re.search(p, value) for p in pk_patterns):
                    findings.append(AuditFinding(
                        rule_id="PRIVATE_KEY_EXPOSED",
                        severity="CRITICAL",
                        key=key,
                        value="****(private key content)",
                        description=f"Private key content found in '{key}'",
                        recommendation=(
                            f"Store the private key in a file with restricted permissions "
                            f"or use a dedicated secrets manager instead of '{key}'."
                        ),
                    ))
        return findings

    def _check_api_key_pattern(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 6: Detect common API key formats (Google, AWS, Azure, etc.).

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for detected API key patterns.
        """
        findings = []
        api_key_patterns = [
            # AWS Access Key ID
            (r"^AKIA[0-9A-Z]{16}$", "AWS Access Key ID"),
            # AWS Secret Access Key (40 chars, base64-ish)
            (r"^[A-Za-z0-9/+=]{40}$", "AWS Secret Access Key (possible)"),
            # Google API Key
            (r"^AIza[0-9A-Za-z\-_]{35}$", "Google API Key"),
            # Google OAuth Access Token
            (r"^ya29\.[0-9A-Za-z\-_]+", "Google OAuth Token"),
            # Azure (starts with specific prefixes)
            (r"^[a-f0-9]{32}$", "Possible Azure Key (32 hex chars)"),
            # Slack Token
            (r"^xox[baprs]-[0-9]{10,}-[0-9A-Za-z]{24,}", "Slack Token"),
            # Stripe Secret Key
            (r"^sk_live_[0-9a-zA-Z]{24,}$", "Stripe Secret Key"),
            # Stripe Publishable Key
            (r"^pk_live_[0-9a-zA-Z]{24,}$", "Stripe Publishable Key"),
            # GitHub Token
            (r"^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}$", "GitHub Token"),
            # SendGrid API Key
            (r"^SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}$", "SendGrid API Key"),
            # Twilio API Key
            (r"^SK[0-9a-fA-F]{32}$", "Twilio API Key"),
            # Mailgun API Key
            (r"^key-[0-9a-zA-Z]{32}$", "Mailgun API Key"),
        ]
        api_key_names = [
            "API_KEY", "APIKEY", "ACCESS_KEY", "SECRET_KEY", "AUTH_KEY",
            "TOKEN", "API_TOKEN", "AUTH_TOKEN", "CLIENT_KEY",
        ]
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(ak in key_upper for ak in api_key_names):
                if value:
                    for pattern, service_name in api_key_patterns:
                        if re.match(pattern, value.strip()):
                            findings.append(AuditFinding(
                                rule_id="API_KEY_PATTERN",
                                severity="CRITICAL",
                                key=key,
                                value=value[:8] + "****",
                                description=f"Detected {service_name} pattern in '{key}'",
                                recommendation=(
                                    f"Rotate the {service_name} in '{key}' immediately. "
                                    "Use a secrets manager for storage."
                                ),
                            ))
                            break  # Only report first match per key
        return findings

    def _check_jwt_secret_weak(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 7: Check for weak JWT signing secrets.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for weak JWT secrets.
        """
        findings = []
        jwt_keys = [
            "JWT_SECRET", "JWT_KEY", "JWT_SIGNING_KEY",
            "TOKEN_SECRET", "JWT_PRIVATE_KEY",
        ]
        weak_jwt_values = [
            "secret", "password", "123456", "admin", "test",
            "changeme", "default", "jwt_secret", "supersecret",
        ]
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(jk in key_upper for jk in jwt_keys):
                if value:
                    if value.lower() in weak_jwt_values or len(value) < 16:
                        findings.append(AuditFinding(
                            rule_id="JWT_SECRET_WEAK",
                            severity="HIGH",
                            key=key,
                            value=value[:4] + "****",
                            description=f"JWT secret in '{key}' is weak ({len(value)} chars)",
                            recommendation=(
                                f"Use a strong, randomly generated JWT secret for '{key}' "
                                "(minimum 32 characters recommended)."
                            ),
                        ))
        return findings

    def _check_default_credentials(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 8: Detect default/common credentials.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for default credentials.
        """
        findings = []
        default_creds = {
            "admin": ["admin", "password", "123456", "admin123"],
            "root": ["root", "toor", "password", "123456"],
            "user": ["user", "password", "123456"],
            "test": ["test", "test123", "password"],
            "guest": ["guest", "guest"],
        }
        cred_keys = [
            "USERNAME", "USER", "LOGIN", "DB_USER", "DATABASE_USER",
            "ADMIN_USER", "ROOT_USER",
        ]
        pass_keys = [
            "PASSWORD", "PASSWD", "DB_PASSWORD", "DATABASE_PASSWORD",
            "ADMIN_PASSWORD", "ROOT_PASSWORD", "SECRET",
        ]
        # Check username/password pairs
        username = None
        password = None
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(ck in key_upper for ck in cred_keys):
                username = value.lower().strip() if value else None
            if any(pk in key_upper for pk in pass_keys):
                password = value.lower().strip() if value else None

        if username and password:
            for user, passes in default_creds.items():
                if username == user and password in passes:
                    findings.append(AuditFinding(
                        rule_id="DEFAULT_CREDENTIALS",
                        severity="CRITICAL",
                        key="credentials",
                        value=f"{username} / {password[:3]}****",
                        description=f"Default credentials detected: {username}/***",
                        recommendation=(
                            "Change default credentials immediately. "
                            "Use strong, unique credentials for each environment."
                        ),
                    ))
                    break

        # Also check individual password values for known defaults
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(pk in key_upper for pk in pass_keys):
                if value and value.lower() in ["admin", "password", "123456", "root", "test"]:
                    findings.append(AuditFinding(
                        rule_id="DEFAULT_CREDENTIALS",
                        severity="HIGH",
                        key=key,
                        value=value[:4] + "****",
                        description=f"Default password detected in '{key}'",
                        recommendation=f"Change the value of '{key}' to a strong password.",
                    ))
        return findings

    def _check_sensitive_in_url(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 9: Check for URLs containing sensitive information (passwords, tokens).

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for sensitive data in URLs.
        """
        findings = []
        sensitive_url_pattern = re.compile(
            r"https?://[^:]+:([^@]{3,})@",
            re.IGNORECASE,
        )
        for key, value in env_vars.items():
            if value and sensitive_url_pattern.search(value):
                findings.append(AuditFinding(
                    rule_id="SENSITIVE_IN_URL",
                    severity="HIGH",
                    key=key,
                    value=value[:30] + "****",
                    description=f"URL in '{key}' contains embedded credentials",
                    recommendation=(
                        f"Remove credentials from the URL in '{key}'. "
                        "Use separate environment variables for authentication."
                    ),
                ))
        return findings

    def _check_encryption_key_exposed(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 10: Check for encryption keys stored in plaintext.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for exposed encryption keys.
        """
        findings = []
        enc_keys = [
            "ENCRYPTION_KEY", "AES_KEY", "FERNET_KEY", "GPG_KEY",
            "CRYPT_KEY", "CIPHER_KEY", "HMAC_KEY", "SIGNING_KEY",
        ]
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(ek in key_upper for ek in enc_keys):
                if value and len(value) > 3:
                    # Check if it looks like a real key (not placeholder)
                    placeholder = value.lower() in [
                        "changeme", "secret", "key", "your-key-here",
                        "placeholder", "",
                    ]
                    if not placeholder:
                        findings.append(AuditFinding(
                            rule_id="ENCRYPTION_KEY_EXPOSED",
                            severity="CRITICAL",
                            key=key,
                            value=value[:4] + "****",
                            description=f"Encryption key stored in plaintext in '{key}'",
                            recommendation=(
                                f"Move '{key}' to a dedicated secrets manager or "
                                "use EnvShield's encrypted vault for storage."
                            ),
                        ))
        return findings

    def _check_debug_mode_enabled(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 11: Check if debug mode is enabled in production-like configurations.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for debug mode issues.
        """
        findings = []
        debug_keys = [
            "DEBUG", "DEBUG_MODE", "FLASK_DEBUG", "DJANGO_DEBUG",
            "APP_DEBUG", "LOG_LEVEL",
        ]
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(dk in key_upper for dk in debug_keys):
                if value and value.lower() in ("true", "1", "yes", "on", "debug"):
                    # Check if this might be a production environment
                    env_value = env_vars.get("ENV", env_vars.get("NODE_ENV", env_vars.get("APP_ENV", "")))
                    if env_value and env_value.lower() in ("production", "prod"):
                        findings.append(AuditFinding(
                            rule_id="DEBUG_MODE_ENABLED",
                            severity="HIGH",
                            key=key,
                            value=value,
                            description=f"Debug mode is enabled in production environment ('{key}')",
                            recommendation=(
                                f"Disable debug mode for '{key}' in production. "
                                "Debug mode can expose sensitive information."
                            ),
                        ))
                    else:
                        findings.append(AuditFinding(
                            rule_id="DEBUG_MODE_ENABLED",
                            severity="LOW",
                            key=key,
                            value=value,
                            description=f"Debug mode is enabled ('{key}={value}')",
                            recommendation=(
                                f"Consider disabling '{key}' unless actively debugging. "
                                "Ensure it is not deployed to production."
                            ),
                        ))
        return findings

    def _check_cors_wildcard(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 12: Check for CORS configured with wildcard origin.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for CORS wildcard configurations.
        """
        findings = []
        cors_keys = [
            "CORS_ORIGIN", "CORS_ORIGINS", "ALLOWED_ORIGINS",
            "ACCESS_CONTROL_ALLOW_ORIGIN", "CORS_ALLOW_ALL",
        ]
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(ck in key_upper for ck in cors_keys):
                if value and "*" in value:
                    findings.append(AuditFinding(
                        rule_id="CORS_WILDCARD",
                        severity="MEDIUM",
                        key=key,
                        value=value,
                        description=f"CORS origin in '{key}' is set to wildcard '*'",
                        recommendation=(
                            f"Restrict '{key}' to specific allowed domains. "
                            "Wildcard CORS allows any origin to access your API."
                        ),
                    ))
        return findings

    def _check_old_tls_version(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 13: Detect old or insecure TLS version configurations.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for old TLS configurations.
        """
        findings = []
        tls_keys = [
            "TLS_VERSION", "SSL_VERSION", "TLS_MIN_VERSION",
            "SSL_PROTOCOL", "SECURE_PROTOCOL",
        ]
        insecure_versions = [
            "tlsv1", "tlsv1.0", "tlsv1.1", "sslv2", "sslv3",
            "tls1", "tls1_1", "ssl2", "ssl3",
        ]
        for key, value in env_vars.items():
            key_upper = key.upper()
            if any(tk in key_upper for tk in tls_keys):
                if value and value.lower().replace(".", "").replace("v", "") in [
                    v.replace(".", "").replace("v", "") for v in insecure_versions
                ]:
                    findings.append(AuditFinding(
                        rule_id="OLD_TLS_VERSION",
                        severity="HIGH",
                        key=key,
                        value=value,
                        description=f"Insecure TLS version configured in '{key}': {value}",
                        recommendation=(
                            f"Update '{key}' to TLS 1.2 or higher. "
                            "Older TLS versions have known security vulnerabilities."
                        ),
                    ))
        return findings

    def _check_missing_rate_limit(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 14: Check for missing rate limiting configuration.

        Looks for API-related configurations that lack rate limiting settings.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for missing rate limits.
        """
        findings = []
        api_indicators = [
            "API_URL", "API_HOST", "API_PORT", "SERVER_PORT",
            "WEB_PORT", "APP_PORT", "LISTEN_PORT",
        ]
        rate_limit_keys = [
            "RATE_LIMIT", "RATE_LIMIT_MAX", "THROTTLE",
            "REQUEST_LIMIT", "API_RATE_LIMIT", "RATE_LIMIT_WINDOW",
        ]
        has_api = any(
            any(ai in k.upper() for ai in api_indicators)
            for k in env_vars.keys()
        )
        has_rate_limit = any(
            any(rl in k.upper() for rl in rate_limit_keys)
            for k in env_vars.keys()
        )
        if has_api and not has_rate_limit:
            findings.append(AuditFinding(
                rule_id="MISSING_RATE_LIMIT",
                severity="MEDIUM",
                key="N/A",
                value="N/A",
                description="API server detected but no rate limiting configuration found",
                recommendation=(
                    "Configure rate limiting to protect against brute force attacks "
                    "and abuse. Set RATE_LIMIT or similar configuration."
                ),
            ))
        return findings

    def _check_insecure_cookie(self, env_vars: Dict[str, str]) -> List[AuditFinding]:
        """Rule 15: Check for cookies missing Secure/HttpOnly flags.

        Args:
            env_vars: Environment variables to check.

        Returns:
            List of findings for insecure cookie configurations.
        """
        findings = []
        cookie_keys = [
            "COOKIE_SECRET", "SESSION_SECRET", "COOKIE_KEY",
            "SESSION_KEY", "COOKIE_SETTINGS",
        ]
        secure_flags = [
            "COOKIE_SECURE", "SESSION_SECURE", "COOKIE_HTTPONLY",
            "SESSION_HTTPONLY", "SECURE_COOKIES", "HTTPONLY_COOKIES",
        ]
        has_cookies = any(
            any(ck in k.upper() for ck in cookie_keys)
            for k in env_vars.keys()
        )
        has_secure = any(
            env_vars.get(k, "").lower() in ("true", "1", "yes")
            for k in env_vars.keys()
            if any(sf in k.upper() for sf in secure_flags)
        )
        if has_cookies and not has_secure:
            findings.append(AuditFinding(
                rule_id="INSECURE_COOKIE",
                severity="MEDIUM",
                key="cookies",
                value="N/A",
                description="Cookie configuration found but Secure/HttpOnly flags may not be set",
                recommendation=(
                    "Enable Secure and HttpOnly flags for all cookies. "
                    "Set COOKIE_SECURE=true and COOKIE_HTTPONLY=true."
                ),
            ))
        return findings
