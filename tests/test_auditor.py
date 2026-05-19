"""Tests for the auditor module."""

import unittest

from envshield.auditor import AuditFinding, AuditResult, SecurityAuditor


class TestSecurityAuditor(unittest.TestCase):
    """Tests for the SecurityAuditor with all 15 rules."""

    def setUp(self):
        """Set up a fresh auditor for each test."""
        self.auditor = SecurityAuditor()

    def test_no_findings_on_clean_env(self):
        """Test that clean env vars produce no findings."""
        env_vars = {
            "APP_NAME": "MyApp",
            "APP_ENV": "production",
            "LOG_LEVEL": "info",
            "PORT": "8080",
        }
        result = self.auditor.audit(env_vars)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.score, 100)

    def test_rule_1_weak_password(self):
        """Test WEAK_PASSWORD rule - short password values."""
        env_vars = {
            "DB_PASSWORD": "short",
            "API_KEY": "longenoughkey12345",
        }
        result = self.auditor.audit(env_vars)
        weak_pw = [f for f in result.findings if f.rule_id == "WEAK_PASSWORD"]
        self.assertTrue(len(weak_pw) >= 1)
        self.assertEqual(weak_pw[0].key, "DB_PASSWORD")
        self.assertEqual(weak_pw[0].severity, "HIGH")

    def test_rule_2_hard_coded_secret(self):
        """Test HARD_CODED_SECRET rule - real secrets in env."""
        env_vars = {
            "SECRET_KEY": "abc123real_secret_value_xyz",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "HARD_CODED_SECRET"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_rule_2_placeholder_not_flagged(self):
        """Test that placeholder values are not flagged as hardcoded secrets."""
        env_vars = {
            "SECRET_KEY": "your-secret-here",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "HARD_CODED_SECRET"]
        self.assertEqual(len(findings), 0)

    def test_rule_3_exposed_db_uri(self):
        """Test EXPOSED_DB_URI rule - plaintext password in DB URI."""
        env_vars = {
            "DATABASE_URL": "postgres://admin:mypassword@localhost:5432/mydb",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "EXPOSED_DB_URI"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_rule_4_http_url(self):
        """Test HTTP_URL rule - non-HTTPS external URLs."""
        env_vars = {
            "API_URL": "http://api.example.com/v1",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "HTTP_URL"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_rule_4_localhost_not_flagged(self):
        """Test that localhost URLs are not flagged."""
        env_vars = {
            "API_URL": "http://localhost:3000",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "HTTP_URL"]
        self.assertEqual(len(findings), 0)

    def test_rule_5_private_key_exposed(self):
        """Test PRIVATE_KEY_EXPOSED rule - PEM private key in env."""
        env_vars = {
            "PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ\n-----END RSA PRIVATE KEY-----",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "PRIVATE_KEY_EXPOSED"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_rule_6_api_key_pattern_aws(self):
        """Test API_KEY_PATTERN rule - AWS Access Key ID."""
        env_vars = {
            "AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "API_KEY_PATTERN"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_rule_6_api_key_pattern_google(self):
        """Test API_KEY_PATTERN rule - Google API Key."""
        env_vars = {
            "API_KEY": "AIzaSyA123456789abcdefghijklmnopqrstuvw",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "API_KEY_PATTERN"]
        self.assertTrue(len(findings) >= 1)

    def test_rule_6_api_key_pattern_stripe(self):
        """Test API_KEY_PATTERN rule - Stripe Secret Key."""
        env_vars = {
            "API_KEY": "sk_test_51AbcDefGhiJklMnoPqrStuVwXyZ0123456789abc",
        }
        result = self.auditor.audit(env_vars)
        # sk_test_ keys are test keys, should not trigger live key detection
        findings = [f for f in result.findings if f.rule_id == "API_KEY_PATTERN"]
        self.assertEqual(len(findings), 0)

    def test_rule_7_jwt_secret_weak(self):
        """Test JWT_SECRET_WEAK rule - weak JWT secret."""
        env_vars = {
            "JWT_SECRET": "secret",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "JWT_SECRET_WEAK"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_rule_7_jwt_secret_strong(self):
        """Test that strong JWT secret does not trigger rule."""
        env_vars = {
            "JWT_SECRET": "my-very-long-and-secure-jwt-secret-key-32chars!",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "JWT_SECRET_WEAK"]
        self.assertEqual(len(findings), 0)

    def test_rule_8_default_credentials(self):
        """Test DEFAULT_CREDENTIALS rule - admin/admin pair."""
        env_vars = {
            "DB_USER": "admin",
            "DB_PASSWORD": "admin",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "DEFAULT_CREDENTIALS"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_rule_9_sensitive_in_url(self):
        """Test SENSITIVE_IN_URL rule - credentials in URL."""
        env_vars = {
            "SERVICE_URL": "https://user:secretpass@api.service.com/endpoint",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "SENSITIVE_IN_URL"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_rule_10_encryption_key_exposed(self):
        """Test ENCRYPTION_KEY_EXPOSED rule - plaintext encryption key."""
        env_vars = {
            "ENCRYPTION_KEY": "0123456789abcdef0123456789abcdef",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "ENCRYPTION_KEY_EXPOSED"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_rule_11_debug_mode_enabled(self):
        """Test DEBUG_MODE_ENABLED rule - debug in production."""
        env_vars = {
            "DEBUG": "true",
            "APP_ENV": "production",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "DEBUG_MODE_ENABLED"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_rule_11_debug_in_dev(self):
        """Test that debug in non-production is LOW severity."""
        env_vars = {
            "DEBUG": "true",
            "APP_ENV": "development",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "DEBUG_MODE_ENABLED"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_rule_12_cors_wildcard(self):
        """Test CORS_WILDCARD rule - wildcard CORS origin."""
        env_vars = {
            "CORS_ORIGIN": "*",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "CORS_WILDCARD"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_rule_13_old_tls_version(self):
        """Test OLD_TLS_VERSION rule - TLS 1.0."""
        env_vars = {
            "TLS_VERSION": "tlsv1.0",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "OLD_TLS_VERSION"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_rule_14_missing_rate_limit(self):
        """Test MISSING_RATE_LIMIT rule - API without rate limiting."""
        env_vars = {
            "API_URL": "https://api.example.com",
            "API_PORT": "8080",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "MISSING_RATE_LIMIT"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_rule_14_rate_limit_present(self):
        """Test that rate limit config prevents the finding."""
        env_vars = {
            "API_URL": "https://api.example.com",
            "RATE_LIMIT": "100",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "MISSING_RATE_LIMIT"]
        self.assertEqual(len(findings), 0)

    def test_rule_15_insecure_cookie(self):
        """Test INSECURE_COOKIE rule - cookies without secure flags."""
        env_vars = {
            "COOKIE_SECRET": "mycookiesecret",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "INSECURE_COOKIE"]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_rule_15_secure_cookie(self):
        """Test that secure cookie flags prevent the finding."""
        env_vars = {
            "COOKIE_SECRET": "mycookiesecret",
            "COOKIE_SECURE": "true",
            "COOKIE_HTTPONLY": "true",
        }
        result = self.auditor.audit(env_vars)
        findings = [f for f in result.findings if f.rule_id == "INSECURE_COOKIE"]
        self.assertEqual(len(findings), 0)

    def test_whitelist_skips_rules(self):
        """Test that whitelisted rules are skipped."""
        auditor = SecurityAuditor(whitelist=["WEAK_PASSWORD", "DEBUG_MODE_ENABLED"])
        env_vars = {
            "DB_PASSWORD": "short",
            "DEBUG": "true",
            "APP_ENV": "production",
        }
        result = auditor.audit(env_vars)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("WEAK_PASSWORD", rule_ids)
        self.assertNotIn("DEBUG_MODE_ENABLED", rule_ids)

    def test_audit_result_score(self):
        """Test that audit result score is calculated correctly."""
        env_vars = {
            "DB_PASSWORD": "short",  # HIGH (-15)
            "DEBUG": "true",
            "APP_ENV": "production",  # HIGH (-15)
        }
        result = self.auditor.audit(env_vars)
        # Score should be 100 - 15 - 15 = 70 (minimum)
        self.assertLessEqual(result.score, 70)
        self.assertGreaterEqual(result.score, 0)

    def test_audit_result_stats(self):
        """Test that audit result stats are computed correctly."""
        env_vars = {
            "DATABASE_URL": "postgres://admin:pass@host/db",  # CRITICAL
            "CORS_ORIGIN": "*",  # MEDIUM
        }
        result = self.auditor.audit(env_vars)
        self.assertGreater(result.stats["CRITICAL"], 0)
        self.assertGreater(result.stats["MEDIUM"], 0)

    def test_audit_result_to_dict(self):
        """Test that AuditResult serializes to dict correctly."""
        env_vars = {"DB_PASSWORD": "short"}
        result = self.auditor.audit(env_vars)
        d = result.to_dict()
        self.assertIn("score", d)
        self.assertIn("total_findings", d)
        self.assertIn("stats", d)
        self.assertIn("findings", d)
        self.assertIsInstance(d["findings"], list)


class TestAuditFinding(unittest.TestCase):
    """Tests for the AuditFinding class."""

    def test_to_dict(self):
        """Test finding serialization."""
        finding = AuditFinding(
            rule_id="TEST_RULE",
            severity="HIGH",
            key="TEST_KEY",
            value="test****",
            description="Test description",
            recommendation="Test recommendation",
        )
        d = finding.to_dict()
        self.assertEqual(d["rule_id"], "TEST_RULE")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["key"], "TEST_KEY")

    def test_repr(self):
        """Test finding repr."""
        finding = AuditFinding(
            rule_id="TEST", severity="LOW", key="K", value="v",
            description="d", recommendation="r",
        )
        self.assertIn("TEST", repr(finding))


if __name__ == "__main__":
    unittest.main()
