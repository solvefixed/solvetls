import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.support import certificate_files

ENTRYPOINT = Path(__file__).resolve().parents[1] / "main.py"


class StartupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="solvetls-startup-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.environment = os.environ.copy()
        self.environment.pop("SOLVETLS_CERT", None)
        self.environment.pop("SOLVETLS_KEY", None)
        self.environment.update(
            SOLVETLS_HOST="127.0.0.1",
            SOLVETLS_PORT="0",
            SOLVETLS_HTTP_PORT="",
            SOLVETLS_MONGODB_URL="",
            SOLVETLS_LOG_LEVEL="INFO",
        )

    def run_cli(self):
        return subprocess.run(  # noqa: S603 — trusted local CLI entry point
            [sys.executable, "-B", str(ENTRYPOINT)],
            cwd=self.directory,
            env=self.environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def assert_missing_tls_files(self, certificate, key):
        result = self.run_cli()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("Traceback", result.stderr)
        for expected in (
            "TLS certificate or private key not found",
            str(certificate),
            str(key),
            "SOLVETLS_CERT",
            "SOLVETLS_KEY",
            "README.md",
            "Certificates",
        ):
            self.assertIn(expected, result.stderr)

    def test_missing_default_files_show_setup_help(self):
        self.assert_missing_tls_files("certs/fullchain.pem", "certs/privkey.pem")

    def test_http_port_defaults_to_80_and_empty_value_disables_redirect(self):
        for value, expected in ((None, 80), ("", None), ("0", 0), ("8080", 8080)):
            with (
                self.subTest(value=value),
                patch.dict(os.environ, self.environment, clear=True),
            ):
                if value is None:
                    os.environ.pop("SOLVETLS_HTTP_PORT", None)
                else:
                    os.environ["SOLVETLS_HTTP_PORT"] = value
                configuration = runpy.run_path(
                    str(ENTRYPOINT.with_name("constants.py"))
                )
                self.assertEqual(configuration["HTTP_PORT"], expected)

    def test_invalid_ports_show_configuration_error_without_traceback(self):
        for name in ("SOLVETLS_PORT", "SOLVETLS_HTTP_PORT"):
            values = ["abc", "1.5", "-1", "65536", "9" * 5000]
            if name == "SOLVETLS_PORT":
                values.append("")
            for value in values:
                with (
                    self.subTest(name=name, value=value[:20]),
                    patch.dict(self.environment, {name: value}),
                ):
                    result = self.run_cli()
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertIn(name, result.stderr)
                    self.assertIn("integer between 0 and 65535", result.stderr)

    def test_port_defaults_and_boundaries_are_accepted(self):
        for name, setting, default in (
            ("SOLVETLS_PORT", "PORT", 443),
            ("SOLVETLS_HTTP_PORT", "HTTP_PORT", 80),
        ):
            for value, expected in (
                (None, default),
                ("0", 0),
                ("65535", 65535),
                (" 8443 ", 8443),
            ):
                with (
                    self.subTest(name=name, value=value),
                    patch.dict(os.environ, self.environment, clear=True),
                ):
                    os.environ.pop(name, None)
                    if value is not None:
                        os.environ[name] = value
                    configuration = runpy.run_path(
                        str(ENTRYPOINT.with_name("constants.py"))
                    )
                    self.assertEqual(configuration[setting], expected)

    def test_invalid_log_level_shows_configuration_error_without_traceback(self):
        for value in ("", "VERBOSE", "20"):
            with (
                self.subTest(value=value),
                patch.dict(self.environment, SOLVETLS_LOG_LEVEL=value),
            ):
                result = self.run_cli()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn("SOLVETLS_LOG_LEVEL", result.stderr)
                self.assertIn("DEBUG", result.stderr)
                self.assertIn("INFO", result.stderr)

    def test_log_level_names_remain_case_insensitive_and_accept_aliases(self):
        for value in (
            "debug",
            "INFO",
            "warning",
            "ERROR",
            "critical",
            "NOTSET",
            "warn",
            "fatal",
        ):
            with (
                self.subTest(value=value),
                patch.dict(os.environ, self.environment, clear=True),
                patch.dict(os.environ, SOLVETLS_LOG_LEVEL=value),
            ):
                configuration = runpy.run_path(
                    str(ENTRYPOINT.with_name("constants.py"))
                )
                self.assertEqual(configuration["LOG_LEVEL"], value.upper())

    def test_missing_custom_files_show_configured_paths(self):
        certificate = self.directory / "custom certificate.pem"
        key = self.directory / "custom private key.pem"
        self.environment.update(SOLVETLS_CERT=str(certificate), SOLVETLS_KEY=str(key))
        self.assert_missing_tls_files(certificate, key)

    def test_existing_certificate_with_missing_key_shows_setup_help(self):
        certificate, _ = certificate_files()
        key = self.directory / "missing private key.pem"
        self.environment.update(SOLVETLS_CERT=certificate, SOLVETLS_KEY=str(key))
        self.assert_missing_tls_files(certificate, key)

    @unittest.skipUnless(
        os.name == "posix" and os.geteuid() != 0,
        "Requires a non-root POSIX account to enforce file read permissions",
    )
    def test_unreadable_certificate_explains_read_permissions(self):
        original, key = certificate_files()
        certificate = self.directory / "unreadable.pem"
        certificate.write_bytes(Path(original).read_bytes())
        certificate.chmod(0)
        self.environment.update(SOLVETLS_CERT=str(certificate), SOLVETLS_KEY=key)
        result = self.run_cli()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("not readable", result.stderr)
        self.assertIn("read access", result.stderr)
        self.assertIn("README.md", result.stderr)
