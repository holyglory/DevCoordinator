from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from devcoordinator.server_credentials import (
    MAX_SERVER_CREDENTIAL_BYTES,
    ServerCredentialError,
    load_server_credential_environment,
    secret_environment_literal,
    server_credential_id,
    staged_material_path,
    validate_server_credential_bindings,
    validate_server_credential_material,
)
from devcoordinator.store import deterministic_id


class ServerCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.material = self.root / "material"
        self.material.mkdir(mode=0o700)
        self.material.chmod(0o700)
        self.server_id = deterministic_id("server", "credential-test")
        self.name = "DATABASE_URL"
        self.credential_id = server_credential_id(self.server_id, self.name)

    def binding(self) -> dict[str, str]:
        return {"name": self.name, "credential_id": self.credential_id}

    def write_material(self, payload: bytes = b"synthetic-private-value") -> Path:
        path = staged_material_path(self.material, self.credential_id)
        path.write_bytes(payload)
        path.chmod(0o600)
        return path

    def test_detection_and_identity_are_deterministic_without_name_false_positive(self) -> None:
        self.assertEqual(
            self.credential_id,
            deterministic_id(
                "server-environment-credential", self.server_id, self.name
            ),
        )
        self.assertFalse(
            secret_environment_literal(
                "DATABASE_URL", "postgresql://127.0.0.1/example"
            )
        )
        self.assertTrue(
            secret_environment_literal(
                "DATABASE_URL", "postgresql://fixture:secret@127.0.0.1/example"
            )
        )
        self.assertTrue(secret_environment_literal("API_TOKEN", "fixture"))
        self.assertTrue(
            secret_environment_literal(
                "DATABASE_URL",
                "postgresql://127.0.0.1/example?sslmode=require&password=fixture",
            )
        )
        self.assertTrue(
            secret_environment_literal(
                "SERVICE_URL", "https://127.0.0.1/path?token=fixture"
            )
        )

    def test_bindings_require_exact_identity_order_and_unique_names(self) -> None:
        second_name = "SERVICE_TOKEN"
        second = {
            "name": second_name,
            "credential_id": server_credential_id(self.server_id, second_name),
        }
        bindings = validate_server_credential_bindings(
            self.server_id, [self.binding(), second]
        )
        self.assertEqual([item.name for item in bindings], [self.name, second_name])
        with self.assertRaisesRegex(ServerCredentialError, "does not match"):
            validate_server_credential_bindings(
                self.server_id,
                [{"name": self.name, "credential_id": server_credential_id(self.server_id, "OTHER")}],
            )
        with self.assertRaisesRegex(ServerCredentialError, "not ordered"):
            validate_server_credential_bindings(
                self.server_id, [second, self.binding()]
            )

    def test_persistent_material_is_exact_root_owned_mode_0600_utf8(self) -> None:
        self.write_material()
        self.assertEqual(
            validate_server_credential_material(
                self.material, self.credential_id, expected_uid=os.geteuid()
            ),
            "synthetic-private-value",
        )
        path = staged_material_path(self.material, self.credential_id)
        path.chmod(0o640)
        with self.assertRaisesRegex(ServerCredentialError, "unsafe"):
            validate_server_credential_material(
                self.material, self.credential_id, expected_uid=os.geteuid()
            )

    def test_persistent_material_rejects_symlink_oversize_and_non_utf8(self) -> None:
        path = self.write_material()
        path.unlink()
        target = self.root / "outside"
        target.write_bytes(b"synthetic-private-value")
        target.chmod(0o600)
        path.symlink_to(target)
        with self.assertRaises(ServerCredentialError):
            validate_server_credential_material(
                self.material, self.credential_id, expected_uid=os.geteuid()
            )
        path.unlink()
        self.write_material(b"x" * (MAX_SERVER_CREDENTIAL_BYTES + 1))
        with self.assertRaisesRegex(ServerCredentialError, "unsafe"):
            validate_server_credential_material(
                self.material, self.credential_id, expected_uid=os.geteuid()
            )
        path.write_bytes(b"\xff")
        path.chmod(0o600)
        with self.assertRaisesRegex(ServerCredentialError, "not UTF-8"):
            validate_server_credential_material(
                self.material, self.credential_id, expected_uid=os.geteuid()
            )

    def test_runtime_directory_requires_exact_files_and_returns_only_values(self) -> None:
        bindings = validate_server_credential_bindings(
            self.server_id, [self.binding()]
        )
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        runtime.chmod(0o700)
        delivered = runtime / self.credential_id
        delivered.write_bytes(b"synthetic-private-value")
        delivered.chmod(0o400)
        self.assertEqual(
            load_server_credential_environment(
                bindings, runtime, expected_uid=os.geteuid()
            ),
            {self.name: "synthetic-private-value"},
        )
        extra = runtime / "extra"
        extra.write_bytes(b"not-bound")
        extra.chmod(0o400)
        with self.assertRaisesRegex(ServerCredentialError, "exact bindings"):
            load_server_credential_environment(
                bindings, runtime, expected_uid=os.geteuid()
            )


if __name__ == "__main__":
    unittest.main()
