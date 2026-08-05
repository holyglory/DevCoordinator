from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from devcoordinator import compose_contract, filesystem_acl, repository_context


class CanonicalRepositoryFixture:
    def __enter__(self) -> Path:
        home = Path.home().resolve()
        self._root = Path(
            tempfile.mkdtemp(prefix=".devcoordinator-acl-", dir=str(home))
        ).resolve(strict=True)
        self.repository = self._root / "repository"
        self.repository.mkdir()
        subprocess.run(
            ["/usr/bin/git", "init", "--quiet", str(self.repository)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return self.repository

    def __exit__(self, *_args: object) -> None:
        shutil.rmtree(self._root)


def inspection(*grants: filesystem_acl.ACLGrant) -> filesystem_acl.ACLInspection:
    return filesystem_acl.ACLInspection(
        platform="fixture",
        model="fixture-acl",
        equivalent_to_mode=not grants,
        grants=tuple(grants),
    )


def fake_linux_acl_library(
    entries: tuple[tuple[int, int | None, bool], ...],
) -> mock.Mock:
    """Return a deterministic libacl capability fixture."""

    library = mock.Mock()
    library.acl_get_fd = mock.Mock(return_value=100)
    library.acl_equiv_mode = mock.Mock(
        side_effect=lambda _acl, _mode: 0 if not entries else 1
    )
    indexed = {101 + index: entry for index, entry in enumerate(entries)}
    position = 0

    def get_entry(
        _acl: object, _selector: object, result: object
    ) -> int:
        nonlocal position
        if position == len(entries):
            return 0
        result._obj.value = 101 + position  # type: ignore[attr-defined]
        position += 1
        return 1

    def get_tag(entry: object, result: object) -> int:
        result._obj.value = indexed[int(entry.value)][0]  # type: ignore[attr-defined]
        return 0

    def get_permset(entry: object, result: object) -> int:
        result._obj.value = int(entry.value)  # type: ignore[attr-defined]
        return 0

    def get_perm(permset: object, _permission: object) -> int:
        return int(indexed[int(permset.value)][2])  # type: ignore[attr-defined]

    qualifiers: list[object] = []

    def get_qualifier(entry: object) -> object:
        identifier = indexed[int(entry.value)][1]  # type: ignore[attr-defined]
        value = filesystem_acl.ctypes.c_uint32(int(identifier))
        qualifiers.append(value)
        return filesystem_acl.ctypes.pointer(value)

    library.acl_get_entry = mock.Mock(side_effect=get_entry)
    library.acl_get_tag_type = mock.Mock(side_effect=get_tag)
    library.acl_get_permset = mock.Mock(side_effect=get_permset)
    library.acl_get_perm = mock.Mock(side_effect=get_perm)
    library.acl_get_qualifier = mock.Mock(side_effect=get_qualifier)
    library.acl_free = mock.Mock(return_value=0)
    library._qualifiers = qualifiers
    return library


class FilesystemACLPolicyTests(unittest.TestCase):
    def test_mode_equivalent_read_only_and_deny_entries_are_allowed(self) -> None:
        cases = (
            inspection(),
            inspection(
                filesystem_acl.ACLGrant(
                    principal_kind="group",
                    principal_id=42,
                    permissions=frozenset({"read"}),
                )
            ),
            inspection(
                filesystem_acl.ACLGrant(
                    principal_kind="user",
                    principal_id=42,
                    permissions=frozenset({"write", "delete", "append"}),
                    allow=False,
                )
            ),
        )
        for evidence in cases:
            with self.subTest(evidence=evidence):
                filesystem_acl.require_fd_acl_trusted(
                    7,
                    owner_uid=501,
                    field="fixture",
                    inspector=lambda _descriptor, evidence=evidence: evidence,
                )

    def test_owner_mutation_is_allowed_for_account_and_service_owned_paths(self) -> None:
        for owner_uid in (0, 501):
            with self.subTest(owner_uid=owner_uid):
                filesystem_acl.require_fd_acl_trusted(
                    7,
                    owner_uid=owner_uid,
                    field="fixture",
                    inspector=lambda _descriptor, owner_uid=owner_uid: inspection(
                        filesystem_acl.ACLGrant(
                            principal_kind="user",
                            principal_id=owner_uid,
                            permissions=frozenset(
                                {"write", "delete", "append", "change_owner"}
                            ),
                        )
                    ),
                )

    def test_every_non_owner_mutation_authority_is_rejected(self) -> None:
        permissions = (
            "write",
            "append",
            "add_file",
            "add_subdirectory",
            "delete",
            "delete_child",
            "write_attributes",
            "write_extended_attributes",
            "write_security",
            "change_owner",
        )
        principals = (("user", 502), ("group", 20), ("everyone", None), ("unknown", None))
        for permission in permissions:
            for principal_kind, principal_id in principals:
                with self.subTest(
                    permission=permission,
                    principal_kind=principal_kind,
                    principal_id=principal_id,
                ):
                    evidence = inspection(
                        filesystem_acl.ACLGrant(
                            principal_kind=principal_kind,
                            principal_id=principal_id,
                            permissions=frozenset({permission}),
                        )
                    )
                    with self.assertRaisesRegex(
                        filesystem_acl.FilesystemACLTrustError,
                        "grants non-owner",
                    ):
                        filesystem_acl.require_fd_acl_trusted(
                            7,
                            owner_uid=501,
                            field="fixture",
                            inspector=lambda _descriptor, evidence=evidence: evidence,
                        )

    def test_invalid_or_unavailable_acl_evidence_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            filesystem_acl.FilesystemACLTrustError, "invalid evidence"
        ):
            filesystem_acl.require_fd_acl_trusted(
                7,
                owner_uid=501,
                field="fixture",
                inspector=lambda _descriptor: object(),  # type: ignore[return-value]
            )
        with self.assertRaisesRegex(
            filesystem_acl.FilesystemACLTrustError, "ACL inspection failed"
        ):
            filesystem_acl.require_fd_acl_trusted(
                7,
                owner_uid=501,
                field="fixture",
                inspector=mock.Mock(side_effect=OSError("fixture failure")),
            )

    def test_linux_nfs_smb_and_rich_acl_models_fail_before_posix_fallback(self) -> None:
        for filesystem_magic in filesystem_acl._LINUX_UNSUPPORTED_ACL_FILESYSTEMS:
            with self.subTest(filesystem_magic=filesystem_magic), mock.patch.object(
                filesystem_acl,
                "_linux_filesystem_magic",
                return_value=filesystem_magic,
            ):
                with self.assertRaisesRegex(
                    filesystem_acl.FilesystemACLTrustError,
                    "NFS/SMB ACL repositories are unsupported",
                ):
                    filesystem_acl._inspect_linux_acl(7)

        with mock.patch.object(
            filesystem_acl, "_linux_filesystem_magic", return_value=0xEF53
        ), mock.patch.object(
            filesystem_acl.os,
            "listxattr",
            return_value=["system.nfs4_acl"],
            create=True,
        ):
            with self.assertRaisesRegex(
                filesystem_acl.FilesystemACLTrustError,
                "unsupported NFSv4/rich ACL model",
            ):
                filesystem_acl._inspect_linux_acl(7)

    def test_linux_posix_acl_capability_fixture_is_masked_and_fail_closed(self) -> None:
        # Linux acl_get_entry returns 1 for an entry and 0 at exhaustion.  The
        # fixture exercises that native ABI without consulting this host's ACL.
        entries = (
            (0x01, None, True),   # ACL_USER_OBJ
            (0x02, 502, True),    # ACL_USER
            (0x04, None, False),  # ACL_GROUP_OBJ
            (0x10, None, True),   # ACL_MASK
            (0x20, None, False),  # ACL_OTHER
        )
        library = fake_linux_acl_library(entries)
        with tempfile.TemporaryFile() as target, mock.patch.object(
            filesystem_acl, "_linux_filesystem_magic", return_value=0xEF53
        ), mock.patch.object(
            filesystem_acl.os, "listxattr", return_value=[], create=True
        ), mock.patch.object(
            filesystem_acl, "_load_native_library", return_value=library
        ):
            with self.assertRaisesRegex(
                filesystem_acl.FilesystemACLTrustError,
                "grants non-owner write authority",
            ):
                filesystem_acl.require_fd_acl_trusted(
                    target.fileno(),
                    owner_uid=int(os.fstat(target.fileno()).st_uid),
                    field="Linux POSIX ACL fixture",
                    inspector=filesystem_acl._inspect_linux_acl,
                )
        self.assertEqual(library.acl_get_entry.call_count, len(entries) + 1)

    def test_linux_mode_equivalent_capability_fixture_is_allowed(self) -> None:
        library = fake_linux_acl_library(())
        with tempfile.TemporaryFile() as target, mock.patch.object(
            filesystem_acl, "_linux_filesystem_magic", return_value=0xEF53
        ), mock.patch.object(
            filesystem_acl.os, "listxattr", return_value=[], create=True
        ), mock.patch.object(
            filesystem_acl, "_load_native_library", return_value=library
        ):
            evidence = filesystem_acl.require_fd_acl_trusted(
                target.fileno(),
                owner_uid=int(os.fstat(target.fileno()).st_uid),
                field="Linux mode-equivalent fixture",
                inspector=filesystem_acl._inspect_linux_acl,
            )
        self.assertTrue(evidence.equivalent_to_mode)
        library.acl_get_entry.assert_not_called()


@unittest.skipUnless(sys.platform == "darwin", "requires native macOS ACLs")
class DarwinFilesystemACLIntegrationTests(unittest.TestCase):
    def test_native_descriptor_accepts_no_acl_and_rejects_mutation_acl(self) -> None:
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as temporary:
            target = Path(temporary) / "target"
            target.mkdir()

            descriptor = os.open(target, os.O_RDONLY)
            try:
                evidence = filesystem_acl.require_fd_acl_trusted(
                    descriptor,
                    owner_uid=int(os.fstat(descriptor).st_uid),
                    field="native no-ACL control",
                )
            finally:
                os.close(descriptor)
            self.assertTrue(evidence.equivalent_to_mode)
            self.assertEqual(evidence.grants, ())

            subprocess.run(
                [
                    "/bin/chmod",
                    "+a",
                    (
                        "group:everyone allow "
                        "write,delete,add_file,add_subdirectory"
                    ),
                    str(target),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            descriptor = os.open(target, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(
                    filesystem_acl.FilesystemACLTrustError,
                    "grants non-owner append, delete, write authority",
                ):
                    filesystem_acl.require_fd_acl_trusted(
                        descriptor,
                        owner_uid=int(os.fstat(descriptor).st_uid),
                        field="native writable ACL fixture",
                    )
            finally:
                os.close(descriptor)


class RepositoryACLIntegrationTests(unittest.TestCase):
    def test_repository_proof_uses_structural_identity_without_acl_authority(self) -> None:
        with CanonicalRepositoryFixture() as repository:
            context = repository_context.resolve_repository_context(
                root_repo=str(repository), temporary_repo=None
            )

        self.assertEqual(context.root.canonical_root, str(repository))
        self.assertFalse(hasattr(repository_context, "_filesystem_acl"))

    def test_repository_proof_never_consults_legacy_acl_authority(self) -> None:
        with CanonicalRepositoryFixture() as repository, mock.patch.object(
            filesystem_acl,
            "require_fd_acl_trusted",
            side_effect=AssertionError("legacy ACL gate was consulted"),
        ) as acl_check:
            context = repository_context.resolve_repository_context(
                root_repo=str(repository), temporary_repo=None
            )
        self.assertEqual(context.root.canonical_root, str(repository))
        acl_check.assert_not_called()

    def test_trusted_local_compose_reads_do_not_consult_acl_authority(self) -> None:
        with CanonicalRepositoryFixture() as repository:
            nested = repository / "deploy"
            nested.mkdir()
            compose = nested / "compose.yaml"
            compose.write_text("services: {}\n", encoding="utf-8")
            with mock.patch.object(
                filesystem_acl,
                "require_fd_acl_trusted",
                side_effect=AssertionError(
                    "trusted-local Compose paths must not use ACL admission"
                ),
            ) as acl_check:
                root_descriptor = compose_contract.open_anchored_compose_root(
                    str(repository)
                )
                try:
                    evidence, payload = compose_contract.read_anchored_compose_file(
                        root_descriptor,
                        ("deploy", "compose.yaml"),
                        maximum_bytes=1024,
                    )
                finally:
                    os.close(root_descriptor)

        self.assertEqual(payload, b"services: {}\n")
        self.assertEqual(evidence["byte_size"], len(payload))
        acl_check.assert_not_called()

    def test_trusted_local_compose_read_still_rejects_symlink_input(self) -> None:
        with CanonicalRepositoryFixture() as repository:
            target = repository / "target.yaml"
            target.write_text("services: {}\n", encoding="utf-8")
            (repository / "compose.yaml").symlink_to(target)
            root_descriptor = compose_contract.open_anchored_compose_root(
                str(repository)
            )
            try:
                with self.assertRaises(OSError):
                    compose_contract.read_anchored_compose_file(
                        root_descriptor,
                        ("compose.yaml",),
                        maximum_bytes=1024,
                    )
            finally:
                os.close(root_descriptor)


if __name__ == "__main__":
    unittest.main()
