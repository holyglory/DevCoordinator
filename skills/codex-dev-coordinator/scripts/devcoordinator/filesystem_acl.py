"""Descriptor-bound ACL trust checks for repository filesystem evidence.

Repository identity is security evidence only while no principal other than the
inode owner can replace or mutate a proved path component.  Mode bits are
checked by callers; this module closes the separate extended-ACL boundary.
"""

from __future__ import annotations

import ctypes
import ctypes.util
from dataclasses import dataclass
import errno
import functools
import os
import sys
from typing import Callable, FrozenSet


class FilesystemACLTrustError(RuntimeError):
    """ACL evidence is unsafe, unavailable, or not understood fail-closed."""


@dataclass(frozen=True)
class ACLGrant:
    """One normalized discretionary ACL entry."""

    principal_kind: str
    principal_id: int | None
    permissions: FrozenSet[str]
    allow: bool = True


@dataclass(frozen=True)
class ACLInspection:
    """Descriptor-bound ACL evidence returned by one native backend."""

    platform: str
    model: str
    equivalent_to_mode: bool
    grants: tuple[ACLGrant, ...] = ()


_MUTATING_PERMISSIONS = frozenset(
    {
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
    }
)

# Linux has no stable descriptor API for NFSv4/rich ACL evaluation comparable
# to libacl's POSIX interface.  Reject known non-POSIX models instead of
# silently treating Unix mode bits as complete authority evidence.
_LINUX_UNSUPPORTED_ACL_XATTRS = frozenset(
    {
        "system.nfs4_acl",
        "system.richacl",
        "security.nfs4_acl",
        "trusted.nfs4_acl",
    }
)
_LINUX_UNSUPPORTED_ACL_FILESYSTEMS = frozenset(
    {
        0x00006969,  # NFS_SUPER_MAGIC
        0xFF534D42,  # CIFS_MAGIC_NUMBER
        0xFE534D42,  # SMB2_SUPER_MAGIC
    }
)


def _evaluate_acl_inspection(
    inspection: ACLInspection, *, owner_uid: int, field: str
) -> None:
    if type(owner_uid) is not int or owner_uid < 0:
        raise FilesystemACLTrustError(f"{field} has an invalid owner identity")
    for grant in inspection.grants:
        mutation = sorted(grant.permissions & _MUTATING_PERMISSIONS)
        if not grant.allow or not mutation:
            continue
        owner_grant = (
            grant.principal_kind in {"owner", "user"}
            and grant.principal_id == owner_uid
        )
        if owner_grant:
            continue
        principal = grant.principal_kind
        if grant.principal_id is not None:
            principal += f":{grant.principal_id}"
        raise FilesystemACLTrustError(
            f"{field} grants non-owner {', '.join(mutation)} authority "
            f"through a {inspection.model} ACL entry for {principal}"
        )


def require_fd_acl_trusted(
    descriptor: int,
    *,
    owner_uid: int,
    field: str,
    inspector: Callable[[int], ACLInspection] | None = None,
) -> ACLInspection:
    """Require complete native ACL evidence for one already-open descriptor."""

    if type(descriptor) is not int or descriptor < 0:
        raise FilesystemACLTrustError(f"{field} has an invalid descriptor")
    inspect = inspector or inspect_fd_acl
    try:
        inspection = inspect(descriptor)
    except FilesystemACLTrustError:
        raise
    except BaseException as error:
        raise FilesystemACLTrustError(
            f"{field} ACL inspection failed: {type(error).__name__}: {error}"
        ) from error
    if not isinstance(inspection, ACLInspection):
        raise FilesystemACLTrustError(
            f"{field} ACL inspector returned invalid evidence"
        )
    _evaluate_acl_inspection(inspection, owner_uid=owner_uid, field=field)
    return inspection


def inspect_fd_acl(descriptor: int) -> ACLInspection:
    if sys.platform == "darwin":
        return _inspect_darwin_acl(descriptor)
    if sys.platform.startswith("linux"):
        return _inspect_linux_acl(descriptor)
    raise FilesystemACLTrustError(
        f"repository ACL inspection is unsupported on {sys.platform}"
    )


@functools.lru_cache(maxsize=4)
def _load_native_library(name: str | None, *, fallback: str) -> ctypes.CDLL:
    candidate = ctypes.util.find_library(name) if name is not None else None
    try:
        return ctypes.CDLL(candidate or fallback, use_errno=True)
    except OSError as error:
        raise FilesystemACLTrustError(
            f"native ACL library is unavailable: {candidate or fallback}"
        ) from error


def _inspect_darwin_acl(descriptor: int) -> ACLInspection:
    library = _load_native_library(None, fallback="/usr/lib/libSystem.B.dylib")
    library.acl_get_fd_np.argtypes = (ctypes.c_int, ctypes.c_int)
    library.acl_get_fd_np.restype = ctypes.c_void_p
    library.acl_get_entry.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    )
    library.acl_get_entry.restype = ctypes.c_int
    library.acl_get_tag_type.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
    )
    library.acl_get_tag_type.restype = ctypes.c_int
    library.acl_get_permset_mask_np.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint64),
    )
    library.acl_get_permset_mask_np.restype = ctypes.c_int
    library.acl_get_qualifier.argtypes = (ctypes.c_void_p,)
    library.acl_get_qualifier.restype = ctypes.c_void_p
    library.acl_free.argtypes = (ctypes.c_void_p,)
    library.acl_free.restype = ctypes.c_int
    library.mbr_uuid_to_id.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_int),
    )
    library.mbr_uuid_to_id.restype = ctypes.c_int

    ctypes.set_errno(0)
    acl = library.acl_get_fd_np(descriptor, 0x00000100)  # ACL_TYPE_EXTENDED
    if not acl:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return ACLInspection(
                platform="darwin", model="darwin-extended", equivalent_to_mode=True
            )
        raise FilesystemACLTrustError(
            "macOS extended ACL inspection failed: "
            + os.strerror(error_number or errno.EIO)
        )

    permissions = {
        1 << 2: "write",
        1 << 4: "delete",
        1 << 5: "append",
        1 << 6: "delete_child",
        1 << 8: "write_attributes",
        1 << 10: "write_extended_attributes",
        1 << 12: "write_security",
        1 << 13: "change_owner",
    }
    grants: list[ACLGrant] = []
    try:
        entry = ctypes.c_void_p()
        entry_selector = 0  # ACL_FIRST_ENTRY
        while True:
            ctypes.set_errno(0)
            outcome = library.acl_get_entry(acl, entry_selector, ctypes.byref(entry))
            if outcome == -1:
                error_number = ctypes.get_errno()
                if error_number == errno.EINVAL:
                    break
                raise FilesystemACLTrustError(
                    "macOS extended ACL entry enumeration failed: "
                    + os.strerror(error_number or errno.EIO)
                )
            if outcome != 0 or not entry.value:
                raise FilesystemACLTrustError(
                    "macOS extended ACL entry enumeration returned invalid evidence"
                )
            entry_selector = -1  # ACL_NEXT_ENTRY
            tag = ctypes.c_int()
            mask = ctypes.c_uint64()
            if library.acl_get_tag_type(entry, ctypes.byref(tag)) != 0:
                raise FilesystemACLTrustError(
                    "macOS extended ACL tag inspection failed"
                )
            if library.acl_get_permset_mask_np(entry, ctypes.byref(mask)) != 0:
                raise FilesystemACLTrustError(
                    "macOS extended ACL permission inspection failed"
                )
            if tag.value not in {1, 2}:
                raise FilesystemACLTrustError(
                    "macOS extended ACL contains an unknown entry type"
                )
            qualifier = library.acl_get_qualifier(entry)
            principal_kind = "unknown"
            principal_id: int | None = None
            if qualifier:
                try:
                    resolved_id = ctypes.c_uint32()
                    resolved_kind = ctypes.c_int()
                    if (
                        library.mbr_uuid_to_id(
                            qualifier,
                            ctypes.byref(resolved_id),
                            ctypes.byref(resolved_kind),
                        )
                        == 0
                    ):
                        principal_kind = (
                            "user" if resolved_kind.value == 0 else "group"
                            if resolved_kind.value == 1
                            else "unknown"
                        )
                        principal_id = int(resolved_id.value)
                finally:
                    if library.acl_free(qualifier) != 0:
                        raise FilesystemACLTrustError(
                            "macOS extended ACL qualifier release failed"
                        )
            grants.append(
                ACLGrant(
                    principal_kind=principal_kind,
                    principal_id=principal_id,
                    permissions=frozenset(
                        name for bit, name in permissions.items() if mask.value & bit
                    ),
                    allow=tag.value == 1,  # ACL_EXTENDED_ALLOW
                )
            )
    finally:
        if library.acl_free(acl) != 0:
            raise FilesystemACLTrustError("macOS extended ACL release failed")
    return ACLInspection(
        platform="darwin",
        model="darwin-extended",
        equivalent_to_mode=not grants,
        grants=tuple(grants),
    )


def _linux_filesystem_magic(descriptor: int) -> int:
    libc = _load_native_library(None, fallback="libc.so.6")
    libc.fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
    libc.fstatfs.restype = ctypes.c_int
    storage = ctypes.create_string_buffer(512)
    if libc.fstatfs(descriptor, ctypes.byref(storage)) != 0:
        error_number = ctypes.get_errno()
        raise FilesystemACLTrustError(
            "Linux filesystem identity inspection failed: "
            + os.strerror(error_number or errno.EIO)
        )
    return int(ctypes.cast(storage, ctypes.POINTER(ctypes.c_long))[0]) & 0xFFFFFFFF


def _inspect_linux_acl(descriptor: int) -> ACLInspection:
    filesystem_magic = _linux_filesystem_magic(descriptor)
    if filesystem_magic in _LINUX_UNSUPPORTED_ACL_FILESYSTEMS:
        raise FilesystemACLTrustError(
            "Linux NFS/SMB ACL repositories are unsupported because no stable "
            "descriptor API exposes their complete NFSv4 authority"
        )
    try:
        xattrs = frozenset(os.listxattr(descriptor))
    except OSError as error:
        raise FilesystemACLTrustError(
            f"Linux ACL attribute discovery failed: {error}"
        ) from error
    unsupported = sorted(xattrs & _LINUX_UNSUPPORTED_ACL_XATTRS)
    if unsupported:
        raise FilesystemACLTrustError(
            "Linux repository uses an unsupported NFSv4/rich ACL model: "
            + ", ".join(unsupported)
        )

    library = _load_native_library("acl", fallback="libacl.so.1")
    library.acl_get_fd.argtypes = (ctypes.c_int,)
    library.acl_get_fd.restype = ctypes.c_void_p
    library.acl_equiv_mode.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint),
    )
    library.acl_equiv_mode.restype = ctypes.c_int
    library.acl_get_entry.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    )
    library.acl_get_entry.restype = ctypes.c_int
    library.acl_get_tag_type.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
    )
    library.acl_get_tag_type.restype = ctypes.c_int
    library.acl_get_permset.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    library.acl_get_permset.restype = ctypes.c_int
    library.acl_get_perm.argtypes = (ctypes.c_void_p, ctypes.c_int)
    library.acl_get_perm.restype = ctypes.c_int
    library.acl_get_qualifier.argtypes = (ctypes.c_void_p,)
    library.acl_get_qualifier.restype = ctypes.c_void_p
    library.acl_free.argtypes = (ctypes.c_void_p,)
    library.acl_free.restype = ctypes.c_int

    ctypes.set_errno(0)
    acl = library.acl_get_fd(descriptor)
    if not acl:
        error_number = ctypes.get_errno()
        raise FilesystemACLTrustError(
            "Linux POSIX ACL inspection failed: "
            + os.strerror(error_number or errno.EIO)
        )
    try:
        mode = ctypes.c_uint()
        equivalent = library.acl_equiv_mode(acl, ctypes.byref(mode))
        if equivalent == 0:
            return ACLInspection(
                platform="linux", model="posix.1e", equivalent_to_mode=True
            )
        if equivalent != 1:
            raise FilesystemACLTrustError(
                "Linux POSIX ACL equivalence inspection failed"
            )

        raw_entries: list[tuple[int, int | None, bool]] = []
        entry = ctypes.c_void_p()
        entry_selector = 0
        while True:
            outcome = library.acl_get_entry(acl, entry_selector, ctypes.byref(entry))
            if outcome == 0:
                break
            if outcome != 1 or not entry.value:
                raise FilesystemACLTrustError(
                    "Linux POSIX ACL entry enumeration failed"
                )
            entry_selector = 1  # ACL_NEXT_ENTRY on Linux
            tag = ctypes.c_int()
            permset = ctypes.c_void_p()
            if library.acl_get_tag_type(entry, ctypes.byref(tag)) != 0:
                raise FilesystemACLTrustError("Linux POSIX ACL tag inspection failed")
            if library.acl_get_permset(entry, ctypes.byref(permset)) != 0:
                raise FilesystemACLTrustError(
                    "Linux POSIX ACL permission inspection failed"
                )
            write_result = library.acl_get_perm(permset, 0x02)
            if write_result not in {0, 1}:
                raise FilesystemACLTrustError(
                    "Linux POSIX ACL write-permission inspection failed"
                )
            has_write = write_result == 1
            principal_id: int | None = None
            if tag.value in {0x02, 0x08}:  # ACL_USER / ACL_GROUP
                qualifier = library.acl_get_qualifier(entry)
                if not qualifier:
                    raise FilesystemACLTrustError(
                        "Linux POSIX ACL qualifier inspection failed"
                    )
                try:
                    principal_id = int(
                        ctypes.cast(qualifier, ctypes.POINTER(ctypes.c_uint32))[0]
                    )
                finally:
                    if library.acl_free(qualifier) != 0:
                        raise FilesystemACLTrustError(
                            "Linux POSIX ACL qualifier release failed"
                        )
            raw_entries.append((int(tag.value), principal_id, has_write))

        mask_entries = [
            has_write
            for tag, _identifier, has_write in raw_entries
            if tag == 0x10
        ]
        if len(mask_entries) != 1:
            raise FilesystemACLTrustError(
                "Linux extended POSIX ACL has no unique effective-permission mask"
            )
        mask_write = mask_entries[0]
        metadata = os.fstat(descriptor)
        grants: list[ACLGrant] = []
        for tag, identifier, has_write in raw_entries:
            if tag == 0x01:  # ACL_USER_OBJ
                kind, principal_id, masked = "owner", int(metadata.st_uid), False
            elif tag == 0x02:  # ACL_USER
                kind, principal_id, masked = "user", identifier, True
            elif tag == 0x04:  # ACL_GROUP_OBJ
                kind, principal_id, masked = "group", int(metadata.st_gid), True
            elif tag == 0x08:  # ACL_GROUP
                kind, principal_id, masked = "group", identifier, True
            elif tag == 0x20:  # ACL_OTHER
                kind, principal_id, masked = "everyone", None, False
            else:
                continue
            effective_write = has_write and (mask_write if masked else True)
            grants.append(
                ACLGrant(
                    principal_kind=kind,
                    principal_id=principal_id,
                    permissions=frozenset({"write"}) if effective_write else frozenset(),
                )
            )
        return ACLInspection(
            platform="linux",
            model="posix.1e",
            equivalent_to_mode=False,
            grants=tuple(grants),
        )
    finally:
        if library.acl_free(acl) != 0:
            raise FilesystemACLTrustError("Linux POSIX ACL release failed")
