"""Fail-closed Git repository-family identity for runtime coordination.

The account authority proves one primary worktree and an optional active linked
worktree without consulting remotes or caller-controlled Git configuration.
The returned identity is stable across ordinary commits, but changes when a
worktree or its Git administrative directory is replaced.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import Any

from . import filesystem_acl as _filesystem_acl


class RepositoryContextError(ValueError):
    """A supplied root/temporary repository relationship was not proved."""


@dataclass(frozen=True)
class RepositoryScopeIdentity:
    canonical_root: str
    git_dir: str
    git_common_dir: str
    identity_fingerprint: str
    root_owner_uid: int
    root_device: int
    root_inode: int
    git_dir_owner_uid: int
    git_dir_device: int
    git_dir_inode: int
    git_common_dir_owner_uid: int
    git_common_dir_device: int
    git_common_dir_inode: int
    git_marker_fingerprint: str
    git_identity_fingerprint: str
    inspection_fingerprint: str
    legacy_identity_fingerprint: str


@dataclass(frozen=True)
class RepositoryContext:
    root: RepositoryScopeIdentity
    effective: RepositoryScopeIdentity
    temporary: RepositoryScopeIdentity | None

    @property
    def project_kind(self) -> str:
        return "temporary" if self.temporary is not None else "primary"


@dataclass(frozen=True)
class PersistedRepositoryContext:
    family_id: str
    root_repo_id: str
    effective_repo_id: str
    project_kind: str


@dataclass(frozen=True)
class _PathIdentity:
    owner_uid: int
    owner_gid: int
    device: int
    inode: int
    mode: int

    def material(self) -> dict[str, int]:
        return {
            "owner_uid": self.owner_uid,
            "owner_gid": self.owner_gid,
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
        }


@dataclass(frozen=True)
class _FileSnapshot:
    path: str
    identity: _PathIdentity
    size: int
    digest: str


@dataclass(frozen=True)
class _AdminSnapshot:
    marker_kind: str
    marker_identity: _PathIdentity
    marker_digest: str
    git_dir: str
    git_dir_identity: _PathIdentity
    git_common_dir: str
    git_common_dir_identity: _PathIdentity
    gitdir_file: _FileSnapshot | None
    commondir_file: _FileSnapshot | None
    config_files: tuple[_FileSnapshot, ...]


_MAX_GIT_OUTPUT = 1024 * 1024
_MAX_ADMIN_FILE = 1024 * 1024
_GIT_TIMEOUT_SECONDS = 5.0
_IDENTITY_FINGERPRINT_VERSION = "repository-scope-v1"
_TRUSTED_GIT_CANDIDATES = (Path("/usr/bin/git"), Path("/bin/git"))
_BLOCKED_AMBIENT_GIT_VARIABLES = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIR",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_EXEC_PATH",
        "GIT_GRAFT_FILE",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_TEMPLATE_DIR",
        "GIT_WORK_TREE",
    }
)
_INCLUDE_SECTION = re.compile(
    rb"(?im)^[ \t]*\[[ \t]*include(?:if)?(?:[ \t]+[^\]\r\n]*)?[ \t]*\]"
)
def _fingerprint(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _legacy_fingerprint(value: Any) -> str:
    """Reproduce the unversioned pre-v8 digest for a safe migration check."""

    try:
        encoded = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    except UnicodeEncodeError:
        # A surrogate-containing Unix path could not have produced a legacy
        # fingerprint because the old implementation failed at this boundary.
        return "legacy-unrepresentable"
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _versioned_identity_fingerprint(value: Any) -> str:
    return f"{_IDENTITY_FINGERPRINT_VERSION}:{_fingerprint(value)}"


def _reject_ambient_git_redirection() -> None:
    blocked = sorted(
        name
        for name in os.environ
        if name in _BLOCKED_AMBIENT_GIT_VARIABLES
        or name.startswith("GIT_CONFIG_KEY_")
        or name.startswith("GIT_CONFIG_VALUE_")
    )
    if blocked:
        raise RepositoryContextError(
            "repository inspection rejects ambient Git redirection: "
            + ", ".join(blocked)
        )


def _trusted_git_executable() -> str:
    for candidate in _TRUSTED_GIT_CANDIDATES:
        try:
            metadata = candidate.lstat()
        except OSError:
            continue
        if (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == 0
            and metadata.st_mode & stat.S_IXUSR
            and not metadata.st_mode
            & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            and os.access(candidate, os.X_OK)
        ):
            return str(candidate)
    raise RepositoryContextError(
        "no root-owned, non-set-id, non-group/world-writable Git executable "
        "exists at /usr/bin/git or /bin/git"
    )


def _git_environment() -> dict[str, str]:
    return {
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": "/usr/bin:/bin",
    }


def _terminate_git_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1.0)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _git(path: Path, *arguments: str) -> bytes:
    command = [
        _trusted_git_executable(),
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.allow=never",
        "-C",
        str(path),
        *arguments,
    ]
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    streams: tuple[Any, ...] = ()
    try:
        process = subprocess.Popen(
            command,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            start_new_session=True,
        )
        if process.stdout is None or process.stderr is None:
            _terminate_git_process(process)
            raise RepositoryContextError(
                f"could not inspect Git repository {path}: missing subprocess pipes"
            )
        streams = (process.stdout, process.stderr)
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + _GIT_TIMEOUT_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_git_process(process)
                raise RepositoryContextError(
                    f"could not inspect Git repository {path}: "
                    f"timed out after {_GIT_TIMEOUT_SECONDS:.3f} seconds"
                )
            events = selector.select(remaining)
            if not events:
                continue
            for key, _mask in events:
                try:
                    chunk = os.read(key.fd, 65536)
                except OSError as error:
                    _terminate_git_process(process)
                    raise RepositoryContextError(
                        f"could not read Git repository inspection output for {path}: {error}"
                    ) from error
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                stream_name = str(key.data)
                buffer = buffers[stream_name]
                if len(buffer) + len(chunk) > _MAX_GIT_OUTPUT:
                    _terminate_git_process(process)
                    raise RepositoryContextError(
                        "Git repository inspection "
                        f"{stream_name} exceeded {_MAX_GIT_OUTPUT} bytes"
                    )
                buffer.extend(chunk)
        try:
            return_code = process.wait(
                timeout=max(0.001, deadline - time.monotonic())
            )
        except subprocess.TimeoutExpired as error:
            _terminate_git_process(process)
            raise RepositoryContextError(
                f"could not inspect Git repository {path}: "
                f"timed out after {_GIT_TIMEOUT_SECONDS:.3f} seconds"
            ) from error
        stdout = bytes(buffers["stdout"])
        stderr = bytes(buffers["stderr"])
    except RepositoryContextError:
        raise
    except OSError as error:
        if process is not None:
            _terminate_git_process(process)
        raise RepositoryContextError(
            f"could not inspect Git repository {path}: {error}"
        ) from error
    finally:
        selector.close()
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass
    if return_code != 0:
        diagnostic = stderr[:4096].decode(
            "utf-8", errors="replace"
        ).strip()
        raise RepositoryContextError(
            f"Git repository inspection failed for {path}: "
            f"{diagnostic or f'exit {return_code}'}"
        )
    return stdout


def _path_identity(metadata: os.stat_result) -> _PathIdentity:
    return _PathIdentity(
        owner_uid=int(metadata.st_uid),
        owner_gid=int(metadata.st_gid),
        device=int(metadata.st_dev),
        inode=int(metadata.st_ino),
        mode=int(stat.S_IMODE(metadata.st_mode)),
    )


def _normalized_absolute_path(path: Path, *, field: str) -> Path:
    if not path.is_absolute():
        raise RepositoryContextError(f"{field} must be an absolute path")
    raw = os.fspath(path)
    if "\0" in raw:
        raise RepositoryContextError(f"{field} must not contain NUL bytes")
    if "\n" in raw or "\r" in raw:
        raise RepositoryContextError(f"{field} must not contain line breaks")
    return Path(os.path.abspath(os.fspath(path)))


def _open_inspected_path(
    path: Path,
    *,
    field: str,
    expected_kind: str,
    final_owner_uid: int,
) -> tuple[int, _PathIdentity]:
    """Open one exact path by anchored components and return its stable identity."""

    path = _normalized_absolute_path(path, field=field)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if not no_follow or not directory:
        raise RepositoryContextError(
            "repository inspection requires O_NOFOLLOW and O_DIRECTORY support"
        )
    directory_flags = os.O_RDONLY | close_on_exec | no_follow | directory
    file_flags = os.O_RDONLY | close_on_exec | no_follow
    try:
        descriptor = os.open(path.anchor, directory_flags)
    except (OSError, ValueError) as error:
        raise RepositoryContextError(
            f"{field} is unavailable at {path.anchor}: {error}"
        ) from error

    current = Path(path.anchor)
    parts = path.parts[1:]
    try:
        anchor_metadata = os.fstat(descriptor)
        _filesystem_acl.require_fd_acl_trusted(
            descriptor,
            owner_uid=int(anchor_metadata.st_uid),
            field=f"{field} path component {current}",
        )
        if not parts:
            is_final = True
            identities = ((current, anchor_metadata, is_final),)
        else:
            identities = ()
        for index, part in enumerate(parts):
            current /= part
            is_final = index == len(parts) - 1
            flags = (
                directory_flags
                if not is_final or expected_kind == "directory"
                else file_flags
            )
            try:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except (OSError, ValueError) as error:
                try:
                    failed_metadata = os.stat(
                        part, dir_fd=descriptor, follow_symlinks=False
                    )
                except (OSError, ValueError):
                    failed_metadata = None
                if failed_metadata is not None and stat.S_ISLNK(
                    failed_metadata.st_mode
                ):
                    raise RepositoryContextError(
                        f"{field} must not contain a symbolic-link component: {current}"
                    ) from error
                raise RepositoryContextError(
                    f"{field} is unavailable at {current}: {error}"
                ) from error
            os.close(descriptor)
            descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            _filesystem_acl.require_fd_acl_trusted(
                descriptor,
                owner_uid=int(metadata.st_uid),
                field=f"{field} path component {current}",
            )
            identities = ((current, metadata, is_final),)

            if not is_final and not stat.S_ISDIR(metadata.st_mode):
                raise RepositoryContextError(
                    f"{field} has a non-directory ancestor: {current}"
                )
            if metadata.st_uid not in {0, final_owner_uid}:
                raise RepositoryContextError(
                    f"{field} has an untrusted owner at {current}"
                )
            writable_by_others = bool(
                metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            )
            trusted_sticky_parent = bool(
                not is_final
                and metadata.st_uid == 0
                and metadata.st_mode & stat.S_ISVTX
            )
            if writable_by_others and not trusted_sticky_parent:
                raise RepositoryContextError(
                    f"{field} has a replaceable group/world-writable path: {current}"
                )

        if not identities:
            raise RepositoryContextError(f"{field} could not be inspected: {path}")
        _current, final_metadata, _is_final = identities[0]
        if final_metadata.st_uid != final_owner_uid:
            raise RepositoryContextError(
                f"{field} must be owned by account uid {final_owner_uid}: {path}"
            )
        if expected_kind == "directory" and not stat.S_ISDIR(final_metadata.st_mode):
            raise RepositoryContextError(f"{field} must identify a directory: {path}")
        if expected_kind == "file" and not stat.S_ISREG(final_metadata.st_mode):
            raise RepositoryContextError(f"{field} must identify a regular file: {path}")
        return descriptor, _path_identity(final_metadata)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _inspect_path(
    path: Path,
    *,
    field: str,
    expected_kind: str,
    final_owner_uid: int,
) -> _PathIdentity:
    descriptor, identity = _open_inspected_path(
        path,
        field=field,
        expected_kind=expected_kind,
        final_owner_uid=final_owner_uid,
    )
    os.close(descriptor)
    return identity


def _canonical_existing_directory(raw: str, *, field: str) -> tuple[Path, _PathIdentity]:
    if not isinstance(raw, str) or not raw.strip():
        raise RepositoryContextError(f"{field} must be a non-empty absolute path")
    candidate = Path(raw)
    candidate = _normalized_absolute_path(candidate, field=field)
    identity = _inspect_path(
        candidate,
        field=field,
        expected_kind="directory",
        final_owner_uid=os.geteuid(),
    )
    try:
        canonical = candidate.resolve(strict=True)
    except (OSError, ValueError) as error:
        raise RepositoryContextError(f"{field} is unavailable: {candidate}: {error}") from error
    if canonical != candidate:
        raise RepositoryContextError(
            f"{field} must be a canonical non-symlink absolute path: {candidate}"
        )
    after = _inspect_path(
        canonical,
        field=field,
        expected_kind="directory",
        final_owner_uid=os.geteuid(),
    )
    if after != identity:
        raise RepositoryContextError(f"{field} changed while it was canonicalized")
    return canonical, identity


def _read_admin_file(path: Path, *, field: str) -> tuple[_FileSnapshot, bytes]:
    descriptor, identity = _open_inspected_path(
        path,
        field=field,
        expected_kind="file",
        final_owner_uid=os.geteuid(),
    )
    try:
        metadata = os.fstat(descriptor)
        if _path_identity(metadata) != identity or not stat.S_ISREG(metadata.st_mode):
            raise RepositoryContextError(f"{field} changed while it was opened: {path}")
        if metadata.st_size > _MAX_ADMIN_FILE:
            raise RepositoryContextError(
                f"{field} exceeds the {_MAX_ADMIN_FILE}-byte inspection limit: {path}"
            )
        chunks: list[bytes] = []
        remaining = _MAX_ADMIN_FILE + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > _MAX_ADMIN_FILE:
            raise RepositoryContextError(
                f"{field} exceeds the {_MAX_ADMIN_FILE}-byte inspection limit: {path}"
            )
    finally:
        os.close(descriptor)
    after = _inspect_path(
        path,
        field=field,
        expected_kind="file",
        final_owner_uid=os.geteuid(),
    )
    if after != identity:
        raise RepositoryContextError(f"{field} changed while it was read: {path}")
    return _FileSnapshot(
        path=str(path),
        identity=identity,
        size=len(content),
        digest=_fingerprint({"bytes_sha256": hashlib.sha256(content).hexdigest()}),
    ), content


def _single_admin_path(content: bytes, *, prefix: bytes | None, field: str) -> str:
    if b"\0" in content:
        raise RepositoryContextError(f"{field} contains a NUL byte")
    stripped = content.rstrip(b"\r\n")
    if b"\n" in stripped or b"\r" in stripped:
        raise RepositoryContextError(f"{field} must contain exactly one path")
    if prefix is not None:
        if not stripped.startswith(prefix):
            raise RepositoryContextError(f"{field} has an invalid Git indirection header")
        stripped = stripped[len(prefix) :]
    if not stripped:
        raise RepositoryContextError(f"{field} contains an empty path")
    return os.fsdecode(stripped)


def _validate_config(snapshot: _FileSnapshot, content: bytes) -> None:
    if _INCLUDE_SECTION.search(content):
        raise RepositoryContextError(
            f"Git config includes are not allowed during identity proof: {snapshot.path}"
        )


def _file_snapshot_material(snapshot: _FileSnapshot | None) -> Any:
    if snapshot is None:
        return None
    return {
        "path": snapshot.path,
        "identity": snapshot.identity.material(),
        "size": snapshot.size,
        "digest": snapshot.digest,
    }


def _admin_snapshot_material(snapshot: _AdminSnapshot) -> dict[str, Any]:
    return {
        "marker_kind": snapshot.marker_kind,
        "marker_identity": snapshot.marker_identity.material(),
        "marker_digest": snapshot.marker_digest,
        "git_dir": snapshot.git_dir,
        "git_dir_identity": snapshot.git_dir_identity.material(),
        "git_common_dir": snapshot.git_common_dir,
        "git_common_dir_identity": snapshot.git_common_dir_identity.material(),
        "gitdir_file": _file_snapshot_material(snapshot.gitdir_file),
        "commondir_file": _file_snapshot_material(snapshot.commondir_file),
        "config_files": [
            _file_snapshot_material(item) for item in snapshot.config_files
        ],
    }


def _stable_path_identity(identity: _PathIdentity) -> dict[str, int]:
    return {
        "owner_uid": identity.owner_uid,
        "device": identity.device,
        "inode": identity.inode,
    }


def _stable_marker_fingerprint(snapshot: _AdminSnapshot) -> str:
    if snapshot.marker_kind == "file":
        return snapshot.marker_digest
    return _fingerprint(_stable_path_identity(snapshot.marker_identity))


def _admin_snapshot(root: Path) -> _AdminSnapshot:
    marker = root / ".git"
    try:
        marker_metadata = marker.lstat()
    except OSError as error:
        raise RepositoryContextError(
            f"repository has no readable .git marker: {root}: {error}"
        ) from error
    if stat.S_ISLNK(marker_metadata.st_mode):
        raise RepositoryContextError(
            f"repository .git marker must not be a symbolic link: {marker}"
        )
    marker_identity = _path_identity(marker_metadata)
    if marker_identity.owner_uid != os.geteuid():
        raise RepositoryContextError(
            f"repository .git marker must be owned by account uid {os.geteuid()}: {marker}"
        )
    if stat.S_ISDIR(marker_metadata.st_mode):
        _inspect_path(
            marker,
            field="repository .git directory",
            expected_kind="directory",
            final_owner_uid=os.geteuid(),
        )
        marker_kind = "directory"
        marker_digest = _fingerprint(marker_identity.material())
        git_dir = marker
    elif stat.S_ISREG(marker_metadata.st_mode):
        marker_snapshot, marker_content = _read_admin_file(
            marker, field="repository .git file"
        )
        marker_kind = "file"
        marker_digest = marker_snapshot.digest
        raw_git_dir = _single_admin_path(
            marker_content, prefix=b"gitdir: ", field="repository .git file"
        )
        candidate = Path(raw_git_dir)
        if not candidate.is_absolute():
            candidate = root / candidate
        git_dir = Path(os.path.abspath(os.fspath(candidate)))
    else:
        raise RepositoryContextError(
            f"repository .git marker must be a directory or regular file: {marker}"
        )

    git_dir_identity = _inspect_path(
        git_dir,
        field="Git administrative directory",
        expected_kind="directory",
        final_owner_uid=os.geteuid(),
    )
    gitdir_link_path = git_dir / "gitdir"
    gitdir_snapshot: _FileSnapshot | None = None
    if gitdir_link_path.exists() or gitdir_link_path.is_symlink():
        gitdir_snapshot, gitdir_content = _read_admin_file(
            gitdir_link_path, field="Git worktree backlink"
        )
        raw_marker = _single_admin_path(
            gitdir_content, prefix=None, field="Git worktree backlink"
        )
        marker_candidate = Path(raw_marker)
        if not marker_candidate.is_absolute():
            marker_candidate = git_dir / marker_candidate
        marker_candidate = Path(os.path.abspath(os.fspath(marker_candidate)))
        if marker_candidate != marker:
            raise RepositoryContextError(
                "Git worktree backlink does not identify the supplied worktree .git marker"
            )
    commondir_path = git_dir / "commondir"
    commondir_snapshot: _FileSnapshot | None = None
    if commondir_path.exists() or commondir_path.is_symlink():
        commondir_snapshot, commondir_content = _read_admin_file(
            commondir_path, field="Git commondir file"
        )
        raw_common = _single_admin_path(
            commondir_content, prefix=None, field="Git commondir file"
        )
        common_candidate = Path(raw_common)
        if not common_candidate.is_absolute():
            common_candidate = git_dir / common_candidate
        git_common_dir = Path(os.path.abspath(os.fspath(common_candidate)))
    else:
        git_common_dir = git_dir
    git_common_dir_identity = _inspect_path(
        git_common_dir,
        field="Git common directory",
        expected_kind="directory",
        final_owner_uid=os.geteuid(),
    )

    config_paths = [git_common_dir / "config"]
    worktree_config = git_dir / "config.worktree"
    if worktree_config.exists() or worktree_config.is_symlink():
        config_paths.append(worktree_config)
    config_files: list[_FileSnapshot] = []
    for config_path in config_paths:
        config_snapshot, config_content = _read_admin_file(
            config_path, field="Git repository config"
        )
        config_files.append(config_snapshot)
        _validate_config(config_snapshot, config_content)
    return _AdminSnapshot(
        marker_kind=marker_kind,
        marker_identity=marker_identity,
        marker_digest=marker_digest,
        git_dir=str(git_dir),
        git_dir_identity=git_dir_identity,
        git_common_dir=str(git_common_dir),
        git_common_dir_identity=git_common_dir_identity,
        gitdir_file=gitdir_snapshot,
        commondir_file=commondir_snapshot,
        config_files=tuple(config_files),
    )


def _checked_git_path(worktree: Path, raw: str, *, field: str) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = worktree / candidate
    candidate = Path(os.path.abspath(os.fspath(candidate)))
    _inspect_path(
        candidate,
        field=field,
        expected_kind="directory",
        final_owner_uid=os.geteuid(),
    )
    return candidate


def _git_scope_facts(path: Path) -> tuple[Path, Path, Path, str, str, str]:
    raw = _git(
        path,
        "rev-parse",
        "--show-toplevel",
        "--absolute-git-dir",
        "--git-common-dir",
        "--is-inside-work-tree",
        "--is-bare-repository",
        "--show-object-format",
    ).decode("utf-8", errors="surrogateescape")
    values = raw.rstrip("\n").split("\n")
    if len(values) != 6 or any("\r" in value for value in values):
        raise RepositoryContextError(
            f"Git returned malformed repository identity material for {path}"
        )
    top = _checked_git_path(path, values[0], field="Git --show-toplevel")
    git_dir = _checked_git_path(path, values[1], field="Git --absolute-git-dir")
    common_dir = _checked_git_path(path, values[2], field="Git --git-common-dir")
    return top, git_dir, common_dir, values[3], values[4], values[5]


def _scope_identity(path: Path, root_identity: _PathIdentity) -> RepositoryScopeIdentity:
    before = _admin_snapshot(path)
    top, git_dir, common_dir, inside, bare, object_format = _git_scope_facts(path)
    top_identity = _inspect_path(
        top,
        field="Git --show-toplevel",
        expected_kind="directory",
        final_owner_uid=os.geteuid(),
    )
    if top_identity != root_identity:
        raise RepositoryContextError(
            f"repository path must be its exact Git top-level: supplied {path}, Git reports {top}"
        )
    git_dir_identity = _inspect_path(
        git_dir,
        field="Git --absolute-git-dir",
        expected_kind="directory",
        final_owner_uid=os.geteuid(),
    )
    common_dir_identity = _inspect_path(
        common_dir,
        field="Git --git-common-dir",
        expected_kind="directory",
        final_owner_uid=os.geteuid(),
    )
    if (
        git_dir_identity != before.git_dir_identity
        or common_dir_identity != before.git_common_dir_identity
    ):
        raise RepositoryContextError(
            "Git administrative identity disagrees with the inspected .git boundary"
        )
    if inside != "true" or bare != "false":
        raise RepositoryContextError(f"repository scope is not a non-bare Git worktree: {path}")
    if object_format not in {"sha1", "sha256"}:
        raise RepositoryContextError(
            f"repository uses an unsupported Git object format: {object_format!r}"
        )
    after = _admin_snapshot(path)
    after_root = _inspect_path(
        path,
        field="repository scope",
        expected_kind="directory",
        final_owner_uid=os.geteuid(),
    )
    if after != before or after_root != root_identity:
        raise RepositoryContextError(
            f"repository identity changed during inspection: {path}"
        )

    git_identity_material = {
        "object_format": object_format,
        "inside_worktree": inside,
        "bare": bare,
    }
    legacy_material = {
        "canonical_root": str(path),
        "root": root_identity.material(),
        "git_dir": {"path": before.git_dir, **before.git_dir_identity.material()},
        "git_common_dir": {
            "path": before.git_common_dir,
            **before.git_common_dir_identity.material(),
        },
        "git_marker_kind": before.marker_kind,
        "git_marker_fingerprint": before.marker_digest,
        "git_identity": git_identity_material,
    }
    stable_marker = _stable_marker_fingerprint(before)
    material = {
        "root": _stable_path_identity(root_identity),
        "git_dir": _stable_path_identity(before.git_dir_identity),
        "git_common_dir": _stable_path_identity(before.git_common_dir_identity),
        "git_marker_kind": before.marker_kind,
        "git_marker_fingerprint": stable_marker,
        "git_identity": git_identity_material,
    }
    return RepositoryScopeIdentity(
        canonical_root=str(path),
        git_dir=before.git_dir,
        git_common_dir=before.git_common_dir,
        identity_fingerprint=_versioned_identity_fingerprint(material),
        root_owner_uid=root_identity.owner_uid,
        root_device=root_identity.device,
        root_inode=root_identity.inode,
        git_dir_owner_uid=before.git_dir_identity.owner_uid,
        git_dir_device=before.git_dir_identity.device,
        git_dir_inode=before.git_dir_identity.inode,
        git_common_dir_owner_uid=before.git_common_dir_identity.owner_uid,
        git_common_dir_device=before.git_common_dir_identity.device,
        git_common_dir_inode=before.git_common_dir_identity.inode,
        git_marker_fingerprint=stable_marker,
        git_identity_fingerprint=_fingerprint(git_identity_material),
        inspection_fingerprint=_fingerprint(_admin_snapshot_material(before)),
        legacy_identity_fingerprint=_legacy_fingerprint(legacy_material),
    )


def _revalidate_scope(scope: RepositoryScopeIdentity, *, field: str) -> None:
    path, root_identity = _canonical_existing_directory(
        scope.canonical_root, field=field
    )
    snapshot = _admin_snapshot(path)
    observed = {
        "root_owner_uid": root_identity.owner_uid,
        "root_device": root_identity.device,
        "root_inode": root_identity.inode,
        "git_dir": snapshot.git_dir,
        "git_dir_owner_uid": snapshot.git_dir_identity.owner_uid,
        "git_dir_device": snapshot.git_dir_identity.device,
        "git_dir_inode": snapshot.git_dir_identity.inode,
        "git_common_dir": snapshot.git_common_dir,
        "git_common_dir_owner_uid": snapshot.git_common_dir_identity.owner_uid,
        "git_common_dir_device": snapshot.git_common_dir_identity.device,
        "git_common_dir_inode": snapshot.git_common_dir_identity.inode,
        "git_marker_fingerprint": _stable_marker_fingerprint(snapshot),
        "inspection_fingerprint": _fingerprint(_admin_snapshot_material(snapshot)),
    }
    expected = {key: getattr(scope, key) for key in observed}
    if observed != expected:
        raise RepositoryContextError(
            f"{field} identity changed between request proof and persistence"
        )


def _revalidate_context(context: RepositoryContext) -> None:
    _reject_ambient_git_redirection()
    _revalidate_scope(context.root, field="root_repo")
    if context.temporary is not None:
        _revalidate_scope(context.temporary, field="temporary_repo")
        if (
            context.temporary.git_common_dir_device,
            context.temporary.git_common_dir_inode,
        ) != (
            context.root.git_common_dir_device,
            context.root.git_common_dir_inode,
        ):
            raise RepositoryContextError(
                "temporary repository family identity changed after proof"
            )


def _worktree_matches_scope(raw: str, scope: RepositoryScopeIdentity) -> bool:
    try:
        identity = _inspect_path(
            Path(raw),
            field="Git listed worktree",
            expected_kind="directory",
            final_owner_uid=os.geteuid(),
        )
    except RepositoryContextError:
        return False
    return (identity.device, identity.inode) == (
        scope.root_device,
        scope.root_inode,
    )


def _listed_worktrees(root: Path) -> tuple[str, ...]:
    raw = _git(root, "worktree", "list", "--porcelain", "-z")
    result: list[str] = []
    for field in raw.split(b"\0"):
        if not field.startswith(b"worktree "):
            continue
        value = field[len(b"worktree ") :].decode(
            "utf-8", errors="surrogateescape"
        )
        if not value or not Path(value).is_absolute():
            raise RepositoryContextError(
                f"Git returned a non-absolute worktree path: {value!r}"
            )
        result.append(os.path.abspath(value))
    if not result:
        raise RepositoryContextError(f"Git returned no worktrees for {root}")
    if len(result) != len(set(result)):
        raise RepositoryContextError(f"Git returned duplicate worktrees for {root}")
    return tuple(result)


def resolve_repository_context(
    *, root_repo: str, temporary_repo: str | None
) -> RepositoryContext:
    """Prove the supplied account-owned primary and optional linked worktree."""

    _reject_ambient_git_redirection()
    root_path, root_path_identity = _canonical_existing_directory(
        root_repo, field="root_repo"
    )
    root = _scope_identity(root_path, root_path_identity)

    temporary_path: Path | None = None
    temporary: RepositoryScopeIdentity | None = None
    if temporary_repo is not None:
        temporary_path, temporary_path_identity = _canonical_existing_directory(
            temporary_repo, field="temporary_repo"
        )
        if temporary_path == root_path:
            raise RepositoryContextError(
                "temporary_repo must be null when the primary worktree is the active scope"
            )
        temporary = _scope_identity(temporary_path, temporary_path_identity)
        if (
            temporary.root_device,
            temporary.root_inode,
        ) == (root.root_device, root.root_inode):
            raise RepositoryContextError(
                "temporary_repo identifies the same filesystem worktree as root_repo"
            )
        if (
            temporary.git_common_dir_device,
            temporary.git_common_dir_inode,
        ) != (root.git_common_dir_device, root.git_common_dir_inode):
            raise RepositoryContextError(
                "temporary_repo does not share the root_repo Git common directory"
            )

    worktrees = _listed_worktrees(root_path)
    if not _worktree_matches_scope(worktrees[0], root):
        raise RepositoryContextError(
            f"root_repo must be the primary Git worktree {worktrees[0]}, got {root_path}"
        )
    if temporary_path is not None:
        if sum(
            _worktree_matches_scope(candidate, temporary)
            for candidate in worktrees[1:]
        ) != 1:
            raise RepositoryContextError(
                "temporary_repo is not an active linked worktree of root_repo"
            )
    context = RepositoryContext(
        root=root,
        effective=temporary or root,
        temporary=temporary,
    )
    # Git worktree enumeration is a separate read. Re-prove the exact opened
    # filesystem/admin identities after it so a concurrent move or repair
    # cannot leave the caller with a mixed-time context.
    _revalidate_context(context)
    return context


def resolve_effective_repository_context(*, project: str) -> RepositoryContext:
    """Discover the primary/temporary relationship for one exact worktree.

    Compatibility actions historically accepted only the active project path.
    Resolve that path through the same trusted Git and filesystem boundary as
    the explicit runtime API, then return the explicit root/temporary context
    used by normalized persistence.  The final resolver repeats every proof so
    a worktree move between discovery and use fails closed.
    """

    _reject_ambient_git_redirection()
    project_path, project_path_identity = _canonical_existing_directory(
        project, field="project"
    )
    project_scope = _scope_identity(project_path, project_path_identity)
    worktrees = _listed_worktrees(project_path)
    matching_indexes = [
        index
        for index, candidate in enumerate(worktrees)
        if _worktree_matches_scope(candidate, project_scope)
    ]
    if len(matching_indexes) != 1:
        raise RepositoryContextError(
            "project is not listed exactly once as an active Git worktree"
        )
    primary_path = worktrees[0]
    if matching_indexes[0] == 0:
        return resolve_repository_context(
            root_repo=str(project_path), temporary_repo=None
        )
    return resolve_repository_context(
        root_repo=primary_path, temporary_repo=str(project_path)
    )


def _scope_identity_changed(row: Any, scope: RepositoryScopeIdentity) -> bool:
    stored = row["identity_fingerprint"]
    if stored is None:
        return False
    if str(stored) == scope.identity_fingerprint:
        return bool(
            row["root_device"] not in {None, scope.root_device}
            or row["root_inode"] not in {None, scope.root_inode}
        )
    if str(stored) == scope.legacy_identity_fingerprint:
        return bool(
            row["git_dir"] not in {None, scope.git_dir}
            or row["git_common_dir"] not in {None, scope.git_common_dir}
        )
    return True


def _family_identity_changed(row: Any, scope: RepositoryScopeIdentity) -> bool:
    stored = row["identity_fingerprint"]
    if stored is None or str(stored) == scope.identity_fingerprint:
        return False
    return bool(
        str(stored) != scope.legacy_identity_fingerprint
        or row["git_common_dir"] not in {None, scope.git_common_dir}
    )


def _repository_path_matches_scope(
    canonical_root: str, scope: RepositoryScopeIdentity
) -> bool:
    if canonical_root == scope.canonical_root:
        return True
    try:
        _path, identity = _canonical_existing_directory(
            canonical_root, field="stored repository root"
        )
    except RepositoryContextError:
        return False
    return (identity.device, identity.inode) == (
        scope.root_device,
        scope.root_inode,
    )


def find_repository_id_by_filesystem_identity(
    connection: Any,
    *,
    host_id: str,
    scope: RepositoryScopeIdentity,
) -> str | None:
    """Resolve one repository by host-scoped worktree inode before insertion.

    Legacy singleton scopes have NULL filesystem identity. They are inspected
    once through the same anchored path guard so a case/Unicode spelling alias
    resolves to the existing repository instead of creating a second project.
    The caller must hold the repository-insertion writer transaction.
    """

    rows = connection.execute(
        """
        SELECT repository.repo_id, repository.canonical_root,
               scope.root_device, scope.root_inode
        FROM repositories repository
        JOIN repository_scopes scope USING(repo_id)
        WHERE repository.host_id = ?
          AND (
              (scope.root_device = ? AND scope.root_inode = ?)
              OR scope.root_device IS NULL OR scope.root_inode IS NULL
              OR repository.canonical_root = ?
          )
        ORDER BY repository.repo_id
        """,
        (
            host_id,
            scope.root_device,
            scope.root_inode,
            scope.canonical_root,
        ),
    ).fetchall()
    matches: list[str] = []
    for row in rows:
        repo_id = str(row["repo_id"])
        stored_device = row["root_device"]
        stored_inode = row["root_inode"]
        stored_root = str(row["canonical_root"])
        if stored_device is not None and stored_inode is not None:
            if (int(stored_device), int(stored_inode)) == (
                scope.root_device,
                scope.root_inode,
            ):
                matches.append(repo_id)
                continue
            if stored_root == scope.canonical_root:
                raise RepositoryContextError(
                    "repository path now identifies a different filesystem worktree"
                )
            continue
        if _repository_path_matches_scope(stored_root, scope):
            matches.append(repo_id)
    unique_matches = tuple(dict.fromkeys(matches))
    if len(unique_matches) > 1:
        raise RepositoryContextError(
            "multiple repository rows identify the same filesystem worktree: "
            + ", ".join(unique_matches)
        )
    return unique_matches[0] if unique_matches else None


def persist_repository_context(
    store: Any,
    context: RepositoryContext,
    *,
    root_repo_id: str,
    effective_repo_id: str,
    timestamp: str,
) -> PersistedRepositoryContext:
    """Re-prove and persist one exact relationship in the normalized store."""

    family_id = str(root_repo_id)
    persisted_result = PersistedRepositoryContext(
        family_id=family_id,
        root_repo_id=str(root_repo_id),
        effective_repo_id=str(effective_repo_id),
        project_kind=context.project_kind,
    )
    # This operation is on the status/polling path. Own the revision update
    # explicitly so an exact repeat performs no row update and increments no
    # state revision.
    with store.immediate_transaction(revision_kind=None) as connection:
        # Keep the final filesystem proof inside the same writer boundary as
        # alias detection and persistence. The account authority cannot hold
        # these descriptors across a later lifecycle operation, which must
        # retain its own exact target proof.
        _revalidate_context(context)
        rows = {
            str(row["repo_id"]): row
            for row in connection.execute(
                """
                SELECT repo_id, host_id, canonical_root
                FROM repositories WHERE repo_id IN (?, ?)
                """,
                (root_repo_id, effective_repo_id),
            )
        }
        root_row = rows.get(str(root_repo_id))
        effective_row = rows.get(str(effective_repo_id))
        if root_row is None or effective_row is None:
            raise RepositoryContextError(
                "repository context cannot be persisted before both repositories are installed"
            )
        if not _repository_path_matches_scope(
            str(root_row["canonical_root"]), context.root
        ):
            raise RepositoryContextError("root repository ID/path identity changed")
        if not _repository_path_matches_scope(
            str(effective_row["canonical_root"]), context.effective
        ):
            raise RepositoryContextError("effective repository ID/path identity changed")
        if str(root_row["host_id"]) != str(effective_row["host_id"]):
            raise RepositoryContextError("repository family cannot cross host authorities")

        root_identity_match = find_repository_id_by_filesystem_identity(
            connection,
            host_id=str(root_row["host_id"]),
            scope=context.root,
        )
        if root_identity_match not in {None, str(root_repo_id)}:
            raise RepositoryContextError(
                "root worktree is already enrolled under repository ID "
                f"{root_identity_match}"
            )
        effective_identity_match = find_repository_id_by_filesystem_identity(
            connection,
            host_id=str(effective_row["host_id"]),
            scope=context.effective,
        )
        if effective_identity_match not in {None, str(effective_repo_id)}:
            raise RepositoryContextError(
                "effective worktree is already enrolled under repository ID "
                f"{effective_identity_match}"
            )

        family_row = connection.execute(
            """
            SELECT host_id, root_repo_id, git_common_dir, identity_fingerprint
            FROM repository_families WHERE family_id = ?
            """,
            (family_id,),
        ).fetchone()
        if family_row is not None and (
            str(family_row["host_id"]) != str(root_row["host_id"])
            or str(family_row["root_repo_id"]) != str(root_repo_id)
        ):
            raise RepositoryContextError(
                "root repository family authority or root identity changed"
            )
        if family_row is not None and _family_identity_changed(
            family_row, context.root
        ):
            raise RepositoryContextError(
                "root repository family identity changed since enrollment"
            )

        root_scope = connection.execute(
            """
            SELECT family_id, project_kind, git_dir, git_common_dir,
                   identity_fingerprint, root_device, root_inode
            FROM repository_scopes WHERE repo_id = ?
            """,
            (root_repo_id,),
        ).fetchone()
        if root_scope is not None and (
            str(root_scope["family_id"]) != family_id
            or str(root_scope["project_kind"]) != "primary"
        ):
            raise RepositoryContextError(
                "root_repo is already recorded as a non-root scope in another family"
            )
        if root_scope is not None and _scope_identity_changed(
            root_scope, context.root
        ):
            raise RepositoryContextError(
                "root repository scope identity changed since enrollment"
            )

        prior = None
        prior_family: str | None = None
        if context.temporary is not None:
            prior = connection.execute(
                """
                SELECT family_id, project_kind, git_dir, git_common_dir,
                       identity_fingerprint, root_device, root_inode
                FROM repository_scopes WHERE repo_id = ?
                """,
                (effective_repo_id,),
            ).fetchone()
            prior_family = str(prior["family_id"]) if prior is not None else None
            if prior_family not in {None, family_id, str(effective_repo_id)}:
                raise RepositoryContextError(
                    "temporary_repo is already assigned to another repository family"
                )
            if prior is not None and _scope_identity_changed(
                prior, context.temporary
            ):
                raise RepositoryContextError(
                    "temporary repository scope identity changed since enrollment"
                )

        family_exact = bool(
            family_row is not None
            and str(family_row["host_id"]) == str(root_row["host_id"])
            and str(family_row["root_repo_id"]) == str(root_repo_id)
            and str(family_row["identity_fingerprint"] or "")
            == context.root.identity_fingerprint
        )
        root_exact = bool(
            root_scope is not None
            and str(root_scope["family_id"]) == family_id
            and str(root_scope["project_kind"]) == "primary"
            and str(root_scope["identity_fingerprint"] or "")
            == context.root.identity_fingerprint
            and root_scope["root_device"] == context.root.root_device
            and root_scope["root_inode"] == context.root.root_inode
        )
        temporary_exact = bool(
            context.temporary is None
            or (
                prior is not None
                and prior_family == family_id
                and str(prior["project_kind"]) == "temporary"
                and str(prior["identity_fingerprint"] or "")
                == context.temporary.identity_fingerprint
                and prior["root_device"] == context.temporary.root_device
                and prior["root_inode"] == context.temporary.root_inode
            )
        )
        if family_exact and root_exact and temporary_exact:
            return persisted_result

        connection.execute(
            """
            INSERT INTO repository_families(
                family_id, host_id, root_repo_id, git_common_dir,
                identity_fingerprint, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(family_id) DO UPDATE SET
                git_common_dir = excluded.git_common_dir,
                identity_fingerprint = excluded.identity_fingerprint,
                updated_at = excluded.updated_at
            """,
            (
                family_id,
                root_row["host_id"],
                root_repo_id,
                context.root.git_common_dir,
                context.root.identity_fingerprint,
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO repository_scopes(
                repo_id, family_id, project_kind, git_dir, git_common_dir,
                identity_fingerprint, root_device, root_inode,
                created_at, updated_at
            ) VALUES (?, ?, 'primary', ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(repo_id) DO UPDATE SET
                family_id = excluded.family_id,
                project_kind = 'primary',
                git_dir = excluded.git_dir,
                git_common_dir = excluded.git_common_dir,
                identity_fingerprint = excluded.identity_fingerprint,
                root_device = excluded.root_device,
                root_inode = excluded.root_inode,
                updated_at = excluded.updated_at
            """,
            (
                root_repo_id,
                family_id,
                context.root.git_dir,
                context.root.git_common_dir,
                context.root.identity_fingerprint,
                context.root.root_device,
                context.root.root_inode,
                timestamp,
                timestamp,
            ),
        )

        if context.temporary is not None:
            if prior_family == str(effective_repo_id):
                dependent = connection.execute(
                    """
                    SELECT repo_id FROM repository_scopes
                    WHERE family_id = ? AND repo_id != ? LIMIT 1
                    """,
                    (prior_family, effective_repo_id),
                ).fetchone()
                if dependent is not None:
                    raise RepositoryContextError(
                        "temporary_repo is currently the root of another non-empty family"
                    )
                connection.execute(
                    """
                    UPDATE runtime_sessions
                    SET family_id = ?, root_repo_id = ?, updated_at = ?
                    WHERE family_id = ?
                    """,
                    (family_id, root_repo_id, timestamp, prior_family),
                )
            connection.execute(
                """
                INSERT INTO repository_scopes(
                    repo_id, family_id, project_kind, git_dir, git_common_dir,
                    identity_fingerprint, root_device, root_inode,
                    created_at, updated_at
                ) VALUES (?, ?, 'temporary', ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repo_id) DO UPDATE SET
                    family_id = excluded.family_id,
                    project_kind = 'temporary',
                    git_dir = excluded.git_dir,
                    git_common_dir = excluded.git_common_dir,
                    identity_fingerprint = excluded.identity_fingerprint,
                    root_device = excluded.root_device,
                    root_inode = excluded.root_inode,
                    updated_at = excluded.updated_at
                """,
                (
                    effective_repo_id,
                    family_id,
                    context.temporary.git_dir,
                    context.temporary.git_common_dir,
                    context.temporary.identity_fingerprint,
                    context.temporary.root_device,
                    context.temporary.root_inode,
                    timestamp,
                    timestamp,
                ),
            )
            if prior_family == str(effective_repo_id) and prior_family != family_id:
                connection.execute(
                    "DELETE FROM repository_families WHERE family_id = ?",
                    (prior_family,),
                )
        connection.execute(
            """
            UPDATE schema_metadata
            SET state_revision = state_revision + 1, updated_at = ?
            WHERE singleton = 1
            """,
            (timestamp,),
        )

    return persisted_result
